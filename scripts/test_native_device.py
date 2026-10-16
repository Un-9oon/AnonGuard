"""Offline setup and localhost adapter contracts; never apply firewall or services."""
import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
setup=load('device_setup');adapter=load('native_adapter');browser=load('browser_session')
def document():
    return {'version':6,'quorum':1,'authorities':[{'id':'authority','address':'192.168.1.2:9100','public_key':'01'*32}]}
def transport():
    return {'mode':'client','binary':'/usr/bin/obfs4proxy',
            'bridges':[{'identity':[2]*32,'bridge':'192.168.1.3:443','arguments':{'cert':'fixture','iat-mode':'0'}}],
            'authorities':[{'identity':[1]*32,'bridge':'192.168.1.2:8443','arguments':{'cert':'fixture','iat-mode':'0'}}]}
def client():
    return setup.profile('client',document(),'ab'*32,transport=transport(),transport_digest='cd'*32)
def query():
    return struct.pack('!6H',42,0x100,1,0,0,0)+b'\x07example\x03com\0\0\x01\0\x01'
class Contracts(unittest.TestCase):
    def test_containment_probe_reports_refusal_without_changing_policy(self):
        with patch.object(setup.os, 'geteuid', return_value=1000), \
                patch.object(setup.Path, 'resolve', return_value=Path('/usr/bin/true')), \
                patch.object(setup.Path, 'stat', return_value=SimpleNamespace(st_mode=setup.stat.S_IFREG | 0o755, st_uid=0)), \
                patch.object(setup.Path, 'read_text', return_value='1\n'), \
                patch.object(setup.os, 'access', return_value=True), \
                patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'permission denied')) as run:
            result = setup.check_app_containment()
        self.assertFalse(result['namespace_probe_passed'])
        self.assertFalse(result['host_policy_modified'])
        self.assertIn('do not disable', result['action'])
        self.assertEqual(run.call_count, 1)
        self.assertIn('--unshare-all', run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs['timeout'], 10)

    def test_containment_probe_does_not_accept_root_as_application_user(self):
        with patch.object(setup.os, 'geteuid', return_value=0), patch.object(setup.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'without sudo'):
                setup.check_app_containment()
        run.assert_not_called()

    def test_bootstrap_shapes(self):
        setup.bootstrap(json.dumps(document()))
        for bad in (None,[],{},dict(document(),quorum=0),dict(document(),authorities=[None])):
            with self.assertRaises(ValueError): setup.bootstrap(json.dumps(bad))
    def test_native_client_boundary(self):
        files=client()
        self.assertIn('--padded-sessions',files['etc/systemd/system/anonguard-client.service'])
        firewall=files['etc/anonguard/native.nft']
        self.assertEqual(firewall.count('policy drop'),3)
        self.assertNotIn('output ct state established accept',firewall)
        self.assertNotIn('flush ruleset',firewall)
        self.assertNotIn('ExecStop=',setup.FIREWALL_SERVICE)
        self.assertFalse(json.loads(files['etc/anonguard/device.json'])['deployment_accepted'])
    def test_volunteer_nonexit(self):
        files=setup.profile('volunteer',document(),'ab'*32,advertised='192.168.1.3:9443')
        self.assertNotIn('etc/anonguard/native.nft',files)
        self.assertNotIn('--exit',files['etc/systemd/system/anonguard-relay.service'])
        with self.assertRaises(ValueError): setup.profile('volunteer',document(),'ab'*32)
    def test_exclusive_private_write(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'config';setup.write_exclusive(p,'original')
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError): setup.write_exclusive(p,'replacement')
            self.assertEqual(p.read_text(),'original')
    def test_browser_native_boundary(self):
        doc=json.loads(client()['etc/anonguard/device.json'])
        with patch.object(browser.subprocess,'run') as run:
            browser.validate_native(doc);self.assertEqual(run.call_count,4)
        with self.assertRaises(ValueError): browser.validate_native(dict(doc,role='volunteer'))
        with self.assertRaises(ValueError): browser.validate_native(dict(doc,entry_policy='direct-lab'))
        browser.validate_policy(browser.policy('127.0.0.1',9050,True),'127.0.0.1',9050,True)
    def test_dns_bounds(self):
        self.assertEqual(adapter.dns_question(query()),(query()[12:],512))
        for bad in (query()+b'x',query()[:12]+b'\xc0\x0c\0\x01\0\x01',b'x'*4097,b''):
            with self.assertRaises(ValueError): adapter.dns_question(bad)
    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd parser unavailable')
    def test_generated_native_units_have_valid_dependency_graph(self):
        files=client()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);units=[]
            for name,content in files.items():
                if not name.endswith('.service'): continue
                content='\n'.join('ExecStart=/usr/bin/true' if line.startswith('ExecStart=') else
                                  'ExecReload=/usr/bin/true' if line.startswith('ExecReload=') else line
                                  for line in content.splitlines())+'\n'
                unit=root/Path(name).name;unit.write_text(content);units.append(str(unit))
            env=dict(os.environ,SYSTEMD_UNIT_PATH=str(root)+':/usr/lib/systemd/system')
            result=subprocess.run(['systemd-analyze','verify',*units],env=env,
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_protected_entry_provisions_exact_policy_and_restricts_transport_egress(self):
        files=client();unit=files['etc/systemd/system/anonguard-client.service']
        self.assertIn('--protected-entry --private-bridges',unit)
        self.assertIn('BindsTo=anonguard-native-pt.service',unit)
        self.assertIn('PartOf=anonguard-native-pt.service',unit)
        self.assertIn('LoadCredential=authorities.json:',unit)
        self.assertIn('--bridge-transports ${CREDENTIALS_DIRECTORY}/bridges.json',unit)
        firewall=files['etc/anonguard/native.nft']
        self.assertNotIn('meta skuid "anonguard-net" meta nfproto ipv4 ip protocol tcp accept',firewall)
        self.assertIn('192.168.1.3 . 443',firewall)
        self.assertIn('192.168.1.2 . 8443',firewall)
        for line in firewall.splitlines():
            if 'nat_output meta skuid !=' in line:self.assertIn('"anonguard-pt-native"',line)
        pt=files['etc/systemd/system/anonguard-native-pt.service']
        self.assertIn('Type=notify',pt);self.assertIn('User=anonguard-pt-native',pt)
        self.assertIn('MemoryMax=256M',pt);self.assertIn('KillMode=control-group',pt)
        self.assertEqual(json.loads(files['etc/anonguard/pt-native.json']),transport())
        self.assertEqual(json.loads(files['etc/anonguard/device.json'])['entry_policy'],'protected-obfs4')

    def test_default_client_refuses_missing_transport_without_implicit_direct_mode(self):
        with self.assertRaisesRegex(ValueError,'authenticated transport'):
            setup.profile('client',document(),'ab'*32)
        lab=setup.profile('client',document(),'ab'*32,direct_entry_lab=True)
        self.assertEqual(json.loads(lab['etc/anonguard/device.json'])['entry_policy'],'direct-lab')
        self.assertNotIn('etc/anonguard/pt-native.json',lab)
        with self.assertRaises(ValueError):setup.profile('client',document(),'ab'*32,transport=transport(),transport_digest='cd'*32,direct_entry_lab=True)
        with self.assertRaises(ValueError):setup.profile('volunteer',document(),'ab'*32,advertised='192.168.1.3:9443',transport=transport())

    def test_transport_pin_coverage_and_argument_admission(self):
        setup.transport_configuration(transport(),document())
        cases=[]
        for field,value in [('mode','server'),('binary','/tmp/obfs4proxy'),('bridges',[]),('authorities',[])]:
            d=transport();d[field]=value;cases.append(d)
        for field,value in [('identity',[3]*32),('bridge','localhost:443'),('bridge','127.0.0.1:443'),('bridge','[::1]:443'),('bridge','192.168.1.2:0'),('bridge','192.168.1.2:08443'),('arguments',{'cert':'x'*255}),('arguments',{'cert':'secret\nline'}),('arguments',{'cert':False})]:
            d=transport();d['authorities'][0][field]=value;cases.append(d)
        d=transport();d['bridges']*=2;cases.append(d)
        d=transport();d['authorities'][0]['proxy']='127.0.0.1:1';cases.append(d)
        for d in cases:
            with self.subTest(case=cases.index(d)):
                with self.assertRaises((ValueError,TypeError)):setup.transport_configuration(d,document())

    def test_transport_file_requires_digest_permissions_and_regular_no_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'pt.json';data=json.dumps(transport()).encode();p.write_bytes(data);p.chmod(0o600)
            digest=hashlib.sha256(data).hexdigest()
            self.assertEqual(setup.read_transport(p,digest,document()),(transport(),digest))
            with self.assertRaises(ValueError):setup.read_transport(p,'00'*32,document())
            p.chmod(0o644)
            with self.assertRaises(ValueError):setup.read_transport(p,digest,document())
            p.chmod(0o600);link=Path(directory)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):setup.read_transport(link,digest,document())

    def test_cli_renders_protected_private_artifacts_and_refuses_missing_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bootstrap=root/'network.json';bootstrap.write_text(json.dumps(document()))
            pt=root/'pt.json';pt.write_text(json.dumps(transport()));pt.chmod(0o600)
            base=[sys.executable,str(Path(setup.__file__)),'--role','client','--bootstrap',str(bootstrap),
                  '--bootstrap-sha256',hashlib.sha256(bootstrap.read_bytes()).hexdigest()]
            refused=subprocess.run(base+['--output',str(root/'refused')],capture_output=True,text=True,timeout=5)
            self.assertEqual(refused.returncode,1);self.assertFalse((root/'refused').exists())
            rendered=subprocess.run(base+['--transport-config',str(pt),'--transport-config-sha256',
                                          hashlib.sha256(pt.read_bytes()).hexdigest(),'--output',str(root/'rendered')],
                                    capture_output=True,text=True,timeout=5)
            self.assertEqual(rendered.returncode,0,rendered.stderr)
            self.assertFalse(json.loads(rendered.stdout)['services_started'])
            private=root/'rendered/etc/anonguard/pt-native.json'
            self.assertEqual(private.stat().st_mode&0o777,0o600)
            self.assertEqual(json.loads(private.read_text()),transport())
            self.assertEqual((root/'rendered').stat().st_mode&0o777,0o700)

    def test_bootstrap_authority_addition_requires_new_transport_coverage(self):
        changed=document();changed['authorities'].append({'id':'b','address':'192.168.1.4:9100','public_key':'03'*32});changed['quorum']=2
        with self.assertRaisesRegex(ValueError,'exactly'):
            setup.transport_configuration(transport(),changed)

    def test_native_optimization_profiles_are_explicit_and_preserved(self):
        files=setup.profile('client',document(),'ab'*32,transport=transport(),transport_digest='cd'*32,
                            link_cover_profile='economy',privacy_profile='balanced-longtail')
        unit=files['etc/systemd/system/anonguard-client.service']
        self.assertIn('--link-cover-profile economy',unit)
        self.assertIn('--privacy-profile balanced-longtail',unit)
        policy=json.loads(files['etc/anonguard/device.json'])
        self.assertEqual(policy['link_cover_profile'],'economy')
        self.assertEqual(policy['privacy_profile'],'balanced-longtail')
        with self.assertRaises(ValueError):
            setup.profile('client',document(),'ab'*32,direct_entry_lab=True,link_cover_profile='uncovered')
        with self.assertRaises(ValueError):
            setup.profile('volunteer',document(),'ab'*32,advertised='192.168.1.3:9443',privacy_profile='balanced-longtail')

    def test_public_profile_permissions_do_not_depend_on_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            previous=os.umask(0o077)
            try:
                path=Path(directory)/'public'/'device.json'
                setup.write_exclusive(path,'{}',0o644)
            finally: os.umask(previous)
            self.assertEqual(path.stat().st_mode&0o777,0o644)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o755)

    def test_dns_response_binds_id_and_question(self):
        response=adapter.dns_error(query(),query()[12:],code=0)
        adapter.validate_response(query(),response)
        for bad in (b'xx'+response[2:],response[:13]+b'X'+response[14:],response[:4]+b'\0\0'+response[6:]):
            with self.assertRaises(ValueError): adapter.validate_response(query(),bad)
class Loopback(unittest.IsolatedAsyncioTestCase):
    async def test_socks_context_contract(self):
        async def accept(reader,writer):
            try:
                self.assertEqual(await reader.readexactly(3),b'\x05\x01\x02')
                writer.write(b'\x05\x02');await writer.drain()
                self.assertEqual(await reader.readexactly(2),b'\x01\x20')
                self.assertEqual(await reader.readexactly(32),adapter.CONTEXT)
                self.assertEqual(await reader.readexactly(2),b'\x01\x01')
                writer.write(b'\x01\0');await writer.drain()
                self.assertEqual(await reader.readexactly(10),b'\x05\x01\0\x01\x08\x08\x08\x08\x01\xbb')
                writer.write(b'\x05\0\0\x01'+b'\0'*6);await writer.drain()
                self.assertEqual(await reader.readexactly(5),b'hello')
                writer.write(b'world');await writer.drain()
            finally: await adapter.close(writer)
        async with await asyncio.start_server(accept,'127.0.0.1',0) as server:
            reader,writer=await asyncio.wait_for(adapter.socks_connect('8.8.8.8',443,server.sockets[0].getsockname()[1]),3)
            writer.write(b'hello');await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(5),3),b'world')
            await adapter.close(writer)
    async def test_dns_no_fallback(self):
        with patch.object(adapter,'dns_lookup',side_effect=OSError('proxy unavailable')):
            answer=await adapter.answer_dns(query())
        self.assertEqual(struct.unpack('!H',answer[2:4])[0]&15,2)
if __name__=='__main__': unittest.main()
