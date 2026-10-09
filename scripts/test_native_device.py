"""Offline setup and localhost adapter contracts; never apply firewall or services."""
import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
setup=load('device_setup');adapter=load('native_adapter');browser=load('browser_session')
def document():
    return {'version':1,'quorum':1,'authorities':[{'id':'authority','address':'192.168.1.2:9100','public_key':'01'*32}]}
def query():
    return struct.pack('!6H',42,0x100,1,0,0,0)+b'\x07example\x03com\0\0\x01\0\x01'
class Contracts(unittest.TestCase):
    def test_bootstrap_shapes(self):
        setup.bootstrap(json.dumps(document()))
        for bad in (None,[],{},dict(document(),quorum=0),dict(document(),authorities=[None])):
            with self.assertRaises(ValueError): setup.bootstrap(json.dumps(bad))
    def test_native_client_boundary(self):
        files=setup.profile('client',document(),'ab'*32)
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
        doc=json.loads(setup.profile('client',document(),'ab'*32)['etc/anonguard/device.json'])
        with patch.object(browser.subprocess,'run') as run:
            browser.validate_native(doc);self.assertEqual(run.call_count,3)
        with self.assertRaises(ValueError): browser.validate_native(dict(doc,role='volunteer'))
        browser.validate_policy(browser.policy('127.0.0.1',9050,True),'127.0.0.1',9050,True)
    def test_dns_bounds(self):
        self.assertEqual(adapter.dns_question(query()),(query()[12:],512))
        for bad in (query()+b'x',query()[:12]+b'\xc0\x0c\0\x01\0\x01',b'x'*4097,b''):
            with self.assertRaises(ValueError): adapter.dns_question(bad)
    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd parser unavailable')
    def test_generated_native_units_have_valid_dependency_graph(self):
        files=setup.profile('client',document(),'ab'*32)
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
