#!/usr/bin/python3 -I
"""Generated native firewall + real adapter inside a private user/network namespace.
Never activates host firewall or creates host accounts. Backend is a SOCKS fixture.
"""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
setup=load('device_setup');adapter=load('native_adapter')
def exact(stream,size):
    data=b''
    while len(data)<size:
        part=stream.recv(size-len(data))
        if not part:raise EOFError()
        data+=part
    return data
class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            stream=self.request;stream.settimeout(20)
            head=exact(stream,2);exact(stream,head[1]);stream.sendall(b'\x05\x02')
            head=exact(stream,2);exact(stream,head[1]);exact(stream,exact(stream,1)[0]);stream.sendall(b'\x01\x00')
            head=exact(stream,4)
            if head[3]==1:exact(stream,4)
            elif head[3]==3:exact(stream,exact(stream,1)[0])
            else:return
            port=struct.unpack('!H',exact(stream,2))[0]
            stream.sendall(b'\x05\x00\x00\x01'+b'\x00'*6)
            if port==853:return  # Fail DNS-over-TLS closed; never use clear DNS fallback.
            stream.sendall(b'OWNED-SOCKS-FIXTURE')
            while stream.recv(1024):pass
        except (OSError,EOFError):return
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True

def fork_service(uid, run):
    pid=os.fork()
    if pid==0:
        try:
            try:os.setgroups([])
            except PermissionError:pass  # A deny-setgroups user namespace cannot add groups.
            os.setgid(uid);os.setuid(uid)
            run()
        finally:os._exit(0)
    return pid

def ready(port):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.2):return
        except OSError:time.sleep(.05)
    raise TimeoutError(f'Fixture {port} not ready')

def inside(parent_namespace):
    assert os.geteuid()==0 and os.stat('/proc/self/ns/net').st_ino!=parent_namespace,'Private namespace required'
    interfaces={line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]}
    assert interfaces=={'lo'},'Refusing a namespace with external interfaces'
    children=[];capture=None
    with tempfile.TemporaryDirectory(prefix='ag-native-ns-') as temporary:
        temporary=Path(temporary)
        try:
            subprocess.run(['ip','link','set','lo','up'],check=True)
            for address in ('93.184.216.34/32','8.8.8.8/32'):
                subprocess.run(['ip','addr','add',address,'dev','lo'],check=True)
            children.append(fork_service(1,lambda:Server(('127.0.0.1',9050),Backend).serve_forever()))
            children.append(fork_service(2,lambda:asyncio.run(adapter.main())))
            for port in (9050,9040,1053):ready(port)
            rules=setup.client_firewall().replace('"anonguard-net"','1').replace('"anonguard-adapter"','2')
            # Numeric fixture UIDs replace account names, with unchanged rules.
            # Explicit terminal counter is equivalent to the existing drop policy.
            rules+='add rule inet anonguard_native output counter drop\n'
            result=subprocess.run(['nft','-f','-'],input=rules,text=True,capture_output=True)
            if result.returncode:raise RuntimeError(result.stderr)
            capture=subprocess.Popen(['tcpdump','-i','lo','-U','-w',str(temporary/'capture.pcap')],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            time.sleep(.2)
            assert capture.poll() is None,'Packet capture did not start'
            connection=socket.create_connection(('93.184.216.34',443),timeout=3)
            connection.settimeout(3)
            assert connection.recv(64)==b'OWNED-SOCKS-FIXTURE','Transparent adapter did not route to SOCKS'
            # Direct UDP has a valid route but is denied by generated policy.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                try:udp.sendto(b'NO-DIRECT-UDP',('93.184.216.34',4444))
                except PermissionError:pass
            # Direct IPv6 has a valid loopback route but is also denied.
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as ipv6:
                ipv6.settimeout(.3)
                try:ipv6.connect(('::1',4444));raise AssertionError('IPv6 unexpectedly connected')
                except (TimeoutError,ConnectionRefusedError,PermissionError):pass
            # Native DNS must return SERVFAIL when authenticated DoT cannot be established.
            query=struct.pack('!6H',123,0x100,1,0,0,0)+b'\x07example\x07invalid\x00'+struct.pack('!HH',1,1)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
                dns.settimeout(5);dns.sendto(query,('8.8.8.8',53));reply,_=dns.recvfrom(4096)
                assert reply[:2]==query[:2] and reply[3]&15==2,'DNS failed open instead of SERVFAIL'
            os.kill(children[0],signal.SIGKILL);os.waitpid(children.pop(0),0)
            assert connection.recv(64)==b'','Backend crash retained active application stream'
            connection.close()
            new=socket.create_connection(('93.184.216.34',443),timeout=3);new.settimeout(18)
            assert new.recv(64)==b'','Backend loss provided direct fallback';new.close()
            data=json.loads(subprocess.check_output(['nft','-j','list','table','inet','anonguard_native'],text=True))
            counters=[expression['counter']['packets'] for entry in data['nftables'] if 'rule' in entry
                      for expression in entry['rule'].get('expr',[]) if 'counter' in expression]
            assert sum(counters)>=2,'UDP/IPv6 attempts did not hit firewall denial'
            capture.send_signal(signal.SIGINT);capture.wait(timeout=3)
            packets=subprocess.check_output(['tcpdump','-nn','-r',str(temporary/'capture.pcap')],stderr=subprocess.DEVNULL,text=True)
            assert ': UDP, length 13' not in packets,'Direct UDP was emitted despite firewall'
            assert ' IP6 ' not in packets,'IPv6 packets passed generated firewall'
            assert '.9040:' in packets and '.9050:' in packets and '.1053:' in packets,'Capture missed transparent/SOCKS/DNS paths'
            os.kill(children[0],signal.SIGKILL);os.waitpid(children.pop(0),0)
            # Neither daemon death removes the table. New direct traffic stays
            # redirected/denied after both controlled services disappear.
            subprocess.run(['nft','list','table','inet','anonguard_native'],stdout=subprocess.DEVNULL,check=True)
            print(json.dumps({'namespace_only':True,'generated_firewall':True,'real_native_adapter':True,
                              'packet_capture':True,'transparent_tcp':True,'dns_fail_closed':True,
                              'udp_ipv6_denied':True,'backend_crash_closes_streams':True,
                              'host_firewall_modified':False,'real_relay_backend':False,'production_accepted':False}))
        finally:
            if capture and capture.poll() is None:capture.send_signal(signal.SIGINT);capture.wait(timeout=3)
            for child in children:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(child,0)

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--inside':inside(int(sys.argv[2]))
    elif len(sys.argv)==1:
        parent=os.stat('/proc/self/ns/net').st_ino
        namespace = ['unshare', '--net'] if os.geteuid() == 0 else ['unshare', '--user', '--map-auto', '--map-root-user', '--net']
        subprocess.run(namespace+[sys.executable,str(Path(__file__).resolve()),'--inside',str(parent)],check=True)
    else:raise SystemExit('No host activation supported')
