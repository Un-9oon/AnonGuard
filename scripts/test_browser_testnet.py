#!/usr/bin/python3 -I
"""Actual Firefox -> observed local SOCKS -> real AnonGuard CLI testnet -> owned HTTP.
Called by the Rust testnet fixture. Private exits/zero PoW are lab-only settings.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import socketserver
import struct
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('session', ROOT / 'scripts/browser_session.py')
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)

def exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size-len(data))
        if not part: raise EOFError()
        data += part
    return data

class Tap(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            incoming=self.request; incoming.settimeout(10)
            with socket.create_connection(('127.0.0.1', self.server.gateway_port),timeout=10) as upstream:
                header=exact(incoming,2); upstream.sendall(header+exact(incoming,header[1]))
                method=exact(upstream,2); incoming.sendall(method)
                if method!=b'\x05\x02': raise ValueError('Real gateway refused context method')
                header=exact(incoming,2); label=exact(incoming,header[1]); length=exact(incoming,1); password=exact(incoming,length[0])
                upstream.sendall(header+label+length+password)
                reply=exact(upstream,2); incoming.sendall(reply)
                if reply!=b'\x01\x00': raise ValueError('Real gateway refused context')
                header=exact(incoming,4)
                if header[3]==1: target=exact(incoming,4)
                elif header[3]==3:
                    length=exact(incoming,1);target=length+exact(incoming,length[0])
                else: raise ValueError('Unexpected target family')
                port=exact(incoming,2);upstream.sendall(header+target+port)
                with self.server.lock:self.server.records.append((struct.unpack('!H',port)[0],label.decode()))
                # Forward the actual gateway response/data without synthesizing
                # SOCKS success or destination content. No DNS/replay fallback.
                peers=[incoming,upstream];deadline=time.monotonic()+45
                while peers and time.monotonic()<deadline:
                    ready,_,_=select.select(peers,[],[],1)
                    for source in ready:
                        destination=upstream if source is incoming else incoming
                        data=source.recv(65536)
                        if not data:
                            peers.remove(source)
                            destination.shutdown(socket.SHUT_WR)
                        else:destination.sendall(data)
        except (OSError,EOFError,ValueError,UnicodeError):return

class TapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True

class Pages(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('.js'):
            content=b'window.fixtureLoaded=true;';kind='application/javascript'
        else:
            nested=''
            if self.server.role=='root':nested=f'<iframe src="http://127.0.0.1:{self.server.frame_port}/"></iframe>'
            content=(f'<body>real AnonGuard testnet{nested}<script src="http://127.0.0.1:{self.server.script_port}/test.js"></script></body>').encode();kind='text/html'
        self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(content)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(content)
    def log_message(self,*_):pass

def main():
    gateway=int(os.environ['ANONGUARD_TESTNET_GATEWAY_PORT'])
    if not 1024<=gateway<=65535:raise ValueError('Invalid local gateway port')
    pages=[]
    for role in ('root','second','frame','script'):
        server=ThreadingHTTPServer(('127.0.0.1',0),Pages);server.daemon_threads=True;server.role=role;pages.append(server)
    for server in pages:
        server.frame_port=pages[2].server_port;server.script_port=pages[3].server_port
        threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with TapServer(('127.0.0.1',9050),Tap) as tap,tempfile.TemporaryDirectory() as temporary:
            tap.gateway_port=gateway;tap.records=[];tap.lock=threading.Lock()
            threading.Thread(target=tap.serve_forever,daemon=True).start()
            archive=Path(temporary)/'lab.xpi'
            with zipfile.ZipFile(archive,'w') as zipfile_object:
                for name in ('manifest.json','background.js','isolation.js'):zipfile_object.write(ROOT/'browser/isolation'/name,name)
            options=Options();options.binary_location=os.environ.get('ANONGUARD_FIREFOX') or shutil.which('firefox-esr');options.add_argument('-headless')
            for key,value in session.LOCKED_PREFERENCES.items():options.set_preference(key,value)
            for key,value in {'dom.security.https_only_mode':False,'network.proxy.type':1,'network.proxy.socks':'127.0.0.1','network.proxy.socks_port':9,'network.proxy.socks_version':5,'network.proxy.socks_remote_dns':True,'network.proxy.no_proxies_on':''}.items():options.set_preference(key,value)
            driver=webdriver.Firefox(options=options,service=Service(os.environ.get('ANONGUARD_GECKODRIVER') or shutil.which('geckodriver'),log_output=str(Path(temporary)/'driver.log')))
            driver.set_page_load_timeout(20)
            try:
                driver.install_addon(str(archive),temporary=True);wait=WebDriverWait(driver,15)
                def load(port):
                    driver.get(f'http://127.0.0.1:{port}/');wait.until(lambda browser:browser.execute_script('return window.fixtureLoaded===true'))
                load(pages[0].server_port);driver.switch_to.frame(0);wait.until(lambda browser:browser.execute_script('return window.fixtureLoaded===true'));driver.switch_to.default_content()
                with tap.lock:first=list(tap.records)
                label=next(value for port,value in first if port==pages[0].server_port)
                for expected in (pages[2].server_port,pages[3].server_port):
                    values=[value for port,value in first if port==expected]
                    assert values and all(value==label for value in values),'Third party escaped root context'
                load(pages[1].server_port)
                with tap.lock:second=next(value for port,value in tap.records if port==pages[1].server_port)
                assert second!=label,'Distinct origins shared a real gateway context'
                print(json.dumps({'real_cli_onion_testnet':True,'browser':driver.capabilities['browserVersion'],'parent_resources_loaded':True,'origin_credentials_separated':True,'production_accepted':False}))
            finally:driver.quit();tap.shutdown()
    finally:
        for server in pages:server.shutdown();server.server_close()

if __name__=='__main__':
    def expired(*_):raise TimeoutError('Browser testnet deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(75)
    main()
