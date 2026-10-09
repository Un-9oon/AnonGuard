#!/usr/bin/python3 -I
"""Disposable headless Firefox integration against local SOCKS/HTTP fixtures only.
Not a packet-capture leak audit, signed-addon acceptance or a real relay test.
Requires selenium, maintained Firefox ESR and geckodriver; never changes host policy.
"""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import tempfile
import threading
import unittest
import zipfile
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parents[1]
# Import package helpers without needing to install project code into Python.
import importlib.util
spec = importlib.util.spec_from_file_location('session', ROOT / 'scripts/browser_session.py')
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


def exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('Fixture peer closed')
        result += part
    return result


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BrowserIntegration(unittest.TestCase):
    def test_browser_isolation_and_failure_boundaries(self):
        records, direct = [], []
        lock = threading.Lock()
        class Socks(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    stream = self.request
                    stream.settimeout(10)
                    version, length = exact(stream, 2)
                    methods = exact(stream, length)
                    if version != 5 or 2 not in methods:
                        stream.sendall(b'\x05\xff')
                        return
                    stream.sendall(b'\x05\x02')
                    version, length = exact(stream, 2)
                    label = exact(stream, length).decode('ascii')
                    password = exact(stream, exact(stream, 1)[0])
                    if version != 1 or not re.fullmatch('[0-9a-f]{64}', label) or password != b'anonguard-browser-v1':
                        raise ValueError('Wrong browser circuit credentials')
                    stream.sendall(b'\x01\x00')
                    header = exact(stream, 4)
                    if header[:3] != b'\x05\x01\x00':
                        raise ValueError('Invalid SOCKS CONNECT')
                    if header[3] == 3:
                        host = exact(stream, exact(stream, 1)[0]).decode('ascii')
                    elif header[3] == 1:
                        host = socket.inet_ntoa(exact(stream, 4))
                    else:
                        raise ValueError('Unexpected target type')
                    port = struct.unpack('!H', exact(stream, 2))[0]
                    with lock:
                        records.append((host, port, label, header[3]))
                    stream.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
                    request = b''
                    while b'\r\n\r\n' not in request and len(request) < 16384:
                        request += exact(stream, 1)
                    path = request.split(b' ')[1]
                    if path.endswith(b'.js'):
                        body, kind = b'window.fixtureLoaded=true;document.body.dataset.timezone=Intl.DateTimeFormat().resolvedOptions().timeZone;', b'application/javascript'
                    elif host == 'frame.invalid':
                        body, kind = b'<iframe src="http://nested.invalid/"></iframe>', b'text/html'
                    elif host == 'nested.invalid':
                        body, kind = b'<script src="http://cdn.invalid/nested.js"></script>', b'text/html'
                    else:
                        body, kind = (b'<body>fixture<script src="http://cdn.invalid/script.js"></script>'
                                      b'<iframe src="http://frame.invalid/"></iframe></body>'), b'text/html'
                    stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: ' + kind +
                                   b'\r\nCache-Control: no-store\r\nContent-Length: ' +
                                   str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                except (OSError, EOFError, ValueError, UnicodeError):
                    return
        class Canary(socketserver.BaseRequestHandler):
            def handle(self):
                direct.append(True)
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nDIRECT')
        firefox = os.environ.get('ANONGUARD_FIREFOX') or shutil.which('firefox-esr')
        gecko = os.environ.get('ANONGUARD_GECKODRIVER') or shutil.which('geckodriver')
        self.assertTrue(firefox and gecko, 'Firefox ESR and geckodriver are required')
        # Fixed native endpoint: refuse occupied ports rather than changing another service.
        with Server(('127.0.0.1', 9050), Socks) as socks, \
                Server(('127.0.0.1', 0), Canary) as canary, tempfile.TemporaryDirectory() as directory:
            for server in (socks, canary):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            xpi = Path(directory) / 'temporary.xpi'
            with zipfile.ZipFile(xpi, 'w') as archive:
                for name in ('manifest.json', 'isolation.js', 'background.js'):
                    archive.write(ROOT / 'browser/isolation' / name, name)
            options = Options()
            options.binary_location = firefox
            options.add_argument('-headless')
            for name, value in session.LOCKED_PREFERENCES.items():
                options.set_preference(name, value)
            # Fixture-only HTTP exception. Production HTTPS policy is unchanged.
            options.set_preference('dom.security.https_only_mode', False)
            for name, value in {'network.proxy.type': 1, 'network.proxy.socks': '127.0.0.1',
                                'network.proxy.socks_port': 9, 'network.proxy.socks_version': 5,
                                'network.proxy.socks_remote_dns': True,
                                'network.proxy.no_proxies_on': ''}.items():
                options.set_preference(name, value)
            driver = webdriver.Firefox(options=options, service=Service(gecko, log_output=str(Path(directory) / 'driver.log')))
            driver.set_page_load_timeout(15)
            try:
                addon = driver.install_addon(str(xpi), temporary=True)
                self.assertEqual(addon, 'isolation@anonguard.local')
                wait = WebDriverWait(driver, 10)
                def load(url):
                    driver.get(url)
                    wait.until(lambda browser: browser.execute_script('return window.fixtureLoaded===true'))
                load('http://one.invalid/')
                driver.switch_to.frame(0)
                driver.switch_to.frame(0)
                wait.until(lambda browser: browser.execute_script('return window.fixtureLoaded===true'))
                driver.switch_to.default_content()
                with lock:
                    first = list(records)
                one = next(record[2] for record in first if record[0] == 'one.invalid')
                for host in ('cdn.invalid', 'frame.invalid', 'nested.invalid'):
                    selected = [record for record in first if record[0] == host]
                    self.assertTrue(selected, host)
                    self.assertTrue(all(record[2] == one for record in selected), host)
                self.assertTrue(all(record[3] == 3 for record in first), 'Domains must reach SOCKS without local DNS')
                self.assertEqual(driver.execute_script('return typeof RTCPeerConnection'), 'undefined')
                self.assertEqual(driver.find_element('tag name', 'body').get_attribute('data-timezone'), 'Atlantic/Reykjavik')
                load('http://two.invalid/')
                two = next(record[2] for record in records if record[0] == 'two.invalid')
                self.assertNotEqual(one, two)
                driver.switch_to.new_window('tab')
                before = len(records)
                load('http://one.invalid/')
                tab = next(record[2] for record in records[before:] if record[0] == 'one.invalid')
                self.assertNotEqual(one, tab)
                canary_url = f'http://127.0.0.1:{canary.server_address[1]}/'
                load(canary_url)
                self.assertFalse(direct, 'Browser bypassed SOCKS for loopback target')
                driver.uninstall_addon(addon)
                before = len(records)
                try:
                    driver.get(canary_url + '?missing-addon')
                except WebDriverException:
                    pass
                self.assertNotIn('fixture', driver.page_source)
                self.assertEqual(len(records), before, 'Missing addon used default NOAUTH circuit')
                self.assertFalse(direct)
                driver.install_addon(str(xpi), temporary=True)
                socks.shutdown()
                socks.server_close()
                try:
                    driver.get(canary_url + '?proxy-down')
                except WebDriverException:
                    pass
                self.assertNotIn('fixture', driver.page_source)
                self.assertFalse(direct, 'Proxy loss caused direct fallback')
                print(json.dumps({'browser': driver.capabilities['browserVersion'],
                                  'temporary_addon': True, 'nested_resources': True,
                                  'site_and_tab_contexts': True, 'remote_domain_socks': True,
                                  'missing_addon_and_proxy_failure': True,
                                  'packet_capture_leak_audit': 'NOT PERFORMED',
                                  'production_accepted': False}))
            finally:
                driver.quit()
                socks.shutdown()
                canary.shutdown()

if __name__ == '__main__':
    unittest.main()
