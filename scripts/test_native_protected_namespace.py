#!/usr/bin/python3 -I
"""Protected native egress UID/endpoint rules in a disposable network namespace.
An explicit fixture INPUT exception admits synthetic remote-address listeners on lo.
This checks production OUTPUT/NAT rules, not a real relay or full deployment.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

spec = importlib.util.spec_from_file_location('setup', Path(__file__).with_name('device_setup.py'))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def connect_as(uid, address):
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        try:
            with socket.create_connection(address, timeout=.5):
                os.write(writer, b'1')
        except OSError:
            os.write(writer, b'0')
        os._exit(0)
    os.close(writer)
    result = os.read(reader, 1) == b'1'
    os.close(reader)
    os.waitpid(pid, 0)
    return result


def inside(parent):
    assert os.geteuid() == 0 and os.stat('/proc/self/ns/net').st_ino != parent
    assert set(socket.if_nameindex()) == {(1, 'lo')}, 'Refusing external interfaces'
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'addr', 'add', '192.0.2.10/32', 'dev', 'lo'], check=True)
    listeners = []
    try:
        for address in [('192.0.2.10', 14443), ('192.0.2.10', 14444), ('127.0.0.1', 19050)]:
            s = socket.socket()
            s.bind(address)
            s.listen(32)
            listeners.append(s)
        rules = setup.client_firewall(['192.0.2.10:14443'])
        for name, uid in [('anonguard-net', 1), ('anonguard-adapter', 2), ('anonguard-pt-native', 3)]:
            rules = rules.replace('"' + name + '"', str(uid))
        # Only synthetic servers need these fixture exceptions. No OUTPUT NEW
        # acceptance is added; client egress and NAT remain exactly generated.
        rules += 'add rule inet anonguard_native input iifname "lo" ip daddr 192.0.2.10 tcp dport { 14443, 14444 } accept\n'
        rules += 'add rule inet anonguard_native output meta skuid 0 ct state established accept\n'
        subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
        assert connect_as(3, ('192.0.2.10', 14443)), 'Provisioned PT endpoint blocked'
        assert not connect_as(3, ('192.0.2.10', 14444)), 'PT escaped endpoint port allowlist'
        assert not connect_as(1, ('192.0.2.10', 14443)), 'Gateway bypassed PT'
        assert connect_as(1, ('127.0.0.1', 19050)), 'Gateway cannot reach dynamic PT listener'
        assert not connect_as(65534, ('127.0.0.1', 19050)), 'Ordinary UID reached private PT listener'
        assert not connect_as(65534, ('192.0.2.10', 14443)), 'Ordinary UID bypassed adapter'
        print(json.dumps({'namespace_only': True, 'protected_output_nat_unchanged': True,
                          'pt_endpoint_allowlist': True, 'gateway_direct_denied': True,
                          'ordinary_uid_pt_denied': True, 'dynamic_pt_gateway_allowed': True,
                          'fixture_input_exceptions': True, 'host_firewall_modified': False,
                          'real_relay_backend': False, 'production_accepted': False}))
    finally:
        for s in listeners:
            s.close()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--inside':
        inside(int(sys.argv[2]))
    elif len(sys.argv) == 1 and os.geteuid() == 0:
        subprocess.run(['unshare', '--net', sys.executable, str(Path(__file__).resolve()),
                        '--inside', str(os.stat('/proc/self/ns/net').st_ino)], check=True)
    else:
        raise SystemExit('Requires root; supports disposable namespace testing only')
