"""Offline security-contract checks. No network or firewall mutations."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("vm_profile", Path(__file__).with_name("vm_profile.py"))
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class VMProfileTests(unittest.TestCase):
    def values(self, **changes):
        values = dict(internal="enp0s8", wan="enp0s3", application_interface="eth0",
                      subnet="10.77.0.0/24", gateway="10.77.0.1",
                      application="10.77.0.2", port=9050)
        values.update(changes)
        return profile.validate(**values)

    def test_rejects_network_injection_and_unsafe_topologies(self):
        invalid = [dict(internal=value) for value in
                   ('lo', '*', 'eth0" accept', 'eth0\n', 'eth0;flush ruleset', 'x' * 16)]
        invalid += [dict(wan="enp0s8"), dict(application_interface="lo"),
                    dict(subnet="8.8.8.0/24"), dict(subnet="127.0.0.0/24"),
                    dict(subnet="192.0.2.0/24"), dict(subnet="10.77.0.0/31"),
                    dict(subnet="10.77.0.1/24"), dict(gateway="10.77.0.0"),
                    dict(application="10.77.0.255"), dict(application="10.78.0.2"),
                    dict(application="10.77.0.1"), dict(gateway="::1"),
                    dict(port=0), dict(port=65536), dict(port=80)]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.values(**change)

    def test_application_allows_only_exact_proxy_flow(self):
        files = profile.render(*self.values())
        rules = files["application/etc/anonguard/vm.nft"]
        # All three hooks deny by default, including IPv6 and forwarding.
        self.assertEqual(rules.count("policy drop"), 3)
        accepts = [line for line in rules.splitlines() if line.endswith(" accept")]
        self.assertEqual(len(accepts), 4)
        self.assertIn('oifname "eth0" ip saddr 10.77.0.2 ip daddr 10.77.0.1 '
                      'tcp dport 9050 ct state new,established accept', rules)
        self.assertIn('iifname "eth0" ip saddr 10.77.0.1 ip daddr 10.77.0.2 '
                      'tcp sport 9050 ct state established accept', rules)
        self.assertNotIn('enp0s3', rules)
        self.assertNotIn('related accept', rules)
        self.assertNotIn('udp', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('delete table', rules)
        network = files["application/etc/systemd/network/10-anonguard-internal.network"]
        for setting in ("DHCP=no", "LinkLocalAddressing=no", "IPv6AcceptRA=no", "IPForward=no"):
            self.assertIn(setting, network)
        self.assertNotIn("Gateway=", network)
        self.assertNotIn("DNS=", network)

    def test_gateway_never_forwards_or_exposes_loopback_daemon(self):
        files = profile.render(*self.values(port=9150))
        rules = files["gateway/etc/anonguard/vm.nft"]
        self.assertEqual(rules.count("policy drop"), 3)
        self.assertNotIn('anonguard_vm forward ', rules.split('policy drop; }\n')[-1])
        self.assertFalse(any('add rule inet anonguard_vm forward' in line
                             for line in rules.splitlines()))
        self.assertIn('ip saddr 10.77.0.2 ip daddr 10.77.0.1 tcp dport 9150', rules)
        socket = files["gateway/etc/systemd/system/anonguard-vm-proxy.socket"]
        self.assertIn('ListenStream=10.77.0.1:9150', socket)
        self.assertIn('FreeBind=no', socket)
        service = files["gateway/etc/systemd/system/anonguard-vm-proxy.service"]
        self.assertIn('127.0.0.1:9050', service)
        self.assertIn('--connections-max=64', service)
        self.assertNotIn('--allow-open-socks5', ''.join(files.values()))
        self.assertNotIn('ExecStop=', profile.FIREWALL_UNIT.split('# No ExecStop:')[0])
        self.assertIn('Before=network-pre.target', profile.FIREWALL_UNIT)
        self.assertIn('BindsTo=anonguard-vm-firewall.service anonguard.service', service)

    def test_private_profile_output_no_overwrite_or_final_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "profile"
            files = profile.render(*self.values())
            profile.write_new(destination, files)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            manifest = json.loads((destination / "profile.json").read_text())
            self.assertFalse(manifest["deployment_accepted"])
            self.assertFalse(manifest["browser_hardening_included"])
            self.assertEqual(len(manifest["sha256"]), len(files) - 1)
            for path, digest in manifest["sha256"].items():
                target = destination / path
                self.assertEqual(profile.hashlib.sha256(target.read_bytes()).hexdigest(), digest)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                profile.write_new(destination, files)
            link = Path(directory) / "link"
            link.symlink_to(destination)
            with self.assertRaises(FileExistsError):
                profile.write_new(link, files)
            self.assertEqual((destination / "profile.json").read_text(), files["profile.json"])

    def test_write_failure_removes_only_new_output(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "profile"
            with patch.object(Path, "open", side_effect=OSError("disk unavailable")):
                with self.assertRaises(OSError):
                    profile.write_new(destination, profile.render(*self.values()))
            self.assertFalse(destination.exists())
            self.assertTrue(Path(directory).exists())

    def test_cli_invalid_input_never_creates_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "profile"
            result = subprocess.run([sys.executable, profile.__file__,
                                     '--internal-interface', 'lo', '--wan-interface', 'eth1',
                                     '--application-interface', 'eth0', '--output', str(destination)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(destination.exists())

    @unittest.skipUnless(shutil.which('systemd-analyze') and Path('/usr/sbin/nft').is_file()
                         and Path('/usr/lib/systemd/systemd-socket-proxyd').is_file(),
                         'systemd parser or VM profile helper binaries unavailable')
    def test_native_systemd_parser_accepts_generated_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile.write_new(root / "profile", profile.render(*self.values()))
            units = root / "profile/gateway/etc/systemd/system"
            # Only a parser fixture: do not start a daemon, socket or firewall.
            (units / "anonguard.service").write_text('[Service]\nExecStart=/usr/bin/true\n')
            environment = dict(os.environ, SYSTEMD_UNIT_PATH=str(units) + ':/usr/lib/systemd/system')
            result = subprocess.run(['systemd-analyze', 'verify',
                                     str(units / 'anonguard-vm-firewall.service'),
                                     str(units / 'anonguard-vm-proxy.socket'),
                                     str(units / 'anonguard-vm-proxy.service')],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
