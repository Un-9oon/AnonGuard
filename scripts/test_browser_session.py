"""Offline browser policy, topology and lifecycle contracts; no real browser launch."""
import importlib.util
import json
import hashlib
import io
import zipfile
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('browser_session', Path(__file__).with_name('browser_session.py'))
browser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


class BrowserSessionTests(unittest.TestCase):
    def topology(self):
        return ({'version': 1, 'gateway': '10.77.0.1', 'port': 9050,
                 'application_interface': 'eth0', 'application': '10.77.0.2',
                 'subnet': '10.77.0.0/24'},
                [{'ifname': 'lo'}, {'ifname': 'eth0', 'addr_info': [
                    {'family': 'inet', 'local': '10.77.0.2', 'prefixlen': 24}]}],
                [{'dst': '10.77.0.0/24', 'dev': 'eth0'}, {'dst': '127.0.0.0/8', 'dev': 'lo'}])

    def test_policy_requires_locked_remote_dns_no_exceptions_or_extensions(self):
        document = browser.policy('10.77.0.1', 9050)
        browser.validate_policy(document, '10.77.0.1', 9050)
        proxy = document['policies']['Proxy']
        self.assertTrue(proxy['Locked'])
        self.assertTrue(proxy['UseProxyForDNS'])
        self.assertEqual(proxy['Passthrough'], '')
        self.assertEqual(proxy['SOCKSVersion'], 5)
        self.assertEqual(document['policies']['ExtensionSettings']['*']['installation_mode'], 'blocked')
        for name in ('network.proxy.failover_direct', 'media.peerconnection.enabled',
                     'network.http.http3.enable'):
            self.assertEqual(document['policies']['Preferences'][name],
                             {'Value': False, 'Status': 'locked', 'Type': 'boolean'})
        self.assertNotIn('DisableAppUpdate', document['policies'])
        self.assertNotIn('DisableRemoteSettingsAndAcceptSecurityConsequences', document['policies'])
        proxy['Passthrough'] = '<local>'
        with self.assertRaises(ValueError):
            browser.validate_policy(document, '10.77.0.1', 9050)

    def test_wrong_gateway_additional_adapter_ipv6_and_default_route_refuse(self):
        document, addresses, routes = self.topology()
        browser.validate_vm(document, '10.77.0.1', 9050, addresses, routes)
        invalid = [
            (dict(document, gateway='10.77.0.3'), addresses, routes),
            (document, addresses + [{'ifname': 'eth1'}], routes),
            (document, [{'ifname': 'eth0', 'addr_info': [
                {'family': 'inet6', 'local': 'fe80::1', 'prefixlen': 64}]}], routes),
            (document, addresses, routes + [{'dst': 'default', 'dev': 'eth0'}]),
            (document, addresses, routes + [{'dst': '8.8.8.8/32', 'dev': 'eth0'}]),
            (document, addresses, routes + [{'dst': '10.77.0.0/24', 'dev': 'eth0', 'gateway': '10.77.0.1'}]),
        ]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                browser.validate_vm(args[0], '10.77.0.1', 9050, args[1], args[2])

    def test_policy_creation_is_exclusive_and_never_starts_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'policies.json'
            command = [sys.executable, browser.__file__, '--emit-policy', str(destination)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['browser_accepted'])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            before = destination.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(destination.read_bytes(), before)

    def test_untrusted_and_nonregular_policy_files_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'policy.json'
            target.write_text('{}')
            with self.assertRaises(ValueError):
                browser.trusted_file(target)
            with self.assertRaises(ValueError):
                browser.trusted_file(Path('relative.json'))
            link = Path(directory) / 'link'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                browser.trusted_file(link)

    def test_session_strips_sandbox_overrides_and_uses_fresh_profile(self):
        with patch.dict(os.environ, {'MOZ_DISABLE_CONTENT_SANDBOX': '1', 'LD_PRELOAD': '/bad.so',
                                     'ALL_PROXY': 'http://bad', 'DISPLAY': ':99'}, clear=True):
            environment = browser.session_environment(Path('/session'))
        self.assertEqual(environment['DISPLAY'], ':99')
        for name in ('MOZ_DISABLE_CONTENT_SANDBOX', 'LD_PRELOAD', 'ALL_PROXY'):
            self.assertNotIn(name, environment)
        prefs = browser.preferences('10.77.0.1', 9050, Path('/session/downloads'))
        self.assertIn('user_pref("network.proxy.socks_remote_dns", true);', prefs)
        self.assertIn('user_pref("network.proxy.no_proxies_on", "");', prefs)
        process = Mock(pid=987654321)
        process.wait.return_value = 0
        observed = []
        def spawn(command, **kwargs):
            root = Path(command[command.index('--profile') + 1])
            self.assertTrue((root / 'user.js').is_file())
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(command[-1], 'about:blank')
            observed.append(root)
            return process
        with patch.object(browser.subprocess, 'Popen', side_effect=spawn), \
                patch.object(browser.os, 'killpg', side_effect=ProcessLookupError):
            self.assertEqual(browser.launch(Path('/usr/bin/firefox-esr'), '10.77.0.1', 9050), 0)
        self.assertFalse(observed[0].exists())

    def test_privacy_locks_use_exact_autoconfig_not_unsupported_enterprise_preferences(self):
        policy = browser.policy('10.77.0.1', 9050)['policies']['Preferences']
        for name, value in browser.AUTOCONFIG_PREFERENCES.items():
            self.assertNotIn(name, policy)
            self.assertIn(f'lockPref({json.dumps(name)}, {json.dumps(value)});', browser.autoconfig())
        self.assertNotIn('sandbox_enabled', browser.AUTOCONFIG_LOADER)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'config'
            command = [sys.executable, browser.__file__, '--emit-autoconfig', str(output)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual((output / 'anonguard.cfg').read_text(), browser.autoconfig())
            self.assertEqual((output / 'anonguard.js').read_text(), browser.AUTOCONFIG_LOADER)
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=5).returncode, 1)

    def test_bundle_is_coherent_exclusive_and_invalid_endpoint_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'bundle'
            manifest = browser.emit_bundle(destination, '127.0.0.1', 9050, True, True)
            self.assertTrue(manifest['signed_extension_required'])
            self.assertFalse(manifest['browser_accepted'])
            for name, digest in manifest['sha256'].items():
                self.assertEqual(hashlib.sha256((destination / name).read_bytes()).hexdigest(), digest)
                self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((destination / 'policies.json').read_text()),
                             browser.policy('127.0.0.1', 9050, True, True))
            with self.assertRaises(FileExistsError):
                browser.emit_bundle(destination, '127.0.0.1', 9050, True, True)
            bad = Path(directory) / 'bad'
            with self.assertRaises(ValueError):
                browser.emit_bundle(bad, '8.8.8.8', 9050, True, True)
            self.assertFalse(bad.exists())

    def test_extension_preflight_rejects_unsigned_wrong_identity_and_extra_code(self):
        source = Path(__file__).resolve().parents[1] / 'browser/isolation'
        manifest = json.loads((source / 'manifest.json').read_text())
        def package(document, signatures=True, extra=None):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.writestr('manifest.json', json.dumps(document))
                archive.writestr('isolation.js', 'test')
                archive.writestr('background.js', 'test')
                if signatures:
                    archive.writestr('META-INF/mozilla.rsa', 'fixture, not a signature')
                    archive.writestr('META-INF/mozilla.sf', 'fixture, not a signature')
                if extra:
                    archive.writestr(extra, 'test')
            return stream.getvalue()
        result = browser.validate_extension(package(manifest))
        self.assertFalse(result['signature_verified'])
        wrong = json.loads(json.dumps(manifest))
        wrong['browser_specific_settings']['gecko']['id'] = 'other@example.com'
        for content in (package(manifest, False), package(wrong),
                        package(manifest, extra='../escape'), package(manifest, extra='extra.js'), b'bad'):
            with self.subTest(content=content[:20]), self.assertRaises(ValueError):
                browser.validate_extension(content)

    def test_invalid_endpoint_never_creates_policy(self):
        for host in ('127.0.0.1', '8.8.8.8', '::1', '10.77.0.1;exec'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                browser.policy(host, 9050)

    def test_failed_browser_start_removes_new_session_directory(self):
        observed = []
        def fail(command, **_kwargs):
            observed.append(Path(command[command.index('--profile') + 1]))
            raise OSError('Browser cannot execute')
        with patch.object(browser.subprocess, 'Popen', side_effect=fail):
            with self.assertRaises(OSError):
                browser.launch(Path('/usr/bin/firefox-esr'), '10.77.0.1', 9050)
        self.assertFalse(observed[0].exists())


if __name__ == '__main__':
    unittest.main()
