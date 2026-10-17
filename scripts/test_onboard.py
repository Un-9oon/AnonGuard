"""Onboarding orchestration contracts; never activate the host firewall/browser."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('onboard', Path(__file__).with_name('onboard.py'))
onboard = importlib.util.module_from_spec(spec); spec.loader.exec_module(onboard)


def arguments(root, role='client'):
    document = {'version': 6, 'quorum': 1, 'authorities': [
        {'id': 'a1', 'address': '192.168.1.2:9100', 'public_key': '01'*32}]}
    bootstrap = root/'bootstrap.json'; bootstrap.write_text(json.dumps(document))
    transport = {'mode': 'client', 'binary': '/usr/bin/obfs4proxy',
                 'bridges': [{'identity': [2]*32, 'bridge': '192.168.1.3:443', 'arguments': {'cert': 'fixture'}}],
                 'authorities': [{'identity': [1]*32, 'bridge': '192.168.1.2:8443', 'arguments': {'cert': 'fixture'}}]}
    pt = root/'pt.json'; pt.write_text(json.dumps(transport)); pt.chmod(0o600)
    return argparse.Namespace(role=role, bootstrap=bootstrap,
        bootstrap_sha256=hashlib.sha256(bootstrap.read_bytes()).hexdigest(), transport_config=pt if role == 'client' else None,
        transport_config_sha256=hashlib.sha256(pt.read_bytes()).hexdigest() if role == 'client' else None,
        relay_advertise='192.168.1.4:9443' if role == 'volunteer' else None,
        browser=Path('/usr/bin/true') if role == 'client' else None, extension=None, extension_sha256=None, extension_version=None,
        previous_extension_sha256=None)


class OnboardTests(unittest.TestCase):
    def setUp(self):
        # Unit orchestration never opens a host /run lock or changes real files.
        lock = patch.object(onboard, 'configuration_lock', side_effect=contextlib.nullcontext)
        lock.start(); self.addCleanup(lock.stop)
        layout = patch.object(onboard.os, 'statvfs', return_value=Mock(f_flag=0))
        layout.start(); self.addCleanup(layout.stop)
        console = patch.object(onboard.setup, 'require_console')
        console.start(); self.addCleanup(console.stop)

    def test_client_inspection_joins_protected_network_and_browser_without_mutations(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp))
            with patch.object(onboard.os, 'access', return_value=True), \
                 patch.object(onboard.browser, 'trusted_file', return_value=b'fixture'), \
                 patch.object(onboard.browser, 'installed_extension') as extension, \
                 patch.object(onboard, 'validate_targets') as targets, \
                 patch.object(onboard.subprocess, 'run', return_value=Mock(stdout='Mozilla Firefox 140.16.0esr')) as run:
                files, policies, executable = onboard.inspect(args)
            self.assertEqual(len(policies), 4)
            self.assertIn('--protected-entry', files['etc/systemd/system/anonguard-client.service'])
            self.assertIn('127.0.0.1:9', policies[Path('/etc/firefox/policies/policies.json')])
            extension.assert_called_once(); targets.assert_called_once()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][-1], '--version')

    def test_volunteer_requires_no_browser_and_is_nonexit(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp), 'volunteer')
            with patch.object(onboard.os, 'access', return_value=True), patch.object(onboard.subprocess, 'run') as run:
                files, policies, executable = onboard.inspect(args)
            run.assert_not_called(); self.assertFalse(policies); self.assertIsNone(executable)
            self.assertNotIn('--is-exit', files['etc/systemd/system/anonguard-relay.service'])
            self.assertNotIn('etc/anonguard/native.nft', files)

    def test_bootstrap_tamper_and_missing_transport_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp)); args.bootstrap_sha256 = '0'*64
            with self.assertRaises(ValueError): onboard.inspect(args)
            args = arguments(Path(temp)); args.transport_config = None
            with self.assertRaisesRegex(ValueError, 'protected-entry'): onboard.inspect(args)

    def test_missing_dependencies_or_esr_stop_before_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp))
            with patch.object(onboard.os, 'access', return_value=False):
                with self.assertRaisesRegex(ValueError, 'dependencies'): onboard.inspect(args)
            args.browser = None
            with patch.object(onboard.os, 'access', return_value=True):
                with self.assertRaisesRegex(ValueError, '--browser'): onboard.inspect(args)
            args.browser = Path('/usr/bin/true')
            with patch.object(onboard.os, 'access', return_value=True), \
                 patch.object(onboard.browser, 'trusted_file', return_value=b'fixture'), \
                 patch.object(onboard.subprocess, 'run', return_value=Mock(stdout='Mozilla Firefox 157.0.1')):
                with self.assertRaisesRegex(ValueError, 'ESR'): onboard.inspect(args)

    def test_readonly_browser_layout_is_refused_before_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp))
            with patch.object(onboard.os, 'access', return_value=True), \
                 patch.object(onboard.browser, 'trusted_file', return_value=b'fixture'), \
                 patch.object(onboard.os, 'statvfs', return_value=Mock(f_flag=onboard.os.ST_RDONLY)), \
                 patch.object(onboard, 'guarded_write') as write:
                with self.assertRaisesRegex(ValueError, 'read-only'): onboard.inspect(args)
                write.assert_not_called()

    def test_volunteer_refuses_accidental_client_options(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp), 'volunteer'); args.browser = Path('/usr/bin/true')
            with self.assertRaisesRegex(ValueError, 'cannot be applied'): onboard.inspect(args)

    def test_apply_rejects_remote_and_unprivileged_before_changes(self):
        args = argparse.Namespace(role='client')
        for uid, env in [(1000, {}), (0, {'SSH_CONNECTION': 'fixture'})]:
            with patch.object(onboard.os, 'geteuid', return_value=uid), patch.dict(os.environ, env, clear=True), \
                 patch.object(onboard.setup, 'apply') as apply:
                with self.assertRaises(ValueError): onboard.apply(args, {}, {}, None)
                apply.assert_not_called()

    def test_conflicting_native_setup_checked_before_browser_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp))
            with patch.object(onboard.os, 'geteuid', return_value=0), patch.dict(os.environ, {}, clear=True), \
                 patch.object(onboard, 'RECEIPT', Path(temp)/'missing'), \
                 patch.object(onboard.setup, 'validate_apply', side_effect=ValueError('existing state')), \
                 patch.object(onboard, 'guarded_write') as write:
                with self.assertRaisesRegex(ValueError, 'existing state'): onboard.apply(args, {}, {}, None)
                write.assert_not_called()

    def test_apply_order_checks_services_and_keeps_acceptance_false(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp)); events = []
            files = {'etc/anonguard/device.json': '{}'}
            def run(command, **kwargs):
                events.append(command[0] + ' ' + command[1])
                return Mock(returncode=1 if 'pgrep' in command[0] else 0)
            with patch.object(onboard.os, 'geteuid', return_value=0), patch.dict(os.environ, {}, clear=True), \
                 patch.object(onboard, 'RECEIPT', Path(temp)/'onboarding.json'), \
                 patch.object(onboard.setup, 'validate_apply', side_effect=lambda _: events.append('preflight')), \
                 patch.object(onboard.setup, 'apply', side_effect=lambda _: events.append('native apply')), \
                 patch.object(onboard, 'guarded_write', side_effect=lambda *a: events.append('write')), \
                 patch.object(onboard.subprocess, 'run', side_effect=run), \
                 patch.object(onboard.browser, 'validate_autoconfig'), \
                 patch.object(onboard.browser, 'installed_extension'), patch.object(onboard.browser, 'validate_native'):
                result = onboard.apply(args, files, {Path('/unused'): 'fixture'}, Path('/usr/bin/true'))
            self.assertLess(events.index('preflight'), events.index('write'))
            self.assertLess(events.index('write'), events.index('native apply'))
            self.assertEqual(events.count('/usr/bin/systemctl is-active'), 4)
            self.assertTrue(result['configuration_complete'])
            self.assertFalse(result['deployment_accepted']); self.assertFalse(result['browser_accepted'])

    def test_failed_activation_never_removes_firewall_or_records_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            args = arguments(Path(temp), 'volunteer')
            with patch.object(onboard.os, 'geteuid', return_value=0), patch.dict(os.environ, {}, clear=True), \
                 patch.object(onboard, 'RECEIPT', Path(temp)/'missing'), \
                 patch.object(onboard.setup, 'validate_apply'), \
                 patch.object(onboard.setup, 'apply', side_effect=subprocess.CalledProcessError(1, 'fixture')), \
                 patch.object(onboard, 'guarded_write') as write, patch.object(onboard.subprocess, 'run') as run:
                with self.assertRaises(subprocess.CalledProcessError): onboard.apply(args, {}, {}, None)
                write.assert_not_called(); run.assert_not_called()

    def test_launch_is_ordinary_user_and_preserves_selected_browser(self):
        receipt = {'version': 1, 'role': 'client', 'configuration_complete': True, 'browser': '/opt/firefox/firefox'}
        with patch.object(onboard.os, 'geteuid', return_value=1000), \
             patch.object(onboard.browser, 'trusted_file', return_value=json.dumps(receipt).encode()), \
             patch.object(onboard.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            self.assertEqual(onboard.launch(), 0)
            self.assertIn('/opt/firefox/firefox', run.call_args.args[0])
            self.assertNotIn('sudo', run.call_args.args[0])
        with patch.object(onboard.os, 'geteuid', return_value=0), patch.object(onboard.subprocess, 'run') as run:
            with self.assertRaises(ValueError): onboard.launch()
            run.assert_not_called()

    def test_desktop_start_joins_sudo_setup_then_ordinary_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp)/'receipt'
            def setup_run(command, **kwargs):
                self.assertEqual(command, ['/usr/bin/sudo', '/usr/bin/anonguard-onboard', '--apply'])
                receipt.write_text('fixture')
                return Mock(returncode=0)
            data = {'version': 1, 'role': 'client', 'configuration_complete': True}
            with patch.object(onboard, 'RECEIPT', receipt), patch.object(onboard.os, 'geteuid', return_value=1000), \
                 patch.dict(os.environ, {}, clear=True), \
                 patch.object(onboard.subprocess, 'run', side_effect=setup_run) as run, \
                 patch.object(onboard.browser, 'trusted_file', return_value=json.dumps(data).encode()), \
                 patch.object(onboard, 'launch', return_value=0) as launch:
                self.assertEqual(onboard.start(), 0)
                run.assert_called_once(); launch.assert_called_once()
                self.assertEqual(onboard.start(), 0)
                run.assert_called_once()

    def test_volunteer_start_never_launches_browser(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp)/'receipt'; receipt.touch()
            data = {'version': 1, 'role': 'volunteer', 'configuration_complete': True}
            with patch.object(onboard, 'RECEIPT', receipt), patch.object(onboard.os, 'geteuid', return_value=1000), \
                 patch.object(onboard.browser, 'trusted_file', return_value=json.dumps(data).encode()), \
                 patch.object(onboard, 'launch') as launch, patch.object(onboard.subprocess, 'run') as run:
                with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(onboard.start(), 0)
                launch.assert_not_called(); run.assert_not_called()

    def test_first_start_refuses_root_or_remote_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            for uid, env in [(0, {}), (1000, {'SSH_CONNECTION': 'fixture'})]:
                with patch.object(onboard, 'RECEIPT', Path(temp)/'absent'), \
                     patch.object(onboard.os, 'geteuid', return_value=uid), patch.dict(os.environ, env, clear=True), \
                     patch.object(onboard.subprocess, 'run') as run:
                    with self.assertRaises(ValueError): onboard.start()
                    run.assert_not_called()

    def test_console_guard_rejects_ssh_ancestry_after_environment_reset(self):
        # Separate source module keeps the real guard independent of the normal
        # orchestration mock, while process metadata stays entirely synthetic.
        source = importlib.util.spec_from_file_location('console_fixture', Path(__file__).with_name('device_setup.py'))
        setup = importlib.util.module_from_spec(source); source.loader.exec_module(setup)
        def read(path):
            return {'/proc/42/comm': 'python3', '/proc/42/status': 'PPid:\t7\n',
                    '/proc/7/comm': 'sshd-session', '/proc/7/status': 'PPid:\t1\n'}[str(path)]
        with patch.object(setup.os, 'geteuid', return_value=0), patch.object(setup.os, 'getpid', return_value=42), \
             patch.dict(os.environ, {}, clear=True), patch.object(setup.sys.stdin, 'isatty', return_value=True), \
             patch.object(Path, 'read_text', read):
            with self.assertRaisesRegex(ValueError, 'Remote shell ancestry'): setup.require_console()

    def test_console_guard_accepts_local_chain_and_refuses_no_tty(self):
        source = importlib.util.spec_from_file_location('console_fixture', Path(__file__).with_name('device_setup.py'))
        setup = importlib.util.module_from_spec(source); source.loader.exec_module(setup)
        def read(path):
            return {'/proc/42/comm': 'python3', '/proc/42/status': 'PPid:\t1\n',
                    '/proc/1/comm': 'systemd', '/proc/1/status': 'PPid:\t0\n'}[str(path)]
        with patch.object(setup.os, 'geteuid', return_value=0), patch.object(setup.os, 'getpid', return_value=42), \
             patch.dict(os.environ, {}, clear=True), patch.object(Path, 'read_text', read), \
             patch.object(setup.sys.stdin, 'isatty', return_value=True):
            setup.require_console()
            with patch.object(setup.sys.stdin, 'isatty', return_value=False):
                with self.assertRaisesRegex(ValueError, 'interactive local'): setup.require_console()

    def test_plan_emits_no_changes_and_never_applies(self):
        argv = ['onboard', '--plan', '--role', 'client', '--bootstrap', '/fixture', '--bootstrap-sha256', 'a'*64]
        with patch.object(sys, 'argv', argv), patch.object(onboard, 'prompt'), \
             patch.object(onboard, 'inspect', return_value=({}, {}, None)), patch.object(onboard, 'apply') as apply:
            output = io.StringIO()
            with contextlib.redirect_stdout(output): self.assertEqual(onboard.main(), 0)
            self.assertFalse(json.loads(output.getvalue())['changes_applied'])
            apply.assert_not_called()


if __name__ == '__main__': unittest.main()
