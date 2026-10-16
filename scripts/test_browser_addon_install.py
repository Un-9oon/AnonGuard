"""Pinned addon installation contracts; fake signature members are not signatures."""
import fcntl
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('browser', Path(__file__).with_name('browser_session.py'))
browser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


def package(version='0.1.1', code='fixture'):
    source = Path(__file__).resolve().parents[1] / 'browser/isolation/manifest.json'
    manifest = json.loads(source.read_text()); manifest['version'] = version
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        archive.writestr('isolation.js', code)
        archive.writestr('background.js', 'fixture')
        archive.writestr('META-INF/mozilla.rsa', 'fixture, not a signature')
        archive.writestr('META-INF/mozilla.sf', 'fixture, not a signature')
    data = output.getvalue()
    return data, hashlib.sha256(data).hexdigest()


class AddonInstallTests(unittest.TestCase):
    def test_pinned_install_receipt_and_explicit_upgrade(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); data, digest = package()
            receipt = browser.publish_extension(root, data, digest, '0.1.1')
            self.assertFalse(receipt['signature_verified']); self.assertFalse(receipt['browser_accepted'])
            self.assertEqual((root/'isolation-signed.xpi').stat().st_mode & 0o777, 0o644)
            browser.check_extension_receipt((root/'isolation-signed.xpi').read_bytes(), receipt)
            new, newer = package('0.1.2')
            browser.publish_extension(root, new, newer, '0.1.2', previous=digest)
            self.assertEqual((root/'isolation-signed.xpi').read_bytes(), new)

    def test_wrong_digest_version_or_missing_approval_never_installs(self):
        for digest, version in [(None, '0.1.1'), ('0'*64, '0.1.1'), ('auto', '0.1.1')]:
            with tempfile.TemporaryDirectory() as temp:
                data, _ = package()
                with self.assertRaises(ValueError): browser.publish_extension(Path(temp), data, digest, version)
                self.assertFalse((Path(temp)/'isolation-signed.xpi').exists())
        with tempfile.TemporaryDirectory() as temp:
            data, digest = package()
            with self.assertRaises(ValueError): browser.publish_extension(Path(temp), data, digest, '0.1.2')

    def test_replacement_requires_previous_pin_and_refuses_downgrade(self):
        for version, previous in [('0.1.2', None), ('0.1.2', '0'*64), ('0.1.0', 'current'), ('0.1.1', 'current')]:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); old, digest = package()
                browser.publish_extension(root, old, digest, '0.1.1')
                new, new_digest = package(version, code='changed')
                with self.assertRaises(ValueError):
                    browser.publish_extension(root, new, new_digest, version,
                                              previous=digest if previous == 'current' else previous)
                self.assertEqual((root/'isolation-signed.xpi').read_bytes(), old)

    def test_modified_receipt_or_xpi_blocks_preflight(self):
        data, _ = package(); observed = browser.validate_extension(data)
        receipt = {'version': 1, 'addon_id': 'isolation@anonguard.local', 'addon_version': '0.1.1',
                   'sha256': observed['sha256'], 'signature_verified': False, 'browser_accepted': False}
        for altered in (dict(receipt, sha256='0'*64), dict(receipt, addon_version='0.1.2'),
                        dict(receipt, signature_verified=True), dict(receipt, browser_accepted=True), {}):
            with self.assertRaises(ValueError): browser.check_extension_receipt(data, altered)

    def test_interrupted_receipt_publication_blocks_launch_and_cleans_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); old, digest = package(); browser.publish_extension(root, old, digest, '0.1.1')
            new, new_digest = package('0.1.2'); original = browser.os.replace
            def interrupt(source, target):
                if Path(target).name.endswith('.json'): raise OSError('fixture publication failure')
                return original(source, target)
            with patch.object(browser.os, 'replace', side_effect=interrupt):
                with self.assertRaises(OSError): browser.publish_extension(root, new, new_digest, '0.1.2', previous=digest)
            with self.assertRaises(ValueError):
                browser.check_extension_receipt((root/'isolation-signed.xpi').read_bytes(),
                                                json.loads((root/'isolation-signed.json').read_text()))
            self.assertFalse(list(root.glob('.addon-*')))

    def test_overlapping_installer_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); data, digest = package()
            browser.publish_extension(root, data, digest, '0.1.1')
            with (root/'.install.lock').open('r+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    browser.publish_extension(root, data, digest, '0.1.1', previous=digest)

    def test_symlink_and_permissive_directory_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); real = root/'real'; real.mkdir(mode=0o700); link = root/'link'; link.symlink_to(real)
            data, digest = package()
            with self.assertRaises(ValueError): browser.publish_extension(link, data, digest, '0.1.1')
            real.chmod(0o777)
            with self.assertRaises(ValueError): browser.publish_extension(real, data, digest, '0.1.1')


if __name__ == '__main__':
    unittest.main()
