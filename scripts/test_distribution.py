"""Portable bundle contracts; never install packages or activate services."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('distribution', Path(__file__).with_name('build_distribution.py'))
distribution = importlib.util.module_from_spec(spec); spec.loader.exec_module(distribution)


class DistributionTests(unittest.TestCase):
    def test_adapter_help_and_unknown_options_do_not_start_networking(self):
        for option, status in [('--help', 0), ('--not-a-supported-option', 2)]:
            result = subprocess.run(['/usr/bin/python3', '-I', str(distribution.ROOT / 'scripts/native_adapter.py'), option],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, status, result.stderr)
            self.assertIn('usage:', result.stdout + result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.make_package()

    def make_package(self, arch='amd64'):
        staging = self.root / ('pkg-' + arch); (staging / 'DEBIAN').mkdir(parents=True)
        (staging / 'DEBIAN/control').write_text('Package: anonguard\nVersion: 0.2.0\nArchitecture: ' + arch +
            '\nMaintainer: Test <test@example.invalid>\nDescription: disposable package fixture\n')
        package = self.root / ('anonguard_0.2.0_' + arch + '.deb')
        subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(staging), str(package)],
                       check=True, capture_output=True)
        return package

    def test_archive_and_manifest_preserve_package_and_installer(self):
        output = self.root / 'delivery'; archive = distribution.build(self.package, output)
        subprocess.run(['sha256sum', '--check', '--strict', 'SHA256SUMS'], cwd=output,
                       check=True, capture_output=True)
        self.assertTrue((output / 'install.sh').stat().st_mode & 0o111)
        self.assertEqual((output / self.package.name).read_bytes(), self.package.read_bytes())
        info = json.loads((output / 'BUILD_INFO.json').read_text())
        self.assertFalse(info['operator_network_material_included'])
        self.assertFalse(info['signed_addon_included'])
        with tarfile.open(archive) as bundle:
            self.assertIn('delivery/QUICK_START.md', bundle.getnames())

    def test_tampered_bundle_refuses_before_dependency_install(self):
        output = self.root / 'delivery'; distribution.build(self.package, output)
        with (output / self.package.name).open('ab') as stream: stream.write(b'changed')
        result = subprocess.run(['bash', str(output / 'install.sh'), '--check'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Checking system dependencies', result.stdout)

    def test_wrong_architecture_refuses_before_dependency_install(self):
        host = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
        package = self.make_package('arm64' if host == 'amd64' else 'amd64')
        output = self.root / 'delivery'; distribution.build(package, output)
        result = subprocess.run(['bash', str(output / 'install.sh'), '--check'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('different CPU architecture', result.stderr)

    def test_existing_output_or_archive_not_overwritten(self):
        output = self.root / 'delivery'; distribution.build(self.package, output)
        with self.assertRaises(ValueError): distribution.build(self.package, output)
        other = self.root / 'other'; other.with_name('other.tar.gz').write_bytes(b'keep')
        with self.assertRaises(ValueError): distribution.build(self.package, other)
        self.assertFalse(other.exists())

    def test_mismatching_provenance_refuses(self):
        (self.root / 'lab-build-provenance.json').write_text(json.dumps(
            {'artifact': self.package.name, 'sha256': '0' * 64}))
        output = self.root / 'delivery'
        with self.assertRaises(ValueError): distribution.build(self.package, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
