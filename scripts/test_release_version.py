"""Release-version boundaries; builds metadata-only fixtures, never installs."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release_version', Path(__file__).with_name('check_release_version.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class Versions(unittest.TestCase):
    def test_exact_tag_and_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'Cargo.toml'
            manifest.write_text('[package]\nversion="0.2.0"\n')
            self.assertEqual(release.check(manifest, 'v0.2.0')['version'], '0.2.0')
            for tag in ('main', 'v0.1.0', 'v0.2.0-beta', 'v0.2.0\n', 'v0.2.0/evil'):
                with self.assertRaises(ValueError):
                    release.check(manifest, tag)
            manifest.write_text('[package]\nversion="0.2.0-beta.1"\n')
            release.check(manifest, 'v0.2.0-beta.1')

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'Debian metadata parser unavailable')
    def test_metadata_and_filename_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / 'Cargo.toml'
            manifest.write_text('[package]\nversion="0.2.0"\n')
            control = root / 'package' / 'DEBIAN'
            control.mkdir(parents=True)
            (control / 'control').write_text('Package: anonguard\nVersion: 0.2.0\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: Metadata fixture\n')
            package = root / 'anonguard_0.2.0_amd64.deb'
            subprocess.run(['dpkg-deb', '--build', str(control.parent), str(package)],
                           check=True, capture_output=True)
            release.check(manifest, 'v0.2.0', [package])
            renamed = root / 'anonguard_0.1.0_amd64.deb'
            package.rename(renamed)
            with self.assertRaises(ValueError):
                release.check(manifest, 'v0.2.0', [renamed])
            renamed.rename(package)
            manifest.write_text('[package]\nversion="0.3.0"\n')
            with self.assertRaises(ValueError):
                release.check(manifest, 'v0.3.0', [package])


if __name__ == '__main__':
    unittest.main()
