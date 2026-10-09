"""Reproducible package and policy admission contracts, without browser execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
builder = load('build_browser_extension')
browser = load('browser_session')

class ExtensionTests(unittest.TestCase):
    def test_reproducible_exclusive_source_only_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = [Path(temporary) / name for name in ('one.xpi', 'two.xpi')]
            self.assertEqual(builder.build(ROOT / 'browser/isolation', first),
                             builder.build(ROOT / 'browser/isolation', second))
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), list(builder.FILES))
                self.assertNotIn('test_isolation.js', archive.namelist())
            with self.assertRaises(FileExistsError):
                builder.build(ROOT / 'browser/isolation', first)
    def test_isolation_policy_blocks_default_socks_and_extra_extensions(self):
        document = browser.policy('127.0.0.1', 9050, True, isolated=True)
        self.assertEqual(document['policies']['Proxy']['SOCKSProxy'], '127.0.0.1:9')
        self.assertEqual(document['policies']['ExtensionSettings']['*']['installation_mode'], 'blocked')
        self.assertEqual(document['policies']['ExtensionSettings']['isolation@anonguard.local']['installation_mode'], 'force_installed')
        browser.validate_policy(document, '127.0.0.1', 9050, True, isolated=True)
        document['policies']['Proxy']['SOCKSProxy'] = '127.0.0.1:9050'
        with self.assertRaises(ValueError):
            browser.validate_policy(document, '127.0.0.1', 9050, True, isolated=True)
        with self.assertRaises(ValueError):
            browser.policy('10.77.0.1', 9050, isolated=True)

if __name__ == '__main__':
    unittest.main()
