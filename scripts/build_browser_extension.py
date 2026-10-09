#!/usr/bin/python3 -I
"""Build reproducible unsigned isolation XPI for Mozilla signing; never installs it."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

FILES = ('manifest.json', 'isolation.js', 'background.js')

def build(source, output):
    manifest = json.loads((source / 'manifest.json').read_text())
    if manifest['browser_specific_settings']['gecko']['id'] != 'isolation@anonguard.local':
        raise ValueError('Unexpected extension identity')
    with output.open('xb') as stream:
        try:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
                for name in FILES:
                    item = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                    item.create_system = 3
                    item.external_attr = 0o100644 << 16
                    archive.writestr(item, (source / name).read_bytes())
        except BaseException:
            output.unlink()
            raise
    return hashlib.sha256(output.read_bytes()).hexdigest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'browser/isolation')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({'sha256': build(args.source, args.output), 'signed': False,
                      'browser_accepted': False}))
