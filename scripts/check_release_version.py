#!/usr/bin/env python3
"""Fail closed when a tag, Cargo version and Debian metadata disagree; no install."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib

VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?')


def check(cargo_toml, tag=None, packages=()):
    with cargo_toml.open("rb") as source:
        data = source.read(65537)
    if len(data) > 65536:
        raise ValueError('Cargo manifest exceeds bound')
    version = tomllib.loads(data.decode('utf-8'))['package']['version']
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Unsupported release version')
    if tag is not None and tag != 'v' + version:
        raise ValueError('Release tag must exactly match Cargo package version')
    for package in packages:
        result = subprocess.run(['dpkg-deb', '--field', str(package.resolve(strict=True)),
                                 'Package', 'Version', 'Architecture'],
                                check=True, text=True, capture_output=True, timeout=10)
        fields = dict(line.split(': ', 1) for line in result.stdout.splitlines())
        if fields.get('Package') != 'anonguard' or fields.get('Version') != version:
            raise ValueError('Debian package metadata differs from release version')
        expected = f'anonguard_{version}_{fields.get("Architecture")}.deb'
        if fields.get('Architecture') not in ('amd64', 'arm64') or package.name != expected:
            raise ValueError('Debian artifact name does not match package metadata')
    return {'version': version, 'tag': tag, 'packages_checked': len(packages),
            'deployment_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo-toml', type=Path, default=Path('Cargo.toml'))
    parser.add_argument('--tag')
    parser.add_argument('--deb', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.cargo_toml, args.tag, args.deb)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Release version refused: {error}\n')


if __name__ == '__main__':
    main()
