#!/usr/bin/env python3
"""Bundle an existing Debian package with an ordinary-user installation entry point."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]

GUIDE = """# AnonGuard — start here

AnonGuard routes supported traffic through several authenticated relays to reduce
direct exposure of your address to destinations. This experimental lab build is
not certified for public anonymity, complete quantum protection or AI invisibility.

## Before you install

- Use a dedicated Ubuntu 24.04 LTS x86-64 test computer with administrator access.
  Other Debian-family systems must satisfy the package's actual dependencies;
  compatibility with every Linux distribution is not claimed.
- Obtain this bundle from a trusted source and independently authenticate it.
  SHA256SUMS detects corruption; a checksum shipped beside a file is not a signature.
- Internet is needed for OS dependencies. This is not a complete offline installer.
- Ask your network operator for the trusted network bootstrap/profile and its
  independently supplied checksum. Client mode also needs private bridge settings,
  supported root-installed Firefox ESR and the approved Mozilla-signed addon.
  These are NOT included: there is no provisioned public AnonGuard network here.

## Install

Extract the archive into a folder. Open a terminal IN that folder and run:

    ./install.sh --check
    ./install.sh

Use your ordinary desktop account, not a root shell. The first command only checks
bundle integrity and simulates dependency installation. The second asks permission,
uses sudo/apt to install dependencies, then opens the Client / Volunteer wizard.
Do not merely unpack the .deb: extraction alone does not install dependencies.

Choose Client for browsing or Volunteer to contribute a non-exit relay. The current
wizard asks for operator files/checksums; an operator must prepare these for a novice.
Do not guess keys, use example profiles or disable verification to skip a refusal.
On Ubuntu a maintained Firefox ESR may need separate administrator provisioning;
the normal Snap/stable Firefox is not automatically converted into supported ESR.

## After setup

Open AnonGuard Browser from the application menu. It uses the selected browser and
checks configuration again. A Volunteer installation does not configure browsing.
Missing operator material/addon/ESR blocks setup; installing the .deb alone does
not mean you can start anonymous browsing. Successful setup is not proof of anonymity.

Setup changes firewall and browser policy. First-run activation must be at the local
console. If it fails, stop and inspect there; do not remove firewall rules to force
internet access. Removing the package intentionally preserves security restrictions
and operator state; it is not an automatic restore-to-normal-networking command.

## What is included

The .deb contains optimized binaries, setup/transport/browser helpers, application
menu entries, service templates, dependency declarations and technical documentation.
BUILD_INFO.json identifies the packaged source and bundle revision. Private operator
keys, real bootstrap/bridge credentials and a signed browser addon are not bundled.
Full installation/boot/browser acceptance on a fresh target remains necessary.
"""


def digest(content):
    return hashlib.sha256(content).hexdigest()


def build(deb, output):
    deb = deb.resolve(strict=True)
    data = deb.read_bytes()
    output = output.absolute()
    archive = output.with_name(output.name + '.tar.gz')
    if output.exists() or output.is_symlink() or archive.exists() or archive.is_symlink():
        raise ValueError('Output directory and archive must be new; distributions are never overwritten')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='anonguard-bundle-', dir=output.parent) as temporary:
        staging = Path(temporary) / 'bundle'; staging.mkdir()
        snapshot = staging / 'input.deb'; snapshot.write_bytes(data)
        fields = [subprocess.check_output(['dpkg-deb', '-f', str(snapshot), field], text=True).strip()
                  for field in ('Package', 'Version', 'Architecture')]
        name, version, architecture = fields
        if name != 'anonguard' or not re.fullmatch(r'[A-Za-z0-9.+~_-]+', version) or architecture not in ('amd64', 'arm64'):
            raise ValueError('Unexpected package identity, version or architecture')
        filename = f'anonguard_{version}_{architecture}.deb'
        snapshot.rename(staging / filename)
        installer = staging / 'install.sh'
        shutil.copyfile(ROOT / 'scripts/install_distribution.sh', installer); installer.chmod(0o755)
        (staging / 'QUICK_START.md').write_text(GUIDE)
        provenance = None
        record = deb.parent / 'lab-build-provenance.json'
        if record.exists():
            candidate = json.loads(record.read_text())
            if candidate.get('sha256') != digest(data) or candidate.get('artifact') != deb.name:
                raise ValueError('Existing package provenance does not match the package bytes')
            provenance = candidate
        info = {'package': filename, 'package_sha256': digest(data), 'package_provenance': provenance,
                'bundle_source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'bundle_source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)),
                'distribution_status': 'unsigned laboratory bundle; no deployment acceptance',
                'offline_dependencies_included': False, 'signed_addon_included': False,
                'operator_network_material_included': False}
        (staging / 'BUILD_INFO.json').write_text(json.dumps(info, indent=2) + '\n')
        manifest = ''.join(f'{digest(path.read_bytes())}  {path.name}\n' for path in sorted(staging.iterdir()))
        (staging / 'SHA256SUMS').write_text(manifest)
        shutil.copytree(staging, output)
    with archive.open('xb') as stream:
        with tarfile.open(fileobj=stream, mode='w:gz') as bundle:
            bundle.add(output, arcname=output.name)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.deb, args.output))


if __name__ == '__main__':
    main()
