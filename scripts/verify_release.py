#!/usr/bin/python3 -I
"""Verify a tagged release into a new private staging directory; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPOSITORY = "https://github.com/Un-9oon/AnonGuard"
ISSUER = "https://token.actions.githubusercontent.com"
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")
ASSET = re.compile(r"anonguard(?:_[0-9][A-Za-z0-9.+~-]*_(?:amd64|arm64)\.deb|-(?:linux-amd64\.tar\.gz|macos-universal\.tar\.gz|windows-amd64\.zip))")


def copy_regular(source, destination, limit):
    """Copy bytes once without following a final symlink or opening a FIFO."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(source, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Release input must be a bounded regular file")
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as stream, destination.open("xb") as output:
            os.chmod(destination, 0o600)
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise ValueError("Release input exceeds size limit")
                output.write(chunk)
    finally:
        os.close(fd)


def checksums(data):
    result = {}
    lines = data.decode("ascii").splitlines()
    if not 1 <= len(lines) <= 64:
        raise ValueError("Manifest must contain 1..64 entries")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        if not match or not NAME.fullmatch(match[2]) or match[2] in (".", ".."):
            raise ValueError("Invalid manifest entry")
        digest, name = match.groups()
        if name in result:
            raise ValueError("Duplicate manifest asset")
        result[name] = digest
    return result


def verify(artifact, manifest, bundle, tag, staging, cosign):
    if sys.platform != "linux":
        raise ValueError("This staging verifier currently supports Linux only")
    if not TAG.fullmatch(tag) or not ASSET.fullmatch(artifact.name):
        raise ValueError("Expected a version tag and a supported release asset name")
    if not cosign.is_absolute() or not cosign.is_file() or not os.access(cosign, os.X_OK):
        raise ValueError("Provide an absolute path to a trusted Cosign executable")
    # Exclusive creation prevents overwriting prior artifacts or following a
    # pre-existing staging symlink. Keep the parent under operator control.
    staging.mkdir(mode=0o700)
    try:
        copy_regular(manifest, staging / "SHA256SUMS", 65536)
        copy_regular(bundle, staging / "SHA256SUMS.sigstore.json", 1024 * 1024)
        copy_regular(artifact, staging / artifact.name, 2 * 1024**3)
        identity = f"{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
        subprocess.run([
            str(cosign), "verify-blob", str(staging / "SHA256SUMS"),
            "--bundle", str(staging / "SHA256SUMS.sigstore.json"),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", ISSUER,
        ], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8"})
        entries = checksums((staging / "SHA256SUMS").read_bytes())
        with (staging / artifact.name).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if entries.get(artifact.name) != digest:
            raise ValueError("Asset is missing from the signed manifest or its digest differs")
        return {"artifact_verified": True, "deployment_accepted": False,
                "tag": tag, "publisher_identity": identity, "sha256": digest,
                "verified_artifact": str((staging / artifact.name).absolute())}
    except BaseException:
        shutil.rmtree(staging)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--staging", type=Path, required=True,
                        help="New directory in an operator-controlled parent")
    parser.add_argument("--cosign", type=Path, required=True,
                        help="Absolute path to independently trusted Cosign")
    args = parser.parse_args()
    try:
        result = verify(args.artifact, args.manifest, args.bundle, args.tag,
                        args.staging, args.cosign)
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        print("Release verification failed; no artifact is approved for installation", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
