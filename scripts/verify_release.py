#!/usr/bin/python3 -I
"""Verify a tagged release into a new private staging directory; never install it."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import secrets
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


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate release policy field")
        value[key] = item
    return value


def stable_version(tag):
    if not isinstance(tag, str) or not re.fullmatch(r"v(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})", tag):
        raise ValueError("Admission policy supports canonical stable release tags only")
    return tuple(int(part) for part in tag[1:].split('.'))


def admit(policy, tag, artifact, digest):
    """Operator-controlled approval; this is not a publisher-signature substitute."""
    if (not isinstance(policy, dict) or set(policy) != {
            'version', 'minimum_tag', 'approved_releases', 'revoked_tags'}
            or type(policy['version']) is not int or policy['version'] != 1):
        raise ValueError("Unsupported release admission policy")
    minimum = stable_version(policy['minimum_tag'])
    approved, revoked = policy['approved_releases'], policy['revoked_tags']
    if (not isinstance(approved, dict) or not 1 <= len(approved) <= 64
            or not isinstance(revoked, list) or len(revoked) > 256):
        raise ValueError("Release policy exceeds bounds")
    for version, assets in approved.items():
        stable_version(version)
        if not isinstance(assets, dict) or not 1 <= len(assets) <= 8:
            raise ValueError("Invalid approved artifact set")
        for name, value in assets.items():
            if (not ASSET.fullmatch(name) or not isinstance(value, str)
                    or not re.fullmatch('[0-9a-f]{64}', value)):
                raise ValueError("Invalid approved artifact digest")
    for version in revoked:
        stable_version(version)
    if len(set(revoked)) != len(revoked):
        raise ValueError("Duplicate revoked release")
    if stable_version(tag) < minimum or tag in revoked:
        raise ValueError("Release is below the operator minimum or revoked")
    if approved.get(tag, {}).get(artifact) != digest:
        raise ValueError("Exact release artifact is not operator approved")


def record_admission(directory, tag, artifact, digest, initialize=False):
    """Serialize a durable highest-admitted floor; never infer installation success."""
    if not directory.is_absolute():
        raise ValueError("Admission state directory must be absolute")
    stable_version(tag)
    if not ASSET.fullmatch(artifact) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError("Invalid admission record")
    if initialize:
        # Explicit exclusive initialization: a missing/removed journal is never
        # silently treated as a fresh installation on ordinary verification.
        directory.mkdir(mode=0o700)
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    temporary = None
    try:
        info = os.fstat(root)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Admission directory must be private and owned by the operator")
        flags = os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW
        if initialize:
            flags |= os.O_CREAT | os.O_EXCL
        lock = os.open('lock', flags, 0o600, dir_fd=root)
        metadata = os.fstat(lock)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
            raise ValueError("Unsafe admission lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if initialize:
            os.fsync(lock)
        if initialize:
            current = {'version': 1, 'highest_tag': None, 'artifacts': {}}
        else:
            descriptor = os.open('state.json', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=root)
            try:
                metadata = os.fstat(descriptor)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                        or metadata.st_mode & 0o077 or metadata.st_size > 65536 or metadata.st_nlink != 1):
                    raise ValueError("Unsafe admission state")
                with os.fdopen(descriptor, 'rb', closefd=False) as source:
                    raw = source.read(65537)
                if len(raw) > 65536:
                    raise ValueError("Admission state exceeds bound")
                current = json.loads(raw, object_pairs_hook=unique_object)
            finally:
                os.close(descriptor)
            if (not isinstance(current, dict) or set(current) != {'version', 'highest_tag', 'artifacts'}
                    or type(current['version']) is not int or current['version'] != 1
                    or not isinstance(current['artifacts'], dict) or not 1 <= len(current['artifacts']) <= 8):
                raise ValueError("Invalid admission journal")
            stable_version(current['highest_tag'])
            for name, value in current['artifacts'].items():
                if not ASSET.fullmatch(name) or not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
                    raise ValueError("Invalid journal artifact")
        previous = current['highest_tag']
        if previous is not None and stable_version(tag) < stable_version(previous):
            raise ValueError("Release is below the durable admitted version")
        artifacts = dict(current['artifacts']) if tag == previous else {}
        if artifact in artifacts and artifacts[artifact] != digest:
            raise ValueError("Previously admitted release artifact changed")
        artifacts[artifact] = digest
        if len(artifacts) > 8:
            raise ValueError("Too many artifacts for an admitted release")
        updated = {'version': 1, 'highest_tag': tag, 'artifacts': artifacts}
        temporary = '.state-' + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=root)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(updated, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, 'state.json', src_dir_fd=root, dst_dir_fd=root)
        temporary = None
        os.fsync(root)
        if initialize:
            parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        return tag
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=root)
            except FileNotFoundError:
                pass
        if lock is not None:
            os.close(lock)
        os.close(root)


def verify(artifact, manifest, bundle, tag, staging, cosign, policy=None,
           admission_state=None, initialize_state=False):
    if (admission_state is not None and policy is None) or (initialize_state and admission_state is None):
        raise ValueError("Admission state requires an explicit operator policy and directory")
    if sys.platform != "linux":
        raise ValueError("This staging verifier currently supports Linux only")
    if not TAG.fullmatch(tag) or not ASSET.fullmatch(artifact.name):
        raise ValueError("Expected a version tag and a supported release asset name")
    if artifact.name.endswith('.deb'):
        version = artifact.name.removeprefix('anonguard_').rsplit('_', 1)[0]
        if version != tag.removeprefix('v'):
            raise ValueError("Debian artifact version must match the authenticated release tag")
    if not cosign.is_absolute() or not cosign.is_file() or not os.access(cosign, os.X_OK):
        raise ValueError("Provide an absolute path to a trusted Cosign executable")
    # Exclusive creation prevents overwriting prior artifacts or following a
    # pre-existing staging symlink. Keep the parent under operator control.
    staging.mkdir(mode=0o700)
    try:
        copy_regular(manifest, staging / "SHA256SUMS", 65536)
        copy_regular(bundle, staging / "SHA256SUMS.sigstore.json", 1024 * 1024)
        copy_regular(artifact, staging / artifact.name, 2 * 1024**3)
        if policy is not None:
            fd = os.open(policy, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_size > 65536
                        or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
                    raise ValueError("Release policy must be a bounded operator-controlled file")
                with os.fdopen(fd, 'rb', closefd=False) as source:
                    policy_bytes = source.read(65537)
                if len(policy_bytes) > 65536:
                    raise ValueError("Release policy exceeds bound")
            finally:
                os.close(fd)
            (staging / 'release-policy.json').write_bytes(policy_bytes)
            os.chmod(staging / 'release-policy.json', 0o600)
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
        if policy is not None:
            admit(json.loads(policy_bytes, object_pairs_hook=unique_object), tag, artifact.name, digest)
        if admission_state is not None:
            record_admission(admission_state, tag, artifact.name, digest, initialize_state)
        return {"artifact_verified": True, "deployment_accepted": False,
                "admission_recorded": admission_state is not None,
                "rollback_floor": tag if admission_state is not None else None,
                "release_policy_accepted": policy is not None,
                "release_admitted": policy is not None,
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest() if policy is not None else None,
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
    parser.add_argument("--policy", type=Path,
                        help="Trusted operator policy: minimum tag, approved artifact digests and revoked tags; without it, signature verification only")
    parser.add_argument("--admission-state", type=Path,
                        help="Existing private durable admission directory; missing state fails closed")
    parser.add_argument("--initialize-admission-state", action="store_true",
                        help="Explicit first admission only; directory must not already exist")
    args = parser.parse_args()
    try:
        result = verify(args.artifact, args.manifest, args.bundle, args.tag,
                        args.staging, args.cosign, args.policy, args.admission_state,
                        args.initialize_admission_state)
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        print("Release verification failed; no artifact is approved for installation", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
