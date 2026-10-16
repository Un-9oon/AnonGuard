#!/usr/bin/env python3
"""Release verifier boundary tests; the stub tests orchestration, not signatures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify_release", Path(__file__).with_name("verify_release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_debian_version_cannot_be_relabelled_under_another_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            args = list(self.fixture(Path(temp)))
            older = args[0].with_name('anonguard_0.1.0_amd64.deb')
            args[0].rename(older)
            args[0] = older
            with self.assertRaisesRegex(ValueError, 'version must match'):
                release.verify(*args)
            self.assertFalse(args[4].exists())

    def fixture(self, root, reject=False):
        asset = root / "anonguard_0.2.0_amd64.deb"
        asset.write_bytes(b"package fixture")
        manifest = root / "manifest"
        manifest.write_text(hashlib.sha256(asset.read_bytes()).hexdigest() + "  " + asset.name + "\n")
        bundle = root / "bundle"
        bundle.write_text("fixture")
        cosign = root / "cosign"
        cosign.write_text("#!/usr/bin/python3\nimport sys\n"
                          "expected = ['verify-blob', sys.argv[2], '--bundle', sys.argv[4], "
                          "'--certificate-identity', 'https://github.com/Un-9oon/AnonGuard/.github/workflows/release.yml@refs/tags/v0.2.0', "
                          "'--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com']\n"
                          "sys.exit(1 if sys.argv[1:] != expected else " + ("1" if reject else "0") + ")\n")
        cosign.chmod(0o700)
        return asset, manifest, bundle, "v0.2.0", root / "verified", cosign

    def test_valid_signature_command_and_private_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp))
            result = release.verify(*args)
            self.assertTrue(result["artifact_verified"])
            self.assertFalse(result["deployment_accepted"])
            self.assertEqual(args[4].stat().st_mode & 0o777, 0o700)
            staged = Path(result["verified_artifact"])
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            args[0].write_bytes(b"later tamper")
            self.assertEqual(staged.read_bytes(), b"package fixture")

    def test_verifier_rejection_cleans_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp), reject=True)
            with self.assertRaises(subprocess.CalledProcessError):
                release.verify(*args)
            self.assertFalse(args[4].exists())

    def test_timeout_cleans_staging_without_disabling_identity_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp))
            with patch.object(release.subprocess, "run", side_effect=subprocess.TimeoutExpired("cosign", 60)) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    release.verify(*args)
            command = run.call_args.args[0]
            self.assertNotIn("--insecure-ignore-tlog", command)
            self.assertNotIn("--certificate-identity-regexp", command)
            self.assertNotIn("--certificate-oidc-issuer-regexp", command)
            self.assertFalse(args[4].exists())

    def test_modified_or_missing_asset_is_rejected(self):
        for mutation in ("tamper", "missing", "invalid"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                args = self.fixture(Path(temp))
                if mutation == "tamper":
                    args[0].write_bytes(b"tampered")
                elif mutation == "missing":
                    args[1].write_text("0" * 64 + "  other.deb\n")
                else:
                    args[1].write_bytes(b"\xff")
                with self.assertRaises((ValueError, UnicodeError)):
                    release.verify(*args)
                self.assertFalse(args[4].exists())

    def test_no_existing_directory_is_overwritten_or_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp))
            args[4].mkdir()
            sentinel = args[4] / "keep"
            sentinel.write_text("keep")
            with self.assertRaises(FileExistsError):
                release.verify(*args)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_symlinks_and_nonregular_inputs_are_rejected(self):
        for kind in ("symlink", "fifo", "oversized"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                args = self.fixture(Path(temp))
                args[2].unlink()
                if kind == "symlink":
                    args[2].symlink_to(args[0])
                elif kind == "fifo":
                    os.mkfifo(args[2])
                else:
                    with args[2].open("wb") as stream:
                        stream.truncate(1024 * 1024 + 1)
                with self.assertRaises((OSError, ValueError)):
                    release.verify(*args)
                self.assertFalse(args[4].exists())

    def test_tag_and_executable_must_be_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            args = list(self.fixture(Path(temp)))
            for tag in ("main", "v0.2.0/evil", "v0.2.0\n", "--insecure", ".*"):
                args[3] = tag
                with self.assertRaises(ValueError):
                    release.verify(*args)
                self.assertFalse(args[4].exists())
            args[3] = "v0.2.0"
            args[5] = Path("cosign")
            with self.assertRaises(ValueError):
                release.verify(*args)

    def policy(self, args):
        return {'version': 1, 'minimum_tag': 'v0.2.0', 'revoked_tags': [],
                'approved_releases': {'v0.2.0': {
                    args[0].name: hashlib.sha256(args[0].read_bytes()).hexdigest()}}}

    def test_signature_alone_is_not_release_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            result = release.verify(*self.fixture(Path(temp)))
            self.assertFalse(result['release_admitted'])
            self.assertFalse(result['release_policy_accepted'])

    def test_exact_operator_policy_admits_only_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp))
            policy = Path(temp) / 'policy.json'
            policy.write_text(json.dumps(self.policy(args)))
            policy.chmod(0o600)
            result = release.verify(*args, policy=policy)
            self.assertTrue(result['release_admitted'])
            self.assertFalse(result['deployment_accepted'])
            staged = args[4] / 'release-policy.json'
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            policy.write_text('{}')
            self.assertEqual(json.loads(staged.read_text())['minimum_tag'], 'v0.2.0')

    def test_old_revoked_unapproved_and_changed_artifacts_are_refused(self):
        for mutation in ('minimum', 'revoked', 'tag', 'digest', 'asset'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                args = self.fixture(Path(temp))
                policy = self.policy(args)
                if mutation == 'minimum': policy['minimum_tag'] = 'v0.3.0'
                elif mutation == 'revoked': policy['revoked_tags'] = ['v0.2.0']
                elif mutation == 'tag': policy['approved_releases'] = {'v0.3.0': policy['approved_releases']['v0.2.0']}
                elif mutation == 'digest': policy['approved_releases']['v0.2.0'][args[0].name] = '0' * 64
                else: policy['approved_releases']['v0.2.0'] = {'anonguard_0.2.0_arm64.deb': 'a' * 64}
                path = Path(temp) / 'policy.json'; path.write_text(json.dumps(policy)); path.chmod(0o600)
                with self.assertRaises(ValueError): release.verify(*args, policy=path)
                self.assertFalse(args[4].exists())

    def test_policy_does_not_bypass_publisher_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp), reject=True)
            policy = Path(temp) / 'policy.json'; policy.write_text(json.dumps(self.policy(args)))
            policy.chmod(0o600)
            with self.assertRaises(subprocess.CalledProcessError):
                release.verify(*args, policy=policy)
            self.assertFalse(args[4].exists())

    def test_policy_file_types_permissions_bounds_and_duplicate_fields(self):
        for kind in ('symlink', 'fifo', 'oversize', 'writable', 'duplicate'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                args = self.fixture(Path(temp)); path = Path(temp) / 'policy.json'
                if kind == 'symlink': path.symlink_to(args[1])
                elif kind == 'fifo': os.mkfifo(path)
                elif kind == 'oversize': path.write_bytes(b' ' * 65537)
                elif kind == 'duplicate': path.write_text('{"version":1,"version":1}')
                else: path.write_text(json.dumps(self.policy(args))); path.chmod(0o666)
                with self.assertRaises((OSError, ValueError)): release.verify(*args, policy=path)
                self.assertFalse(args[4].exists())

    def test_policy_schema_and_numeric_version_ordering(self):
        name = 'anonguard_0.2.0_amd64.deb'; digest = 'a' * 64
        base = {'version': 1, 'minimum_tag': 'v0.2.0', 'revoked_tags': [],
                'approved_releases': {'v0.2.0': {name: digest}}}
        for bad in (None, {}, dict(base, version=True), dict(base, extra=True),
                    dict(base, minimum_tag='v0.02.0'), dict(base, minimum_tag='v0.2.0-rc1'),
                    dict(base, revoked_tags=['v0.1.0'] * 2), dict(base, approved_releases={})):
            with self.subTest(policy=bad), self.assertRaises(ValueError):
                release.admit(bad, 'v0.2.0', name, digest)
        numeric = dict(base, minimum_tag='v0.9.0', approved_releases={'v0.10.0': {name: digest}})
        release.admit(numeric, 'v0.10.0', name, digest)
        with self.assertRaises(ValueError): release.admit(numeric, 'v0.8.0', name, digest)

    def test_manifest_rejects_ambiguous_names_and_duplicates(self):
        digest = "a" * 64
        for value in ("", digest + "  ../bad\n", digest + "  /bad\n",
                      digest + "  .\n", digest + "  ..\n", digest + "  name with space\n",
                      digest + "  ok\n" + digest + "  ok\n", (digest + "  ok\n") * 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.checksums(value.encode())
        self.assertEqual(release.checksums((digest + " *ok.deb\n").encode()), {"ok.deb": digest})


if __name__ == "__main__":
    unittest.main()
