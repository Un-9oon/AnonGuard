#!/usr/bin/env python3
"""Release verifier boundary tests; the stub tests orchestration, not signatures."""
import hashlib
import importlib.util
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
