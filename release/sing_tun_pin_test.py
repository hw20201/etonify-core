"""Test selected Go source identity using real temporary Git/Go checkouts."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import sing_tun_pin

BASE = "5c2edb183cc92eb190d41c04dedfa5519ca3e78c"
VERSION = "v0.9.7-0.20261009022811-5c2edb183cc9"
REPOSITORY = "https://github.com/yamixdev/sing-tun.git"


class PinFixture:
    def __init__(self, directory):
        self.root = Path(directory) / "core"
        self.root.mkdir()
        self.child = self.root / "third_party/sing-tun"
        self.child.parent.mkdir()
        self.git("init", cwd=self.root)
        self.git("config", "user.name", "Fixture", cwd=self.root)
        self.git("config", "user.email", "fixture@example.invalid", cwd=self.root)
        self.git("config", "core.autocrlf", "false", cwd=self.root)
        source = Path(__file__).resolve().parents[1] / "third_party/sing-tun"
        self.git("clone", "--shared", "--no-checkout", str(source), str(self.child), cwd=self.root)
        self.git("config", "core.autocrlf", "false", cwd=self.child)
        self.git("checkout", "--detach", BASE, cwd=self.child)
        self.git("remote", "set-url", "origin", REPOSITORY, cwd=self.child)
        self.git("config", "user.name", "Fixture", cwd=self.child)
        self.git("config", "user.email", "fixture@example.invalid", cwd=self.child)
        self.child_commit = self.git("rev-parse", "HEAD", cwd=self.child)
        (self.root / ".gitmodules").write_text(
            f'[submodule "third_party/sing-tun"]\n\tpath = third_party/sing-tun\n\turl = {REPOSITORY}\n', encoding="utf-8")
        self.write_mod()
        (self.root / "release").mkdir()
        self.pin = {"repository": REPOSITORY, "commit": self.child_commit,
                    "upstream_commit": BASE, "module_version": VERSION}
        (self.root / "release/SING_TUN_PIN.json").write_text(json.dumps(self.pin), encoding="utf-8")
        self.git("add", ".gitmodules", "go.mod", "release/SING_TUN_PIN.json", cwd=self.root)
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.child_commit},third_party/sing-tun", cwd=self.root)
        self.git("commit", "-m", "fixture", cwd=self.root)

    @staticmethod
    def git(*args, cwd):
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()

    def write_mod(self, version=VERSION, replacement="./third_party/sing-tun", wildcard=False):
        text = f"module example.invalid/pin-fixture\n\ngo 1.26.0\n\nrequire github.com/sagernet/sing-tun {version}\n"
        if replacement:
            left_version = "" if wildcard else " " + VERSION
            text += f"replace github.com/sagernet/sing-tun{left_version} => {replacement}\n"
        (self.root / "go.mod").write_text(text, encoding="utf-8")


class SingTunPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="etonify-pin-test-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = PinFixture(self.temp.name)

    def test_exact_checkout_is_used(self):
        actual = sing_tun_pin.dependency_metadata(self.fixture.root, require_clean=True)
        self.assertEqual(self.fixture.pin, actual)
        go = os.environ.get("GO_BIN") or shutil.which("go")
        selected = json.loads(subprocess.check_output(
            [go, "list", "-m", "-json", "github.com/sagernet/sing-tun"], cwd=self.fixture.root, text=True))
        self.assertEqual(self.fixture.child.resolve(), Path(selected["Dir"]).resolve())

    def test_missing_submodule_fails(self):
        self.fixture.child.rename(self.fixture.child.with_name("not-the-submodule"))
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root)

    def test_wrong_url_fails(self):
        path = self.fixture.root / ".gitmodules"
        path.write_text(path.read_text().replace(REPOSITORY, "https://github.com/SagerNet/sing-tun.git"))
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root)

    def test_checkout_sha_mismatch_fails(self):
        self.fixture.git("commit", "--allow-empty", "-m", "unexpected checkout", cwd=self.fixture.child)
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root)

    def test_wrong_require_fails(self):
        self.fixture.write_mod(version="v0.9.7-0.20261002083955-3f8acd9da65b")
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root)

    def test_cached_upstream_or_other_replace_fails(self):
        for replacement, wildcard in [(None, False), ("../another-checkout", False), ("./third_party/sing-tun", True)]:
            with self.subTest(replacement=replacement, wildcard=wildcard):
                self.fixture.write_mod(replacement=replacement, wildcard=wildcard)
                with self.assertRaises(RuntimeError):
                    sing_tun_pin.dependency_metadata(self.fixture.root)

    def test_strict_rejects_dirty_checkout(self):
        path = self.fixture.child / "flow.go"
        path.write_text(path.read_text(encoding="utf-8") + "\n// modified fixture\n", encoding="utf-8")
        self.assertEqual(self.fixture.pin, sing_tun_pin.dependency_metadata(self.fixture.root))
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root, require_clean=True)

    def test_manifest_sha_must_match_gitlink(self):
        self.fixture.pin["commit"] = "0" * 40
        (self.fixture.root / "release/SING_TUN_PIN.json").write_text(json.dumps(self.fixture.pin))
        with self.assertRaises(RuntimeError):
            sing_tun_pin.dependency_metadata(self.fixture.root)


if __name__ == "__main__":
    unittest.main()
