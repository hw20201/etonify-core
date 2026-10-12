"""Source archives contain committed nested source, not empty gitlink folders."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from sing_tun_pin_test import PinFixture
import source_archive


class SourceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = PinFixture(self.tmp.name)
        (self.f.root / "LICENSE").write_text("fixture parent license\n")
        self.f.git("add", "LICENSE", cwd=self.f.root)
        self.f.git("commit", "-m", "license", cwd=self.f.root)
        self.output = Path(self.tmp.name) / "source.tar.gz"

    def test_archive_contains_pinned_child_and_license(self):
        plain = subprocess.check_output(["git", "archive", "HEAD"], cwd=self.f.root)
        with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
            self.assertNotIn("third_party/sing-tun/flow.go", archive.getnames())
        source_archive.create_source_archive(self.f.root, self.output)
        with tarfile.open(self.output) as archive:
            for name in ("LICENSE", "release/SING_TUN_PIN.json", "third_party/sing-tun/go.mod",
                         "third_party/sing-tun/flow.go", "third_party/sing-tun/LICENSE"):
                self.assertIn(name, archive.getnames())
            self.assertFalse(any(".git/" in name or name.endswith("/.git") for name in archive.getnames()))

    def test_archive_is_deterministic(self):
        source_archive.create_source_archive(self.f.root, self.output)
        second = self.output.with_name("different-name.tar.gz")
        source_archive.create_source_archive(self.f.root, second)
        self.assertEqual(self.output.read_bytes(), second.read_bytes())

    def test_archive_rejects_wrong_or_dirty_child_and_parent(self):
        (self.f.child / "flow.go").write_text("package tun\n// dirty\n")
        with self.assertRaises(RuntimeError):
            source_archive.create_source_archive(self.f.root, self.output)
        self.f.git("add", "flow.go", cwd=self.f.child)
        self.f.git("commit", "-m", "different child", cwd=self.f.child)
        with self.assertRaises(RuntimeError):
            source_archive.create_source_archive(self.f.root, self.output)
        # A clean but staged different source must not be archived as HEAD.
        self.f.pin["commit"] = self.f.git("rev-parse", "HEAD", cwd=self.f.child)
        (self.f.root / "release/SING_TUN_PIN.json").write_text(json.dumps(self.f.pin))
        self.f.git("add", "release/SING_TUN_PIN.json", "third_party/sing-tun", cwd=self.f.root)
        with self.assertRaises(RuntimeError):
            source_archive.create_source_archive(self.f.root, self.output)

    def test_extracted_archive_resolves_local_module(self):
        source_archive.create_source_archive(self.f.root, self.output)
        extracted = Path(self.tmp.name) / "extracted"
        extracted.mkdir()
        with tarfile.open(self.output) as archive:
            archive.extractall(extracted, filter="data")
        go = os.environ.get("GO_BIN") or shutil.which("go")
        module = json.loads(subprocess.check_output([go, "list", "-m", "-json", "github.com/sagernet/sing-tun"], cwd=extracted, text=True))
        self.assertEqual((extracted / "third_party/sing-tun").resolve(), Path(module["Dir"]).resolve())


if __name__ == "__main__":
    unittest.main()
