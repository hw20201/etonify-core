import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from sing_tun_pin_test import PinFixture

spec = importlib.util.spec_from_file_location("verify_forward_nat", Path(__file__).with_name("verify_forward_nat.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ForwardNATRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="etonify-runner-test-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = PinFixture(self.temp.name)
        self.root = self.fixture.root
        target = self.root / "release/testdata/singtun"
        target.mkdir(parents=True)
        (target / "fragment_overlay_test.go").write_text("package tun\n", encoding="utf-8")
        (self.root / "go.sum").write_text("", encoding="utf-8")
        self.go = os.environ.get("GO_BIN") or shutil.which("go")

    def test_refuses_wrong_dependency_without_running_tests(self):
        self.fixture.write_mod(version="v0.9.7-0.20261002083955-3f8acd9da65b")
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return subprocess.run(command, **kwargs)
        self.assertEqual(1, module.verify(self.go, self.root, run=run))
        self.assertEqual([], calls)

    def test_overlay_is_read_only_and_propagates_failure(self):
        before_mod = (self.root / "go.mod").read_bytes()
        before_status = self.fixture.git("status", "--porcelain", cwd=self.fixture.child)
        def run(command, **kwargs):
            if command[1] != "test":
                return subprocess.run(command, **kwargs)
            self.assertIn("-race", command)
            path = next(arg.split("=", 1)[1] for arg in command if arg.startswith("-overlay="))
            overlay = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(1, len(overlay["Replace"]))
            source = next(iter(overlay["Replace"].values()))
            self.assertTrue(Path(source).is_file())
            self.assertEqual("github.com/sagernet/sing-tun", command[-1])
            copied = Path(next(iter(overlay["Replace"]))).parent
            self.assertNotEqual(self.fixture.child, copied)
            self.assertFalse((copied / ".git").exists())
            modfile = next(arg.split("=", 1)[1] for arg in command if arg.startswith("-modfile="))
            parsed = json.loads(subprocess.check_output([self.go, "mod", "edit", f"-modfile={modfile}", "-json"], text=True))
            replacements = [r for r in parsed["Replace"] if r["Old"]["Path"] == "github.com/sagernet/sing-tun"]
            self.assertEqual(1, len(replacements))
            self.assertEqual(module.EXPECTED_VERSION, replacements[0]["Old"]["Version"])
            self.assertEqual(copied.resolve(), Path(replacements[0]["New"]["Path"]).resolve())
            return subprocess.CompletedProcess(command, 7)
        self.assertEqual(7, module.verify(self.go, self.root, race=True, run=run))
        self.assertEqual(before_mod, (self.root / "go.mod").read_bytes())
        self.assertEqual(before_status, self.fixture.git("status", "--porcelain", cwd=self.fixture.child))

    def test_refuses_cached_upstream_instead_of_fork(self):
        self.fixture.write_mod(replacement=None)
        self.assertEqual(1, module.verify(self.go, self.root))

    def test_strict_refuses_dirty_fork(self):
        (self.fixture.child / "untracked.go").write_text("package tun\n")
        self.assertEqual(1, module.verify(self.go, self.root, strict=True))


if __name__ == "__main__":
    unittest.main()
