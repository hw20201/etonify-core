import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify_forward_nat", Path(__file__).with_name("verify_forward_nat.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ForwardNATRunnerTest(unittest.TestCase):
    def test_refuses_wrong_dependency_without_running_tests(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, json.dumps({"Version": "old"}), "")
        self.assertEqual(1, module.verify("go", Path(__file__).parents[1], run=run))
        self.assertEqual(1, len(calls))

    def test_overlay_is_read_only_and_propagates_failure(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp)
            (cache / "go.mod").write_text("module github.com/sagernet/sing-tun\n")
            self.check_overlay(root, cache)

    def check_overlay(self, root, cache):
        def run(command, **kwargs):
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, json.dumps({"Version": module.EXPECTED_VERSION, "Dir": str(cache)}), "")
            self.assertIn("-race", command)
            path = next(arg.split("=", 1)[1] for arg in command if arg.startswith("-overlay="))
            overlay = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(1, len(overlay["Replace"]))
            source = next(iter(overlay["Replace"].values()))
            self.assertTrue(Path(source).is_file())
            self.assertEqual("github.com/sagernet/sing-tun", command[-1])
            self.assertNotEqual(cache, Path(next(iter(overlay["Replace"]))).parent)
            modfile = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("-modfile=")))
            self.assertIn("replace github.com/sagernet/sing-tun", modfile.read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(command, 7)
        self.assertEqual(7, module.verify("go", root, race=True, run=run))
        self.assertEqual(["go.mod"], [p.name for p in cache.iterdir()])


if __name__ == "__main__":
    unittest.main()
