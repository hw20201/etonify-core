"""Fail-closed CLI fixtures plus wiring checks for the nested dependency gate."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from sing_tun_pin_test import PinFixture

ROOT = Path(__file__).resolve().parents[1]


class ForkCITests(unittest.TestCase):
    def test_cli_stops_build_on_invalid_selection(self):
        for mutation in ("missing", "sha", "dirty", "no-replace", "cache", "valid"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                f = PinFixture(tmp)
                gate = f.root / "release/sing_tun_pin.py"
                shutil.copyfile(ROOT / "release/sing_tun_pin.py", gate)
                if mutation == "missing":
                    f.child.rename(f.child.with_name("absent"))
                elif mutation == "sha":
                    f.git("update-index", "--cacheinfo", f"160000,{'1'*40},third_party/sing-tun", cwd=f.root)
                elif mutation == "dirty":
                    (f.child / "flow.go").write_text("package tun\n// dirty\n")
                elif mutation == "no-replace":
                    f.write_mod(replacement=None)
                elif mutation == "cache":
                    f.write_mod(replacement="../module-cache/sing-tun")
                result = subprocess.run([sys.executable, "-B", str(gate), "--strict"], capture_output=True, text=True)
                # The workflow's next compilation step can run only after exit0.
                if mutation == "valid":
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(f.pin, json.loads(result.stdout))
                else:
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("sing-tun", result.stderr)

    def test_ci_runs_selective_strict_gate_before_build(self):
        workflow = (ROOT / ".github/workflows/etonify-libbox.yml").read_text()
        self.assertIn("- '.gitmodules'", workflow)
        self.assertIn("- 'third_party/sing-tun'", workflow)
        self.assertEqual(2, workflow.count("git submodule update --init -- third_party/sing-tun"))
        self.assertIn("go test -race -count=1 -run '^TestEtonify' .", workflow)
        self.assertIn("go test -count=1 -exec sudo ./...", workflow)
        baseline = (ROOT / "release/verify_etonify_baseline.sh").read_text()
        self.assertIn('release/sing_tun_pin.py --strict', baseline)
        self.assertLess(baseline.index('release/sing_tun_pin.py --strict'), baseline.index('grep -Fq'))


if __name__ == "__main__":
    unittest.main()
