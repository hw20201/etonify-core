#!/usr/bin/env python3
"""Run the same IPv4 fragment assertion against the previous API/pin in isolation."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    go = os.environ.get("GO_BIN") or shutil.which("go")
    if not go:
        raise SystemExit("Go not found; set GO_BIN")
    with tempfile.TemporaryDirectory(prefix="etonify-nat-baseline-") as temp:
        target = Path(temp)
        (target / "go.mod").write_text(
            "module etonify-nat-baseline\n\ngo 1.27.1\n\nrequire (\n"
            "github.com/sagernet/sing-tun v0.9.7-0.20261002083955-3f8acd9da65b\n"
            "github.com/sagernet/sing v0.9.7-0.20260929150544-6f21f2425a95\n"
            "github.com/stretchr/testify v1.11.1\n)\n", encoding="utf-8")
        shutil.copyfile(root / "go.sum", target / "go.sum")
        fixture = (root / "common/forwardnat/fixtures_test.go").read_text(encoding="utf-8")
        fixture = fixture.replace("options tun.UDPNatOptions", "options time.Duration")
        fixture = fixture.replace("tun.SelectorRange", "baselineSelectorRange")
        fixture += "\ntype baselineSelectorRange struct { Start, Count uint16 }\n"
        (target / "fixtures_test.go").write_text(fixture, encoding="utf-8")
        fragments = (root / "common/forwardnat/fragment_test.go").read_text(encoding="utf-8")
        fragments = fragments.replace('tun "github.com/sagernet/sing-tun"\n', "")
        fragments = fragments.replace("tun.UDPNatOptions{}", "0")
        fragments += '\nvar client = netip.MustParseAddrPort("10.0.0.2:12345")\nvar server = netip.MustParseAddrPort("198.51.100.1:443")\n'
        (target / "fragment_test.go").write_text(fragments, encoding="utf-8")
        result = subprocess.run([go, "test", "-mod=mod", "-count=1", "-run", "^TestForwardNATIPv4FragmentReturn$", "."],
                                cwd=target, capture_output=True, text=True)
        output = result.stdout + result.stderr
        print(output, end="")
        # Compilation errors and infrastructure failures do not prove sensitivity.
        expected = "FAIL: TestForwardNATIPv4FragmentReturn" in output and "Should be empty" in output
        if result.returncode and expected:
            print("Baseline sensitivity confirmed: old sing-tun does not consume/rewrite the fragmented response.")
            return 0
        print("Baseline probe did not fail on the expected packet assertion.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
