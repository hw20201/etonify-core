#!/usr/bin/env python3
"""Exercise private sing-tun fragment regressions without modifying the module cache."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from sing_tun_pin import dependency_metadata

EXPECTED_VERSION = "v0.9.7-0.20261009022811-5c2edb183cc9"


def verify(go, root, race=False, run=subprocess.run, strict=False):
    root = Path(root).resolve()
    try:
        dependency_metadata(root, require_clean=strict)
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Refusing fragment overlay: {error}")
        return 1
    info = run([go, "list", "-m", "-json", "github.com/sagernet/sing-tun"],
               cwd=root, capture_output=True, text=True)
    if info.returncode:
        print(info.stderr, end="")
        return info.returncode
    module = json.loads(info.stdout)
    if (module.get("Version") != EXPECTED_VERSION
            or Path(module.get("Dir", "")).resolve() != (root / "third_party/sing-tun").resolve()):
        print("Refusing fragment overlay: unexpected sing-tun version or replacement")
        return 1
    module_dir = Path(module["Dir"])
    source = Path(root) / "release/testdata/singtun/fragment_overlay_test.go"
    if not source.is_file():
        raise FileNotFoundError(source)
    with tempfile.TemporaryDirectory(prefix="etonify-forward-nat-") as temp:
        # Go 1.27 disallows overlays beneath GOMODCACHE. Use an exact temporary
        # copy and a temporary modfile; neither the cache nor root pins change.
        copied_module = Path(temp) / "sing-tun"
        shutil.copytree(module_dir, copied_module, ignore=shutil.ignore_patterns(".git"))
        modfile = Path(temp) / "verify.mod"
        shutil.copyfile(root / "go.mod", modfile)
        shutil.copyfile(Path(root) / "go.sum", modfile.with_suffix(".sum"))
        edited = run([go, "mod", "edit", f"-modfile={modfile}",
                      f"-replace=github.com/sagernet/sing-tun@{EXPECTED_VERSION}={copied_module.as_posix()}"],
                     cwd=root)
        if edited.returncode:
            return edited.returncode
        overlay = Path(temp) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(copied_module / "etonify_forward_fragment_test.go"): str(source.resolve())
        }}), encoding="utf-8")
        command = [go, "test", "-count=1", f"-modfile={modfile}", f"-overlay={overlay}"]
        if race:
            command.append("-race")
        command.extend(["-run", "^TestEtonifyForwardFragment", "github.com/sagernet/sing-tun"])
        return run(command, cwd=root).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    go = os.environ.get("GO_BIN") or shutil.which("go")
    if not go:
        parser.error("Go executable not found; set GO_BIN")
    return verify(go, Path(__file__).resolve().parents[1], args.race, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
