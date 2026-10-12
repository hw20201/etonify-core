#!/usr/bin/env python3
"""Verify the exact source selected for Etonify's sing-tun dependency."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MODULE = "github.com/sagernet/sing-tun"
VERSION = "v0.9.7-0.20261009022811-5c2edb183cc9"
UPSTREAM = "5c2edb183cc92eb190d41c04dedfa5519ca3e78c"
REPOSITORY = "https://github.com/yamixdev/sing-tun.git"
SUBMODULE = "third_party/sing-tun"


def command(root, *args):
    result = subprocess.run(args, cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def dependency_metadata(root: Path, *, require_clean: bool = False) -> dict[str, str]:
    root = Path(root).resolve()
    try:
        pin = json.loads((root / "release/SING_TUN_PIN.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"sing-tun pin manifest unavailable: {error}") from error
    if (not isinstance(pin, dict) or pin.get("repository") != REPOSITORY
            or pin.get("module_version") != VERSION or pin.get("upstream_commit") != UPSTREAM
            or not isinstance(pin.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", pin["commit"])):
        raise RuntimeError("unexpected sing-tun pin metadata")
    child = (root / SUBMODULE).resolve()
    if not child.is_dir() or not (child / "go.mod").is_file():
        raise RuntimeError("sing-tun submodule not initialized; run git submodule update --init -- third_party/sing-tun")
    if command(child, "git", "rev-parse", "--show-toplevel").replace("\\", "/") != child.as_posix():
        raise RuntimeError("sing-tun path is not its own Git checkout")
    link = command(root, "git", "ls-files", "--stage", "--", SUBMODULE)
    if link != f"160000 {pin['commit']} 0\t{SUBMODULE}":
        raise RuntimeError("sing-tun manifest does not match staged gitlink")
    if command(child, "git", "rev-parse", "HEAD") != pin["commit"]:
        raise RuntimeError("sing-tun checkout SHA does not match pinned gitlink")
    for key, expected in (("path", SUBMODULE), ("url", REPOSITORY)):
        value = command(root, "git", "config", "-f", ".gitmodules", "--get", f"submodule.{SUBMODULE}.{key}")
        if value != expected:
            raise RuntimeError(f"unexpected sing-tun .gitmodules {key}")
    if command(child, "git", "remote", "get-url", "origin") != REPOSITORY:
        raise RuntimeError("sing-tun checkout origin is not the requested fork")
    command(child, "git", "merge-base", "--is-ancestor", UPSTREAM, "HEAD")
    if require_clean and command(child, "git", "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("sing-tun checkout is dirty")
    go = os.environ.get("GO_BIN") or shutil.which("go")
    if not go:
        raise RuntimeError("Go executable not found; set GO_BIN")
    mod = json.loads(command(root, go, "mod", "edit", "-json"))
    requirements = [entry for entry in mod.get("Require", []) if entry["Path"] == MODULE]
    replacements = [entry for entry in mod.get("Replace", []) if entry["Old"]["Path"] == MODULE]
    if len(requirements) != 1 or requirements[0]["Version"] != VERSION:
        raise RuntimeError("unexpected sing-tun require version")
    if (len(replacements) != 1 or replacements[0]["Old"].get("Version") != VERSION
            or replacements[0]["New"]["Path"] != "./" + SUBMODULE
            or replacements[0]["New"].get("Version")):
        raise RuntimeError("sing-tun requires the exact-version local submodule replacement")
    selected = json.loads(command(root, go, "list", "-m", "-json", MODULE))
    replacement = selected.get("Replace", {})
    if (selected.get("Path") != MODULE or selected.get("Version") != VERSION
            or Path(selected.get("Dir", "")).resolve() != child
            or replacement.get("Path") != "./" + SUBMODULE
            or Path(replacement.get("Dir", "")).resolve() != child or replacement.get("Version")):
        raise RuntimeError("Go selected a different sing-tun source than the pinned submodule")
    return {key: pin[key] for key in ("repository", "commit", "upstream_commit", "module_version")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="also reject dirty fork code")
    args = parser.parse_args()
    try:
        metadata = dependency_metadata(Path(__file__).resolve().parents[1], require_clean=args.strict)
    except (RuntimeError, OSError, ValueError) as error:
        print(f"sing-tun verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
