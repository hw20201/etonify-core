#!/usr/bin/env python3
"""Archive committed core and the exact pinned sing-tun source reproducibly."""
import argparse
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

from sing_tun_pin import SUBMODULE, command, dependency_metadata


def create_source_archive(root: Path, output: Path) -> None:
    root, output = Path(root).resolve(), Path(output).resolve()
    pin = dependency_metadata(root, require_clean=True)
    command(root, "git", "diff", "--quiet", "HEAD", "--")
    if command(root, "git", "ls-tree", "HEAD", "--", SUBMODULE) != f"160000 commit {pin['commit']}\t{SUBMODULE}":
        raise RuntimeError("committed sing-tun gitlink does not match archive pin")
    committed = json.loads(command(root, "git", "show", "HEAD:release/SING_TUN_PIN.json"))
    if any(committed.get(key) != value for key, value in pin.items()):
        raise RuntimeError("committed sing-tun manifest does not match archive pin")
    sources = ((root, "HEAD", ""), (root / SUBMODULE, pin["commit"], SUBMODULE + "/"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".source-", suffix=".tmp", dir=output.parent, delete=False) as temporary:
        temp_path = Path(temporary.name)
    try:
        with temp_path.open("wb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target:
                for directory, commit, prefix in sources:
                    data = subprocess.check_output(["git", "archive", "--format=tar", commit], cwd=directory)
                    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                        for member in archive:
                            info = copy.copy(member)
                            info.name = prefix + member.name
                            info.pax_headers = {k:v for k,v in member.pax_headers.items() if k not in ("path", "linkpath")}
                            # Git objects only; never traverse local/uninitialized
                            # client submodules or follow filesystem symlinks.
                            target.addfile(info, archive.extractfile(member) if member.isfile() else None)
        temp_path.replace(output)
    finally:
        temp_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        create_source_archive(Path(__file__).resolve().parents[1], args.output)
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"source archive refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
