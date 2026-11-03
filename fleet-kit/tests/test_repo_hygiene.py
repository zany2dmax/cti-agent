#!/usr/bin/env python3
"""No compiled binary or large generated file may be tracked.

A `go build ./cmd/<name>` without -o drops a 10 MB binary in the repo root;
`.gitignore` (`/cti-*`) normally catches it, but `git add -f` or a differently
named output would not be caught. History is public, so a binary committed
once stays there. This test fails the ship before that can happen.

    python3 -m unittest discover -s fleet-kit/tests
"""
import pathlib
import subprocess
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
MAX_BYTES = 1_000_000
MAGIC = {
    b"\x7fELF": "Linux executable",
    b"\xcf\xfa\xed\xfe": "macOS executable",
    b"\xce\xfa\xed\xfe": "macOS executable",
    b"\xca\xfe\xba\xbe": "macOS universal executable",
    b"MZ": "Windows executable",
}


def tracked():
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


class RepoHygiene(unittest.TestCase):
    def test_no_tracked_binaries_or_large_files(self):
        files = tracked()
        if files is None:
            self.skipTest("not a git checkout")
        bad = []
        for rel in files:
            p = REPO / rel
            if not p.is_file():
                continue
            size = p.stat().st_size
            if size > MAX_BYTES:
                bad.append(f"{rel}: {size} bytes (limit {MAX_BYTES})")
                continue
            with open(p, "rb") as f:
                head = f.read(4)
            for magic, what in MAGIC.items():
                if head.startswith(magic) and not rel.endswith((".md", ".txt", ".py", ".go")):
                    bad.append(f"{rel}: looks like a {what}")
        self.assertEqual(bad, [], "tracked binaries or large files:\n  " + "\n  ".join(bad))


if __name__ == "__main__":
    unittest.main()
