#!/usr/bin/env python3
"""`task ship` refuses a release tag whose own commit is not the release.

2.0-rc2 and 2.0-rc3 were each tagged on the commit before "Release X": the
CHANGELOG at the tag still said "## Unreleased", so the GitHub Release failed
after the push, and cheatsheet:check passed only because the stamp was sitting
uncommitted in the working tree. These tests run the Taskfile's own
changelog:check and cheatsheet:check scripts in a scratch repository.

    python3 -m unittest discover -s fleet-kit/tests
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]


def task_script(name):
    """The `- |` block of a Taskfile task, dedented."""
    lines = (REPO / "Taskfile.yml").read_text(encoding="utf-8").splitlines()
    start = lines.index(f"  {name}:")
    i = next(j for j in range(start + 1, len(lines)) if lines[j] == "      - |")
    body = []
    for line in lines[i + 1:]:
        if line and not line.startswith("        "):
            break
        body.append(line[8:])
    return "\n".join(body) + "\n"


CHANGELOG = "# Changelog\n\n## {head}\n\n### Fixed\n\n- a fix\n\n## 1.0 — 2026-01-01\n\n- first\n"
FIRST = "# Changelog\n\n## 1.0 \u2014 2026-01-01\n\n- first\n"
SHEET = "# Cheat sheet\n\n**This copy is for release {ver} (2026-01-01).** Compare it.\n"


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class ReleaseCheck(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "scripts").mkdir()
        shutil.copy(REPO / "scripts" / "release-notes.sh", self.dir / "scripts")
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        self.git("init", "-q")
        (self.dir / "CHANGELOG.md").write_text(FIRST, encoding="utf-8")
        (self.dir / "CHEATSHEET.md").write_text(SHEET.format(ver="1.0"), encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "Release 1.0")
        self.git("tag", "-a", "1.0", "-m", "Release 1.0")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.dir, env=self.env, check=True, capture_output=True)

    def write(self, head, ver):
        (self.dir / "CHANGELOG.md").write_text(CHANGELOG.format(head=head), encoding="utf-8")
        (self.dir / "CHEATSHEET.md").write_text(SHEET.format(ver=ver), encoding="utf-8")

    def commit(self, head, ver, msg):
        self.write(head, ver)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def check(self, name):
        r = subprocess.run(["bash", "-c", task_script(name)], cwd=self.dir, env=self.env,
                           capture_output=True, text=True, check=False)
        return r.returncode, r.stderr

    def test_a_release_commit_then_its_tag_passes(self):
        self.commit("Unreleased", "1.0", "a fix")
        self.commit("1.1 — 2026-02-01", "1.1", "Release 1.1")
        self.git("tag", "-a", "1.1", "-m", "Release 1.1")
        for name in ("changelog:check", "cheatsheet:check"):
            rc, err = self.check(name)
            self.assertEqual(rc, 0, f"{name}: {err}")

    def test_a_tag_before_the_release_commit_fails(self):
        # The rc3 case: tagged on the fix, the release commit made afterwards.
        self.commit("Unreleased", "1.0", "a fix")
        self.git("tag", "-a", "1.1", "-m", "Release 1.1")
        self.commit("1.1 — 2026-02-01", "1.1", "Release 1.1")
        rc, err = self.check("changelog:check")
        self.assertNotEqual(rc, 0)
        self.assertIn("has no section for 1.1", err)
        self.assertIn("git tag -d 1.1", err)
        rc, err = self.check("cheatsheet:check")
        self.assertNotEqual(rc, 0, "the tagged sheet still names 1.0")
        self.assertIn("at 1.1 does not name release 1.1", err)

    def test_an_uncommitted_stamp_does_not_pass(self):
        self.commit("Unreleased", "1.0", "a fix")
        self.git("tag", "-a", "1.1", "-m", "Release 1.1")
        self.write("1.1 — 2026-02-01", "1.1")  # stamped and renamed, never committed
        for name in ("changelog:check", "cheatsheet:check"):
            rc, _ = self.check(name)
            self.assertNotEqual(rc, 0, f"{name} read the working tree")

    def test_ship_runs_both(self):
        taskfile = (REPO / "Taskfile.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/quiet-step.sh release:check task release:check", taskfile)
        block = taskfile[taskfile.index("  release:check:"):taskfile.index("  changelog:check:")]
        self.assertIn("task: changelog:check", block)
        self.assertIn("task: cheatsheet:check", block)


if __name__ == "__main__":
    unittest.main()
