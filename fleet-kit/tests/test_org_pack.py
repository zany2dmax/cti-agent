#!/usr/bin/env python3
"""The org pack: one organization's notes, added to the core prompts.

fleet-kit/bin/org-pack finds, checks and composes a pack, and install-fedora.sh
uses it for the orchestrator's CLAUDE.md, the three agent prompts and the
skills (docs/org-pack.md). The pack steers the beat, so a bad one must stop
the install, and a pack must only ever add to the core text.

    python3 -m unittest discover -s fleet-kit/tests
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "fleet-kit" / "bin" / "org-pack"
CORE = REPO / "fleet-kit" / "fleet"
EXAMPLE = REPO / "examples" / "org-pack"
INSTALLER = REPO / "fleet-kit" / "install-fedora.sh"


def org_pack(*args):
    return subprocess.run(["bash", str(TOOL), *map(str, args)], capture_output=True, text=True, check=False)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.pack = self.dir / "org"
        shutil.copytree(EXAMPLE, self.pack)
        for p in [self.pack, *self.pack.rglob("*")]:
            os.chmod(p, 0o755 if p.is_dir() else 0o644)

    def check(self):
        return org_pack("check", self.pack, CORE)


class TheExamplePack(Base):
    def test_the_example_passes(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_example_holds_every_kind_of_file(self):
        names = {str(p.relative_to(EXAMPLE)) for p in EXAMPLE.rglob("*") if p.is_file()}
        self.assertIn("README.md", names)
        self.assertIn("recipe.md", names)
        self.assertIn("orchestrator.md", names)
        self.assertIn("expected-gaps.txt", names)
        for agent in sorted(d.name for d in (CORE / "agents").iterdir() if d.is_dir()):
            self.assertIn(f"agents/{agent}.md", names, "the example has no notes for a core agent")
        self.assertTrue(any(re.fullmatch(r"skills/[a-z0-9-]+/SKILL\.md", n) for n in names), "no example skill")

    def test_upstream_has_no_org_folder(self):
        # A fork's org/ never conflicts only because upstream has none.
        self.assertFalse((REPO / "org").exists(), "org/ is a fork's folder; upstream keeps examples/org-pack")


class Refusals(Base):
    def assert_refused(self, why):
        r = self.check()
        self.assertEqual(r.returncode, 1, f"accepted: {r.stdout}")
        self.assertIn(why, r.stderr)

    def test_an_unknown_file(self):
        (self.pack / "orchestrator.txt").write_text("x")
        self.assert_refused("orchestrator.txt: not part of an org pack")

    def test_a_malformed_declared_gap(self):
        # Refused before anything is installed: a skipped line would turn a
        # chosen gap into an accident, or the reverse, without a word.
        for bad in ("appscan | Staging | not_scanned\n",               # no reason
                    "AppScan | Staging | not_scanned | why\n",        # not a lane name
                    "appscan | Staging | not_scanned | why | until=next week\n"):
            with self.subTest(line=bad):
                (self.pack / "expected-gaps.txt").write_text("# ok\n" + bad)
                self.assert_refused("expected-gaps.txt: line 2 is not lane | subject | kind | reason")

    def test_a_misspelt_folder(self):
        (self.pack / "agent").mkdir()
        self.assert_refused("agent: not part of an org pack")

    def test_notes_for_an_agent_that_is_not_core(self):
        (self.pack / "agents" / "triage.md").write_text("x")
        self.assert_refused("agents/triage.md: there is no core agent called triage")

    def test_a_skill_that_reuses_a_core_name(self):
        (self.pack / "skills" / "checkin").mkdir()
        (self.pack / "skills" / "checkin" / "SKILL.md").write_text("x")
        self.assert_refused("/checkin is a core skill")

    def test_a_skill_with_no_skill_md(self):
        (self.pack / "skills" / "empty").mkdir()
        self.assert_refused("skills/empty: no SKILL.md")

    def test_a_skill_with_a_bad_name(self):
        (self.pack / "skills" / "Bad_Name").mkdir()
        (self.pack / "skills" / "Bad_Name" / "SKILL.md").write_text("x")
        self.assert_refused("lower-case letters, digits and hyphens")

    def test_a_symlink(self):
        (self.pack / "agents" / "supplier.md").unlink()
        (self.pack / "agents" / "supplier.md").symlink_to("/etc/hosts")
        self.assert_refused("agents/supplier.md: a symlink")

    def test_a_group_writable_file(self):
        os.chmod(self.pack / "orchestrator.md", 0o664)
        self.assert_refused("orchestrator.md: writable by group or others")

    def test_a_world_writable_folder(self):
        os.chmod(self.pack / "skills", 0o757)
        self.assert_refused("skills: writable by group or others")

    def test_a_file_too_large(self):
        (self.pack / "orchestrator.md").write_text("x" * 65537)
        self.assert_refused("larger than 65536 bytes")

    def test_not_root_owned_where_the_installer_runs(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        r = org_pack("check", self.pack, CORE, "--root-owned")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not owned by root", r.stderr)


class Compose(unittest.TestCase):
    core = CORE / "agents" / "supplier" / "CLAUDE.md"

    def test_no_notes_is_the_core_file_unchanged(self):
        for args in ([self.core], [self.core, ""], [self.core, "/nonexistent/supplier.md"]):
            r = org_pack("compose", *args)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, self.core.read_text(encoding="utf-8"))

    def test_notes_go_after_the_core_text_which_wins(self):
        notes = EXAMPLE / "agents" / "supplier.md"
        out = org_pack("compose", self.core, notes).stdout
        core = self.core.read_text(encoding="utf-8")
        self.assertTrue(out.startswith(core), "the core text must come first, whole")
        rest = out[len(core):]
        self.assertIn("## Organization notes", rest)
        self.assertIn("never override them: where the two disagree, the instructions above win", rest)
        self.assertTrue(rest.endswith(notes.read_text(encoding="utf-8")))


class Find(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.kit, self.conf = self.dir / "kit", self.dir / "etc"
        self.kit.mkdir()
        self.conf.mkdir()

    def find(self):
        return org_pack("find", self.kit, self.conf)

    def test_none(self):
        r = self.find()
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_a_forks_or_a_boxs(self):
        (self.kit / "org").mkdir()
        self.assertEqual(self.find().stdout.strip(), str(self.kit / "org"))
        (self.kit / "org").rmdir()
        (self.conf / "org").mkdir()
        self.assertEqual(self.find().stdout.strip(), str(self.conf / "org"))

    def test_both_is_refused(self):
        (self.kit / "org").mkdir()
        (self.conf / "org").mkdir()
        r = self.find()
        self.assertEqual(r.returncode, 1)
        self.assertIn("two org packs", r.stderr)

    def test_a_file_is_refused(self):
        (self.conf / "org").write_text("x")
        self.assertEqual(self.find().returncode, 1)


class TheInstaller(unittest.TestCase):
    def setUp(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.code = "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))

    def test_the_pack_is_checked_root_owned_before_anything_is_installed(self):
        check = self.code.index('org-pack" check "$ORG_PACK" "$SRC/fleet" --root-owned || bail 1')
        self.assertLess(check, self.code.index('bold "Service account'))
        self.assertLess(self.code.index('org-pack" find "$SRC/.." "$CONF_DIR")" || bail 1'), check)

    def test_every_prompt_is_installed_composed(self):
        self.assertIn('org_compose "$SRC/fleet/CLAUDE.md" orchestrator.md "$ORG_TMP/CLAUDE.md"', self.code)
        self.assertIn('cmp -s "$AGENT_DIR/CLAUDE.md" "$ORG_TMP/CLAUDE.md"', self.code)
        self.assertIn('run install -m 0644 -o root -g root "$ORG_TMP/CLAUDE.md" "$AGENT_DIR/CLAUDE.md"', self.code)
        self.assertIn('org_compose "$SRC/fleet/agents/$a/CLAUDE.md" "agents/$a.md"', self.code)
        agents = re.search(r"for a in ([a-z -]+); do\n\s*org_compose", self.code)
        self.assertIsNotNone(agents)
        core_agents = sorted(d.name for d in (CORE / "agents").iterdir() if d.is_dir())
        self.assertEqual(sorted(agents.group(1).split()), core_agents)
        # Nothing installs a core prompt straight from the kit any more.
        self.assertNotRegex(self.code, r'run install [^\n]*"\$SRC/fleet/(CLAUDE\.md|agents/)')

    def test_the_core_skill_list_matches_the_kit(self):
        core_skills = sorted(d.name for d in (CORE / "skills").iterdir() if d.is_dir())
        loop = re.search(r"for s in ([a-z -]+); do\n\s*run install -d", self.code)
        self.assertEqual(sorted(loop.group(1).split()), core_skills)
        keep = re.search(r'case " ([a-z -]+)\$ORG_SKILLS"', self.code)
        self.assertEqual(sorted(keep.group(1).split()), core_skills)


if __name__ == "__main__":
    unittest.main()
