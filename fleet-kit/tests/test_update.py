"""update-fedora.sh against throwaway git repositories: it pulls the kit, then
hands over to the installer from the UPDATED kit, and says how to run like every
other command that changes something."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def git(cwd, *args):
    return subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.email=t@example.com", "-c", "user.name=t",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        check=True, capture_output=True, text=True).stdout


def write_installer(kit, marker):
    p = pathlib.Path(kit) / "fleet-kit" / "install-fedora.sh"
    p.write_text(f'#!/usr/bin/env bash\necho "INSTALLER {marker} args=$*"\n', encoding="utf-8")
    p.chmod(0o755)


class UpdateFedora(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.origin = self.tmp / "origin.git"
        subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(self.origin)], check=True)
        self.kit = self.tmp / "kit"
        (self.kit / "fleet-kit" / "fleet" / "share").mkdir(parents=True)
        shutil.copy(ROOT / "fleet-kit" / "update-fedora.sh", self.kit / "fleet-kit" / "update-fedora.sh")
        shutil.copy(ROOT / "fleet-kit" / "fleet" / "share" / "fleet-mode.sh",
                    self.kit / "fleet-kit" / "fleet" / "share" / "fleet-mode.sh")
        write_installer(self.kit, "one")
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.kit)], check=True)
        git(self.kit, "add", "-A")
        git(self.kit, "commit", "-q", "-m", "one")
        git(self.kit, "tag", "v1.0")
        git(self.kit, "remote", "add", "origin", str(self.origin))
        git(self.kit, "push", "-q", "-u", "origin", "main", "--tags")

    def publish(self, marker, tag=None, edit_updater=False):
        """Another checkout pushes a new release to origin."""
        other = self.tmp / f"other-{marker}"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(other)], check=True)
        write_installer(other, marker)
        if edit_updater:  # the updater itself changes in the update
            p = other / "fleet-kit" / "update-fedora.sh"
            p.write_text(p.read_text(encoding="utf-8") + "\n# changed in the update\n", encoding="utf-8")
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", marker)
        if tag:
            git(other, "tag", tag)
        git(other, "push", "-q", "origin", "main", "--tags")

    def run_update(self, *args, uid="0"):
        return subprocess.run(
            ["bash", str(self.kit / "fleet-kit" / "update-fedora.sh"), *args],
            check=False, capture_output=True, text=True,
            env={"PATH": os.environ["PATH"], "HOME": str(self.tmp), "FLEET_UPDATE_UID": uid})

    def test_it_must_be_told_how_to_run(self):
        r = self.run_update()
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("say how to run it", r.stderr)
        self.assertIn("cti-agent-update", r.stderr)
        r = self.run_update("--dry-run", "--for-real")
        self.assertEqual(r.returncode, 2)
        self.assertIn("contradict", r.stderr)

    def test_a_dry_run_shows_what_is_incoming_and_changes_nothing(self):
        self.publish("two", tag="v1.1")
        r = self.run_update("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("v1.1", r.stdout)
        self.assertIn("1 new commit", r.stdout)
        self.assertIn("two", r.stdout)
        self.assertNotIn("INSTALLER", r.stdout)
        # Nothing was merged.
        self.assertEqual(git(self.kit, "describe", "--tags", "--always").strip(), "v1.0")

    def test_for_real_pulls_the_kit_then_runs_the_UPDATED_installer(self):
        self.publish("two", tag="v1.1")
        r = self.run_update("--for-real")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("v1.0 -> v1.1", r.stdout)
        # The point of the script: the installer that ran is the new one.
        self.assertIn("INSTALLER two", r.stdout)
        self.assertNotIn("INSTALLER one", r.stdout)

    def test_an_unknown_argument_stops_it_before_the_pull(self):
        # The installer refuses every option it could be handed, so passing one
        # on only ever failed - after the kit had been pulled. Now it stops here.
        self.publish("two", tag="v1.1")
        for args in (("--for-real", "--something"), ("--something", "--for-real"), ("--dry-run", "x")):
            with self.subTest(args=args):
                r = self.run_update(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("unknown argument", r.stderr)
                self.assertNotIn("INSTALLER", r.stdout)
                self.assertEqual(git(self.kit, "describe", "--tags", "--always").strip(), "v1.0")

    def test_the_installer_is_run_with_for_real_and_nothing_else(self):
        self.publish("two", tag="v1.1")
        r = self.run_update("--for-real")
        self.assertIn("INSTALLER two args=--for-real\n", r.stdout)

    def test_help_says_how_and_changes_nothing(self):
        self.publish("two", tag="v1.1")
        r = self.run_update("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--dry-run|--for-real", r.stdout)
        self.assertEqual(git(self.kit, "describe", "--tags", "--always").strip(), "v1.0")

    def test_an_up_to_date_kit_still_reinstalls(self):
        r = self.run_update("--for-real")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0 new commit", r.stdout)
        self.assertIn("INSTALLER one", r.stdout)

    def test_a_commit_with_no_tag_yet_is_called_out(self):
        self.publish("two")  # pushed with no tag, the 1.5.2 mistake
        r = self.run_update("--for-real")
        self.assertIn("not an exact release tag", r.stdout)

    def test_it_survives_changing_itself_in_the_update(self):
        self.publish("two", tag="v1.1", edit_updater=True)
        r = self.run_update("--for-real")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("INSTALLER two", r.stdout)

    def test_local_changes_in_the_kit_stop_it(self):
        (self.kit / "fleet-kit" / "install-fedora.sh").write_text("# edited on the box\n", encoding="utf-8")
        r = self.run_update("--for-real")
        self.assertEqual(r.returncode, 1)
        self.assertIn("local changes", r.stderr)
        self.assertNotIn("INSTALLER", r.stdout)

    def rewrite_upstream(self, retag):
        """What scrub-history.sh then a force push does: the same history with
        new commit ids, and (if retag) the release tag moved onto the new one."""
        other = self.tmp / "rewriter"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(other)], check=True)
        git(other, "commit", "-q", "--amend", "-m", "one, rewritten")
        if retag:
            git(other, "tag", "-f", "v1.0")
            git(other, "push", "-q", "--force", "origin", "main", "--tags")
        else:
            git(other, "push", "-q", "--force", "origin", "main")

    def test_a_rewritten_tag_stops_it_out_loud_with_the_fix(self):
        # Seen for real: git fetch --tags --quiet refuses a moved tag without a
        # word, and set -e ended the update with no output at all.
        self.rewrite_upstream(retag=True)
        for mode in ("--dry-run", "--for-real"):
            r = self.run_update(mode)
            self.assertEqual(r.returncode, 1, mode)
            self.assertIn("nothing was pulled or installed", r.stderr)
            self.assertIn("would clobber existing tag", r.stderr)
            self.assertIn("fetch --force --tags origin", r.stderr)
            self.assertIn("reset --hard", r.stderr)
            self.assertIn("/opt/cti-agent/agent", r.stderr)
            self.assertNotIn("INSTALLER", r.stdout)
        # Printed, never run: the kit still has the old history.
        self.assertEqual(git(self.kit, "log", "-1", "--format=%s").strip(), "one")

    def test_a_rewritten_branch_is_refused_with_the_fix(self):
        self.rewrite_upstream(retag=False)
        r = self.run_update("--for-real")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot be fast-forwarded", r.stderr)
        self.assertIn("reset --hard", r.stderr)
        self.assertNotIn("INSTALLER", r.stdout)

    def test_a_fetch_that_fails_says_so(self):
        git(self.kit, "remote", "set-url", "origin", str(self.tmp / "gone.git"))
        r = self.run_update("--dry-run")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not fetch", r.stderr)
        self.assertIn("git: ", r.stderr)
        self.assertNotIn("would clobber", r.stderr)

    def test_a_real_update_needs_root_but_looking_does_not(self):
        self.assertEqual(self.run_update("--for-real", uid="1000").returncode, 1)
        self.assertEqual(self.run_update("--dry-run", uid="1000").returncode, 0)

    def test_it_will_not_run_from_inside_the_tree_the_installer_pulls(self):
        # The guard is a path check; exercise it on the path alone.
        src = (ROOT / "fleet-kit" / "update-fedora.sh").read_text(encoding="utf-8")
        self.assertIn("/opt/cti-agent|/opt/cti-agent/*", src)

    def test_the_installer_leaves_the_update_command_on_the_box(self):
        inst = (ROOT / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/local/sbin/cti-agent-update", inst)
        self.assertIn('exec "$SRC/update-fedora.sh"', inst)
        # And uninstall takes it away again.
        self.assertIn("rm -f /usr/local/sbin/cti-agent-update", inst)


class UpdateDocsAndCompletion(unittest.TestCase):
    """cti-agent-update is not in the command manifest (the cti-agent wrapper
    does not run it), so nothing generated keeps its man page and completions
    in step with it. This does: the flags update-fedora.sh takes are exactly
    the ones the page and both completions offer."""

    SHARE = ROOT / "fleet-kit" / "fleet" / "share"

    def flags(self):
        src = (ROOT / "fleet-kit" / "update-fedora.sh").read_text(encoding="utf-8")
        return set(re.findall(r"^\s*(--[a-z-]+)\)\s", src, re.M))

    def test_the_updater_has_the_two_modes(self):
        self.assertEqual(self.flags(), {"--dry-run", "--for-real"})

    def test_the_man_page_documents_every_flag(self):
        page = (ROOT / "man" / "man1" / "cti-agent-update.1").read_text(encoding="utf-8").replace("\\-", "-")
        for f in self.flags() | {"--uninstall", "--purge"}:
            self.assertRegex(page, r"(?<![\w-])" + re.escape(f) + r"(?![\w-])", f)

    def test_both_completions_offer_exactly_the_updater_flags(self):
        for name in ("cti-agent-update.bash", "_cti-agent-update"):
            with self.subTest(file=name):
                text = (self.SHARE / name).read_text(encoding="utf-8")
                code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
                self.assertEqual(set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", code)), self.flags())

    def test_the_completions_are_valid_shell(self):
        for name, shell in (("cti-agent-update.bash", "bash"), ("_cti-agent-update", "zsh")):
            with self.subTest(file=name):
                if shutil.which(shell) is None:
                    self.skipTest(f"no {shell} here")
                r = subprocess.run([shell, "-n", str(self.SHARE / name)],
                                   check=False, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_bash_completion_offers_one_mode_and_then_nothing(self):
        if shutil.which("bash") is None:
            self.skipTest("no bash here")
        script = (f'source "{self.SHARE / "cti-agent-update.bash"}"\n'
                  't(){ COMP_WORDS=("$@"); COMP_CWORD=$(( $# - 1 )); COMP_TYPE=9; '
                  '_cti_agent_update 2>/dev/null; echo "${#COMPREPLY[@]} ${COMPREPLY[0]%% *}"; }\n'
                  't cti-agent-update ""; t cti-agent-update --f; t cti-agent-update --dry-run ""\n')
        r = subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True)
        self.assertEqual(r.stdout.split("\n")[:3], ["2 --dry-run", "1 --for-real", "0 "])

    def test_the_installer_installs_and_removes_them(self):
        inst = (ROOT / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        for name, dest in (("cti-agent-update.bash", "/usr/share/bash-completion/completions/cti-agent-update"),
                           ("_cti-agent-update", "/usr/share/zsh/site-functions/_cti-agent-update")):
            self.assertIn(f'"$SRC/fleet/share/{name}" {dest}', inst)
            self.assertGreaterEqual(inst.count(dest), 3, f"{dest}: installed, relabelled and removed")


if __name__ == "__main__":
    unittest.main()


class InstallerSaysHow(unittest.TestCase):
    """install-fedora.sh has no default: with no mode it prints usage, exits 2
    and touches nothing. Runs without root, because the refusal comes first."""
    SCRIPT = ROOT / "fleet-kit" / "install-fedora.sh"

    def run_installer(self, *args):
        return subprocess.run(["bash", str(self.SCRIPT), *args], check=False, capture_output=True,
                              text=True, env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})

    def test_no_mode_exits_2_with_usage_and_no_scare(self):
        for args in ((), ("--uninstall",), ("--purge",)):
            with self.subTest(args=args):
                r = self.run_installer(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("say how to run it", r.stderr)
                self.assertIn("--dry-run", r.stderr)
                self.assertIn("--for-real", r.stderr)
                self.assertNotIn("PARTIALLY", r.stderr)
                self.assertNotIn("run with sudo", r.stdout + r.stderr)

    def test_contradictory_modes_are_refused(self):
        r = self.run_installer("--dry-run", "--for-real")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("contradict", r.stderr)

    def test_help_needs_no_mode_and_names_for_real(self):
        r = self.run_installer("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--for-real", r.stdout)

    def test_uninstall_dry_run_removes_nothing(self):
        r = self.run_installer("--uninstall", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing was removed", r.stdout)

    def test_every_caller_in_the_tree_passes_a_mode(self):
        """Any line that runs the installer (not just names it) says --for-real
        or --dry-run, or is the updater's exec."""
        run = re.compile(r"(sudo\s+|exec\s+)\S*install-fedora\.sh(?P<rest>[^\n`]*)")
        for f in [ROOT / "RUNBOOK.md", ROOT / "fleet-kit" / "README.md", ROOT / "fleet-kit" / "update-fedora.sh",
                  ROOT / "fleet-kit" / "stop-fedora.sh", ROOT / "fleet-kit" / "install-fedora.sh"]:
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                m = run.search(line)
                if m and "--help" not in line:
                    with self.subTest(file=f.name, line=n):
                        self.assertRegex(m.group("rest"), r"--(for-real|dry-run)", line)
