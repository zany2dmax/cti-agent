"""update-fedora.sh against throwaway git repositories: it pulls the kit, then
hands over to the installer from the UPDATED kit, and says how to run like every
other command that changes something."""
import os
import pathlib
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

    def test_other_arguments_go_to_the_installer(self):
        self.publish("two", tag="v1.1")
        r = self.run_update("--for-real", "--something")
        self.assertIn("INSTALLER two args=--something", r.stdout)

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


if __name__ == "__main__":
    unittest.main()
