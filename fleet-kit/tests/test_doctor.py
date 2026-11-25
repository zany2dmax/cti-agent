#!/usr/bin/env python3
"""cti-agent-doctor against a scratch box: each check's OK, WARN and FAIL.

    python3 -m unittest discover -s fleet-kit/tests
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import shutil
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
FLEET = REPO / "fleet-kit" / "fleet"
TOOL = REPO / "fleet-kit" / "bin" / "cti-agent-doctor"


class Doctor(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        r = self.dir
        for d in ("etc/cti-agent", "opt/cti-agent/bin", "opt/cti-agent/share", "var/lib/cti-agent/reports"):
            (r / d).mkdir(parents=True)
        shutil.copy(FLEET / "lanes.list", r / "opt/cti-agent/share/lanes.list")
        shutil.copy(FLEET / "settings.manifest", r / "opt/cti-agent/settings.manifest")
        shutil.copy(FLEET / "bin" / "fleet-config", r / "opt/cti-agent/bin/fleet-config")
        (r / "etc/cti-agent/version").write_text("tag=v9.9\ncommit=abc\n")
        (r / "etc/cti-agent/fleet.env").write_text("FLEET_LANES=checkin,digest\n")
        audit = r / "opt/cti-agent/bin/run-checkin"
        audit.write_text("#!/bin/bash\n[ \"$1\" = --audit ] && echo audit ok && exit 0\nexit 2\n")
        audit.chmod(0o755)
        os.environ["CTI_DOCTOR_ROOT"] = str(r)
        os.environ["CTI_KIT"] = str(r / "no-kit")
        self.addCleanup(os.environ.pop, "CTI_DOCTOR_ROOT", None)
        self.addCleanup(os.environ.pop, "CTI_KIT", None)
        loader = importlib.machinery.SourceFileLoader("doctor", str(TOOL))
        spec = importlib.util.spec_from_loader("doctor", loader)
        self.m = importlib.util.module_from_spec(spec)
        loader.exec_module(self.m)

    def run_it(self):
        out = io.StringIO()
        rc = self.m.main(["--json"], out=out)
        return rc, {c["check"]: (c["state"], c["detail"]) for c in json.loads(out.getvalue())}

    def report(self, rows):
        (self.dir / "var/lib/cti-agent/reports/credcheck.txt").write_text(
            "# run-credcheck\n" + "".join(f"{lane}\t{cmd}\t{st}\t{last}\n" for lane, cmd, st, last in rows))

    def test_every_check_reports(self):
        rc, c = self.run_it()
        self.assertEqual(set(c), {"version", "settings", "units", "timers", "credentials", "org pack", "beat files"})
        self.assertEqual(c["version"][0], "OK")
        self.assertIn("installed v9.9", c["version"][1])
        self.assertEqual(c["beat files"][0], "OK")
        self.assertEqual(c["org pack"][0], "OK")
        self.assertIn("none", c["org pack"][1])
        # Not on a box: systemd is not asked.
        self.assertEqual(c["units"][0], "WARN")
        # Settings are missing here, so fleet-config's result is a FAIL and so is the run.
        self.assertEqual(c["settings"][0], "FAIL")
        self.assertIn("problem", c["settings"][1])
        self.assertEqual(rc, 1)

    def test_the_credential_report(self):
        _, c = self.run_it()
        self.assertEqual(c["credentials"][0], "WARN")
        self.assertIn("has not run", c["credentials"][1])
        self.report([("checkin", "cti-mailer", "ok", "token OK"), ("checkin", "cti-jira", "ok", "OK")])
        self.assertEqual(self.run_it()[1]["credentials"], ("OK", "2 check(s) ok"))
        self.report([("checkin", "cti-mailer", "ok", "x"), ("vmscan", "cti-vmscan", "FAIL", "403")])
        state, detail = self.run_it()[1]["credentials"]
        self.assertEqual(state, "FAIL")
        self.assertIn("cti-vmscan (vmscan)", detail)
        self.report([("checkin", "cti-mailer", "ok", "x")])
        old = self.dir / "var/lib/cti-agent/reports/credcheck.txt"
        os.utime(old, (old.stat().st_atime, old.stat().st_mtime - 3 * 86400))
        state, detail = self.run_it()[1]["credentials"]
        self.assertEqual(state, "WARN")
        self.assertIn("old", detail)

    def kit(self):
        """A kit at CTI_KIT, with the org-pack tool and the core it checks against."""
        kit = self.dir / "kit"
        (kit / "fleet-kit" / "bin").mkdir(parents=True)
        shutil.copy(REPO / "fleet-kit" / "bin" / "org-pack", kit / "fleet-kit" / "bin" / "org-pack")
        for d in ("agents", "skills"):
            shutil.copytree(FLEET / d, kit / "fleet-kit" / "fleet" / d)
        self.m.KIT = kit
        return kit

    def test_a_forks_org_pack_is_found_and_checked(self):
        # A fork commits org/ in the kit; the installer uses it, so the doctor checks it.
        kit = self.kit()
        _, c = self.run_it()
        self.assertEqual(c["org pack"], ("OK", "none (the core prompts only)"))
        (kit / "org").mkdir()
        (kit / "org" / "orchestrator.md").write_text("A note.\n")
        _, c = self.run_it()
        # Checked as on the box: root-owned, which a test's files are not.
        self.assertEqual(c["org pack"][0], "FAIL")
        self.assertIn(str(kit / "org"), c["org pack"][1])

    def test_two_org_packs_are_a_fail(self):
        kit = self.kit()
        (kit / "org").mkdir()
        (self.dir / "etc/cti-agent/org").mkdir()
        _, c = self.run_it()
        self.assertEqual(c["org pack"][0], "FAIL")
        self.assertIn("two org packs", c["org pack"][1])

    def test_a_failing_audit_is_a_fail(self):
        (self.dir / "opt/cti-agent/bin/run-checkin").write_text("#!/bin/bash\necho 'CLAUDE.md is writable by ctiagent' >&2\nexit 1\n")
        state, detail = self.run_it()[1]["beat files"]
        self.assertEqual(state, "FAIL")
        self.assertIn("writable by ctiagent", detail)

    def test_no_version_file_is_a_fail(self):
        (self.dir / "etc/cti-agent/version").unlink()
        self.assertEqual(self.run_it()[1]["version"][0], "FAIL")

    def test_it_prints_no_setting_value(self):
        (self.dir / "etc/cti-agent/fleet.env").write_text("FLEET_LANES=checkin\nDIGEST_TO=secret-list@example.com\n")
        out = io.StringIO()
        self.m.main([], out=out)
        self.assertNotIn("secret-list@example.com", out.getvalue())
        self.assertIn("cti-agent-doctor: ", out.getvalue())


if __name__ == "__main__":
    unittest.main()
