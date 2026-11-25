#!/usr/bin/env python3
"""cti-agent-doctor against a scratch box: each check's OK, WARN and FAIL.

    python3 -m unittest discover -s fleet-kit/tests
"""
import datetime
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

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
        self.assertEqual(set(c), {"version", "settings", "units", "timers", "credentials", "lane health",
                                  "org pack", "beat files"})
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

    def test_a_refusal_reports_what_was_refused(self):
        # The audit's first line names the file; the lines after it say how to fix it.
        (self.dir / "opt/cti-agent/bin/run-checkin").write_text(
            "#!/bin/bash\necho 'run-checkin: REFUSING to start: /opt/x is writable' >&2\n"
            "echo '  reinstall with install-fedora.sh --for-real' >&2\nexit 1\n")
        state, detail = self.run_it()[1]["beat files"]
        self.assertEqual((state, detail), ("FAIL", "run-checkin: REFUSING to start: /opt/x is writable"))

    def test_as_root_the_audit_runs_as_the_service_account(self):
        # Root can write every file, so the audit run as root refuses them all.
        seen = []
        real_run = self.m.run

        def fake(cmd, **kw):
            seen.append(cmd)
            return real_run(cmd[cmd.index("--") + 1:] if cmd[0] == "runuser" else cmd, **kw)
        with mock.patch.object(self.m.os, "geteuid", return_value=0), \
             mock.patch.object(self.m.shutil, "which", return_value="/usr/sbin/runuser"), \
             mock.patch.object(self.m, "run", fake):
            state, _ = self.run_it()[1]["beat files"]
        self.assertEqual(state, "OK")
        audit = [c for c in seen if "--audit" in c]
        self.assertEqual(audit[0][:4], ["runuser", "-u", "ctiagent", "--"])
        with mock.patch.object(self.m.os, "geteuid", return_value=0), \
             mock.patch.object(self.m.shutil, "which", return_value=None):
            state, detail = self.run_it()[1]["beat files"]
        self.assertEqual(state, "WARN")
        self.assertIn("runuser", detail)

    def test_a_setting_to_move_out_of_core_is_a_warn(self):
        # Still read where it is, so not a FAIL; a real problem still is.
        for result, want in (("result: 0 problem(s); 2 to move out of core; 0 setting(s) can be removed", "WARN"),
                             ("result: 1 problem(s); 2 to move out of core; 0 setting(s) can be removed", "FAIL"),
                             ("result: 0 problem(s); 0 setting(s) can be removed (3 would remain)", "OK")):
            with self.subTest(result=result), mock.patch.object(
                    self.m, "run", lambda cmd, out=result + "\n", **kw: self.m.subprocess.CompletedProcess(cmd, 0, out, "")):
                self.assertEqual(self.m.check_settings()[0], want)

    def test_lane_health(self):
        share = self.dir / "opt/cti-agent/share"
        (share / "health.list").write_text("# lanes\nappscan\tappaudit\t26\tnot_scanned,held\n")
        # FLEET_LANES=checkin,digest here: the appscan lane is not in use.
        self.assertEqual(self.m.check_lane_health(self.m.settings()),
                         ("OK", "no lane this box runs has a health report yet"))
        (self.dir / "etc/cti-agent/fleet.env").write_text("FLEET_LANES=checkin,appscan\n")
        vals = self.m.settings()
        state, detail = self.m.check_lane_health(vals)
        self.assertEqual(state, "WARN")
        self.assertIn("appscan: no readable report (cti-agent-appaudit.service writes it)", detail)
        rep = self.dir / "var/lib/cti-agent/reports/health/appscan.json"
        rep.parent.mkdir(parents=True)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rep.write_text(json.dumps({"schema": "cti-lane-health/1", "lane": "appscan", "generated": now,
                                   "gaps": [{"subject": "A", "kind": "not_scanned", "expected": False},
                                            {"subject": "B", "kind": "not_scanned", "expected": True}]}))
        self.assertEqual(self.m.check_lane_health(vals),
                         ("OK", "1 lane report(s) current; 1 gap(s) open that are not by design (the check-in escalates them)"))
        rep.write_text(json.dumps({"schema": "cti-lane-health/1", "generated": "2026-01-01T00:00:00Z", "gaps": []}))
        self.assertIn("over 26h old", self.m.check_lane_health(vals)[1])
        rep.write_text(json.dumps({"schema": "cti-lane-health/1", "generated": now, "error": "the scanner is unreachable"}))
        self.assertIn("could not work out its health", self.m.check_lane_health(vals)[1])

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
