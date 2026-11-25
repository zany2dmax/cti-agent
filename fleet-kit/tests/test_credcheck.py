#!/usr/bin/env python3
"""run-credcheck: every in-use lane's credential check, for the check-in to read.

Run against fake checks in a scratch FLEET_CODE: what each prints and exits
with decides the line. The check-in reads the report, so a line holding a
credential's value must never reach it.

    python3 -m unittest discover -s fleet-kit/tests
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
FLEET = REPO / "fleet-kit" / "fleet"


class RunCredcheck(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.code, self.home, self.creds = self.dir / "code", self.dir / "home", self.dir / "creds"
        for d in (self.code / "bin", self.code / "share", self.home, self.creds):
            d.mkdir(parents=True)
        shutil.copy(FLEET / "lanes.list", self.code / "share" / "lanes.list")
        shutil.copy(FLEET / "share" / "fleet-mode.sh", self.code / "share" / "fleet-mode.sh")
        shutil.copy(FLEET / "bin" / "run-credcheck", self.code / "bin" / "run-credcheck")
        self.fake("cti-mailer", "OK: token works, roles Mail.Read Mail.Send", 0)
        self.fake("cti-jira", "FAIL: credentials rejected: 401", 1)
        self.fake("cti-appreport", "OK: WAS login works, 80% of the rate budget left", 0)
        self.fake("cti-domains", "OK: 12 domain(s) in the account", 0)
        self.fake("cti-vmscan", "OK: spreadsheet read, 40 asset groups", 0)

    def fake(self, name, last, rc):
        p = self.code / "bin" / name
        p.write_text(f'#!/bin/sh\n[ "$1" = --check ] || exit 9\necho "starting"\necho\necho "{last}"\nexit {rc}\n')
        p.chmod(0o755)

    def run_it(self, lanes=None):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "FLEET_HOME": str(self.home),
               "FLEET_CODE": str(self.code), "FLEET_ENV": str(self.dir / "absent.env"),
               "CREDENTIALS_DIRECTORY": str(self.creds)}
        if lanes is not None:
            env["FLEET_LANES"] = lanes
        r = subprocess.run(["bash", str(self.code / "bin" / "run-credcheck")], capture_output=True, text=True,
                           env=env, check=False)
        report = self.home / "reports" / "credcheck.txt"
        return r, report.read_text() if report.exists() else ""

    def rows(self, text):
        return [ln.split("\t") for ln in text.splitlines() if ln and not ln.startswith("#")]

    def test_every_lane_by_default(self):
        r, text = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = {(lane, cmd): (state, last) for lane, cmd, state, last in self.rows(text)}
        self.assertEqual(rows[("checkin", "cti-mailer")], ("ok", "OK: token works, roles Mail.Read Mail.Send"))
        self.assertEqual(rows[("checkin", "cti-jira")], ("FAIL", "FAIL: credentials rejected: 401"))
        self.assertEqual({c for _l, c in rows}, {"cti-mailer", "cti-jira", "cti-appreport", "cti-domains", "cti-vmscan"})
        self.assertIn("5 check(s), 1 failed", r.stdout)
        self.assertEqual(oct((self.home / "reports" / "credcheck.txt").stat().st_mode & 0o777), "0o600")

    def test_only_the_lanes_in_use(self):
        _, text = self.run_it("checkin,digest,vmscan")
        self.assertEqual(sorted(c for _l, c, _s, _t in self.rows(text)), ["cti-jira", "cti-mailer", "cti-vmscan"])

    def test_a_line_holding_a_credential_is_withheld(self):
        (self.creds / "JIRA_API_TOKEN").write_text("tok-SECRET-12345")
        self.fake("cti-jira", "FAIL: 401 for token tok-SECRET-12345", 1)
        _, text = self.run_it()
        self.assertNotIn("tok-SECRET-12345", text)
        self.assertIn("[line withheld: it contained a credential's value]", text)
        self.assertIn("OK: token works", text, "an innocent line was withheld")

    def test_a_check_it_does_not_know_is_not_run(self):
        lst = self.code / "share" / "lanes.list"
        lst.write_text(lst.read_text().replace("cti-vmscan\t", "rm\t", 1))
        (self.code / "bin" / "rm").write_text("#!/bin/sh\ntouch RAN\n")
        (self.code / "bin" / "rm").chmod(0o755)
        _, text = self.run_it()
        self.assertIn("rm\tFAIL\tnot one of run-credcheck's checks; not run", text)
        self.assertFalse((self.home / "RAN").exists())

    def test_it_takes_no_arguments(self):
        r = subprocess.run(["bash", str(self.code / "bin" / "run-credcheck"), "--for-real"], capture_output=True,
                           text=True, check=False)
        self.assertEqual(r.returncode, 2)


class TheCheckinUnitHoldsOnlyWhatTheBeatNeeds(unittest.TestCase):
    def test_its_credentials_are_one_claude_token_and_graph_for_alerts(self):
        # The beat reads untrusted mail. It needs a Claude credential to run,
        # and Graph for cti-alert, its one way to reach a person; every other
        # secret it once held came from a check or a preview it no longer runs.
        unit = (FLEET / "systemd-fedora" / "cti-agent-checkin.service").read_text(encoding="utf-8")
        got = {ln.split("=", 1)[1] for ln in unit.splitlines() if ln.startswith("ImportCredential=")}
        self.assertEqual(got, {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                               "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID"})


if __name__ == "__main__":
    unittest.main()
