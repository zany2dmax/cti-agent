#!/usr/bin/env python3
"""cti-agent-onboard: lanes, their settings, their secrets.

Run against a scratch install (the generated lanes.list, lane-settings.list,
fleet.d examples and settings.manifest, and a copy of fleet.env.example as a
new box's fleet.env), with the operator's answers given by a function.

    python3 -m unittest discover -s fleet-kit/tests
"""
import importlib.machinery
import importlib.util
import io
import os
import pathlib
import shutil
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
FLEET = REPO / "fleet-kit" / "fleet"
TOOL = REPO / "fleet-kit" / "bin" / "cti-agent-onboard"


def module():
    loader = importlib.machinery.SourceFileLoader("onboard", str(TOOL))
    spec = importlib.util.spec_from_loader("onboard", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


class Onboard(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        code, self.conf, self.store = self.dir / "code", self.dir / "conf", self.dir / "store"
        for d in (code / "share", code / "bin", self.conf, self.store):
            d.mkdir(parents=True)
        for f in ("lanes.list", "lane-settings.list", "credentials.map"):
            shutil.copy(FLEET / f, code / "share" / f)
        shutil.copytree(FLEET / "fleet.d.example", code / "share" / "fleet.d.example")
        shutil.copy(FLEET / "settings.manifest", code / "settings.manifest")
        shutil.copy(FLEET / "bin" / "fleet-config", code / "bin" / "fleet-config")
        self.env = self.conf / "fleet.env"
        shutil.copy(FLEET / "fleet.env.example", self.env)
        os.chmod(self.env, 0o640)
        self.calls = self.dir / "calls"
        fake = self.dir / "cti-agent-secrets"
        fake.write_text(f'#!/bin/sh\necho "$@" >> {self.calls}\n')
        fake.chmod(0o755)
        self.m = module()
        self.m.CONF, self.m.CODE, self.m.STORE, self.m.SECRETS_TOOL = self.conf, code, self.store, str(fake)
        os.environ["CTI_CONF_DIR"] = str(self.conf)  # also lets it run without root
        self.addCleanup(os.environ.pop, "CTI_CONF_DIR", None)

    def run_it(self, argv, answers=None):
        answers = answers or {}
        asked = []

        def ask(prompt):
            asked.append(prompt)
            for start, reply in answers.items():
                if prompt.lstrip().startswith(start):
                    return reply.pop(0) if isinstance(reply, list) else reply
            return ""
        out, err = io.StringIO(), io.StringIO()
        rc = self.m.main(argv, out=out, err=err, ask=ask)
        return rc, out.getvalue(), err.getvalue(), asked

    def value(self, path, key):
        vals = {}
        for line in path.read_text().splitlines():
            if line.startswith(key + "="):
                vals[key] = line.split("=", 1)[1]
        return vals.get(key)

    def test_a_dry_run_asks_nothing_and_writes_nothing(self):
        before = self.env.read_text()
        rc, out, _, asked = self.run_it(["--dry-run", "--lanes", "checkin,digest,scout"])
        self.assertEqual((rc, asked), (0, []))
        self.assertEqual(self.env.read_text(), before)
        self.assertIn("would set FLEET_LANES=checkin,digest,scout", out)
        self.assertIn("  DIGEST_TO\n", out)
        self.assertIn("  GRAPH_MAILBOX\n", out)
        # Another lane's settings are not this box's to fill in.
        for other in ("DOMAINS_SMTP", "PROOFPOINT_POD_TENANT", "SUPPLIER_JIRA_PROJECT", "VMSCAN_TO"):
            self.assertNotIn(other, out)
        self.assertIn("one Claude credential for the check-in: CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY", out)
        self.assertNotIn("GODADDY_PAT", out)

    def test_the_answers_are_written_and_nothing_secret(self):
        rc, out, err, asked = self.run_it(["--for-real"], {
            "Lanes this box runs": "checkin,digest,scout",
            "DIGEST_TO=": "soc@example.com",
            "GRAPH_MAILBOX=": "cti@example.com",
            "FLEET_ATTRIBUTION=": "Example Org security, two words",
            "Which one to store": "1",
            "Store CLAUDE_CODE_OAUTH_TOKEN": "y",
            "Store ": "n",
        })
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.value(self.env, "FLEET_LANES"), "checkin,digest,scout")
        self.assertEqual(self.value(self.env, "DIGEST_TO"), "soc@example.com")
        self.assertEqual(self.value(self.env, "GRAPH_MAILBOX"), "cti@example.com")
        self.assertEqual(self.value(self.env, "FLEET_ATTRIBUTION"), '"Example Org security, two words"')
        # The commented-out FLEET_LANES line was the one set, not a second line added.
        text = self.env.read_text()
        self.assertEqual(text.count("FLEET_LANES="), 1)
        self.assertEqual(oct(self.env.stat().st_mode & 0o777), "0o640")
        # Only the chosen Claude credential was stored, through cti-agent-secrets.
        self.assertEqual(self.calls.read_text().split("\n")[0], "set CLAUDE_CODE_OAUTH_TOKEN")
        self.assertNotIn("set ANTHROPIC_API_KEY", self.calls.read_text())
        self.assertIn("fleet-config check:", out)
        self.assertFalse(any(p.startswith("DOMAINS_") for p in asked))

    def test_a_value_it_cannot_write_safely_is_asked_again(self):
        rc, out, _, _ = self.run_it(["--for-real", "--lanes", "checkin,digest"], {
            "DIGEST_TO=": ["$(id)", "soc@example.com"], "Store ": "n"})
        self.assertEqual(rc, 0)
        self.assertIn("a value may not hold a quote, a backslash, a $ or a newline; try again", out)
        self.assertEqual(self.value(self.env, "DIGEST_TO"), "soc@example.com")

    def test_a_split_box_gets_each_setting_in_its_lanes_file(self):
        d = self.conf / "fleet.d"
        d.mkdir()
        ex = self.m.CODE / "share" / "fleet.d.example"
        for f in ("00-core.env", "vmscan.env"):
            shutil.copy(ex / f, d / f)
        os.chmod(d / "vmscan.env", 0o640)
        self.env.unlink()
        rc, out, err, _ = self.run_it(["--for-real", "--lanes", "checkin,digest,vmscan"], {
            "VMSCAN_TO=": "vm@example.com", "Store ": "n"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.value(d / "vmscan.env", "VMSCAN_TO"), "vm@example.com")
        self.assertIsNone(self.value(d / "00-core.env", "VMSCAN_TO"))
        self.assertEqual(self.value(d / "00-core.env", "FLEET_LANES"), "checkin,digest,vmscan")

    def test_every_lane_leaves_fleet_lanes_unset(self):
        rc, out, _, _ = self.run_it(["--for-real"], {"Lanes this box runs": "", "Store ": "n"})
        self.assertEqual(rc, 0)
        self.assertIsNone(self.value(self.env, "FLEET_LANES"))
        self.assertIn("(all: FLEET_LANES unset)", out)

    def test_a_name_that_is_no_lane(self):
        rc, _, err, _ = self.run_it(["--dry-run", "--lanes", "digest,nosuch"])
        self.assertEqual(rc, 2)
        self.assertIn("not a lane: nosuch", err)

    def test_before_the_installer(self):
        self.env.unlink()
        rc, _, err, _ = self.run_it(["--dry-run"])
        self.assertEqual(rc, 1)
        self.assertIn("run install-fedora.sh first", err)

    def test_a_mode_is_required(self):
        with self.assertRaises(SystemExit) as cm:
            self.m.main([], out=io.StringIO(), err=io.StringIO())
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
