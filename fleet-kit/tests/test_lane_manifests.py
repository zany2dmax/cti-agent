#!/usr/bin/env python3
"""The lane manifests (fleet-kit/lanes/*.toml) and the units they generate.

scripts/lanes writes every lane's .service unit from its manifest and checks
its timer against it (docs/lane-manifest.md). These tests run it the way
task lane:check does, and against scratch copies to show a hand edit, a stale
manifest and a bad manifest are each caught.

    python3 -m unittest discover -s fleet-kit/tests
"""
import importlib.machinery
import importlib.util
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "lanes"
UNITS = REPO / "fleet-kit" / "fleet" / "systemd-fedora"
LANES = REPO / "fleet-kit" / "lanes"


def module():
    loader = importlib.machinery.SourceFileLoader("lanes_script", str(SCRIPT))
    spec = importlib.util.spec_from_loader("lanes_script", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


class TheRepository(unittest.TestCase):
    def test_every_unit_is_current_with_its_manifest(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_lane_unit_and_timer_has_a_manifest(self):
        m = module()
        named = {u["name"] for lane in m.load_all().values() for u in lane["unit"]}
        services = {p.name[len("cti-agent-"):-len(".service")] for p in UNITS.glob("cti-agent-*.service")}
        services.discard("alert@")  # the failure handler every unit names, not a lane
        self.assertEqual(services, named, "a unit with no manifest, or a manifest with no unit")
        timers = {p.name[len("cti-agent-"):-len(".timer")] for p in UNITS.glob("cti-agent-*.timer")}
        self.assertLessEqual(timers, named, "a timer whose service no manifest describes")

    def test_the_handles_are_the_bash_guards(self):
        # A lane's board handle must be one the guard lets a beat address.
        m = module()
        handles = {h for lane in m.load_all().values() for h in lane["handles"]}
        policy = (REPO / "cmd" / "checkin-bash-guard" / "policy.go").read_text(encoding="utf-8")
        guard = set(re.findall(r'"(@[a-z]+)"', policy[policy.index("var handles = set("):policy.index("var boardKinds")]))
        self.assertEqual(handles, guard - {"@all", "@operator", "@you"})


class AScratchCopy(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.units, self.lanes = self.dir / "units", self.dir / "lanes"
        shutil.copytree(UNITS, self.units)
        shutil.copytree(LANES, self.lanes)
        self.m = module()
        self.m.UNITS, self.m.LANES = self.units, self.lanes

    def check(self):
        return self.m.main(["--check"])

    def test_a_hand_edit_to_a_unit_is_caught_and_write_undoes_it(self):
        p = self.units / "cti-agent-scout.service"
        p.write_text(p.read_text().replace("Nice=15", "Nice=0"))
        self.assertEqual(self.check(), 1)
        self.assertEqual(self.m.main(["--write"]), 0)
        self.assertIn("Nice=15", p.read_text())
        self.assertEqual(self.check(), 0)

    def test_a_changed_manifest_without_write_is_caught(self):
        p = self.lanes / "scout.toml"
        p.write_text(p.read_text().replace("timeout = 900", "timeout = 901"))
        self.assertEqual(self.check(), 1)
        self.m.main(["--write"])
        self.assertIn("TimeoutStartSec=901", (self.units / "cti-agent-scout.service").read_text())

    def test_the_settings_and_credentials_blocks_are_kept(self):
        p = self.units / "cti-agent-domains.service"
        before = p.read_text()
        blocks = [b for b in re.findall(r"(?s)# BEGIN (?:settings|credentials).*?# END (?:settings|credentials)", before)]
        self.assertEqual(len(blocks), 2)
        self.m.main(["--write"])
        for b in blocks:
            self.assertIn(b, p.read_text())

    def test_a_new_lane_gets_a_unit_with_placeholders(self):
        (self.lanes / "newlane.toml").write_text('''lane = "newlane"
handles = []
summary = "x"
[[unit]]
name = "newlane"
description = "A new lane"
exec = "/opt/cti-agent/bin/cti-new --for-real"
timeout = 60
nice = 10
''')
        self.assertEqual(self.m.main(["--write"]), 0)
        text = (self.units / "cti-agent-newlane.service").read_text()
        self.assertIn("EnvironmentFile=/etc/cti-agent/fleet.env\n", text)  # settings-manifest fills it
        self.assertIn("ExecStart=/opt/cti-agent/bin/cti-new --for-real\nTimeoutStartSec=60\nNice=10\n", text)
        self.assertIn("SyslogIdentifier=cti-agent-newlane\n", text)
        self.assertNotIn("LogsDirectory", text)

    def test_a_timer_that_disagrees_is_caught(self):
        p = self.units / "cti-agent-domains.timer"
        p.write_text(p.read_text().replace("OnCalendar=Tue", "OnCalendar=Wed"))
        self.assertEqual(self.check(), 1)
        p.unlink()
        self.assertEqual(self.check(), 1)


class BadManifests(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.m = module()
        self.good = (LANES / "scout.toml").read_text()

    def refused(self, text, why, name="scout.toml"):
        p = self.dir / name
        p.write_text(text)
        with self.assertRaises(self.m.ManifestError) as cm:
            self.m.load(p)
        self.assertIn(why, str(cm.exception))

    def test_the_good_one_loads(self):
        p = self.dir / "scout.toml"
        p.write_text(self.good)
        self.assertEqual(self.m.load(p)["lane"], "scout")

    def test_an_unknown_key(self):
        self.refused(self.good.replace("nice = 15", "nice = 15\nniceness = 3"), "unknown key(s): niceness")

    def test_a_misspelt_lane_key(self):
        self.refused(self.good.replace("summary =", "sumary ="), "unknown key(s): sumary")

    def test_the_name_must_match_the_file(self):
        self.refused(self.good, "must be lower-case and match the file name", name="other.toml")

    def test_exec_outside_the_code_dir(self):
        self.refused(re.sub(r'exec = "[^"]*"', 'exec = "/usr/bin/curl http://x"', self.good), "exec must start with /opt/cti-agent/bin/")

    def test_a_timer_with_no_schedule(self):
        self.refused(re.sub(r"on_calendar = .*\n", "", self.good), "timer needs on_calendar")

    def test_a_bad_handle(self):
        self.refused(self.good.replace('"@scout"', '"scout"'), "is not like @name")

    def test_not_toml(self):
        self.refused("lane = ", "not valid TOML")

    def test_a_unit_in_two_lanes(self):
        lanes = self.dir / "lanes"
        lanes.mkdir()
        (lanes / "scout.toml").write_text(self.good)
        (lanes / "copy.toml").write_text(self.good.replace('lane = "scout"', 'lane = "copy"'))
        self.m.LANES = lanes
        with self.assertRaises(self.m.ManifestError) as cm:
            self.m.load_all()
        self.assertIn("unit scout is in both", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
