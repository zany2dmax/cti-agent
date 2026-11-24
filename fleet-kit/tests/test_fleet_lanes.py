#!/usr/bin/env python3
"""FLEET_LANES: the lanes a box runs.

A lane left out has its timer turned off by the installer (install-fedora.sh),
is listed as off on purpose by fleet-timers so the check-in does not report it
or run its credential checks, needs none of its settings (fleet-config) and
must be "off" in the check-in's verdict (cti-checkin-verdict; Go test in
internal/checkin). Unset, every lane runs, as before.

    python3 -m unittest discover -s fleet-kit/tests
"""
import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
FLEET = REPO / "fleet-kit" / "fleet"
INSTALLER = REPO / "fleet-kit" / "install-fedora.sh"


def lanes_block():
    """The installer's FLEET_LANES block, to run on its own."""
    text = INSTALLER.read_text(encoding="utf-8")
    return text[text.index('LANE_LIST="$SRC/fleet/lanes.list"'):text.index("# org_compose CORE NAME OUT")]


def run_installer_block(lanes, after):
    stubs = f"""
SRC={FLEET.parent}
cfgval() {{ printf '%s' {lanes!r}; }}
bad() {{ echo "BAD $*"; }}
bail() {{ echo "BAIL"; exit 1; }}
ok() {{ echo "OK $*"; }}
info() {{ echo "INFO $*"; }}
"""
    return subprocess.run(["bash", "-c", stubs + lanes_block() + after], capture_output=True, text=True, check=False)


class TheInstaller(unittest.TestCase):
    def test_unset_is_every_lane(self):
        r = run_installer_block("", "lane_in_use appscan && echo IN")
        self.assertIn("INFO lanes in use: all", r.stdout)
        self.assertIn("IN", r.stdout)

    def test_a_list_turns_the_rest_off(self):
        r = run_installer_block("checkin,digest,scout", """
for l in digest scout appscan mailbox; do lane_in_use $l && echo "$l on" || echo "$l off"; done
""")
        self.assertIn("OK lanes in use (FLEET_LANES): checkin, digest, scout", r.stdout)
        for want in ("digest on", "scout on", "appscan off", "mailbox off"):
            self.assertIn(want, r.stdout)

    def test_a_timer_maps_to_its_lane(self):
        r = run_installer_block("", """
for t in cti-agent-weekly.timer cti-agent-digest.timer cti-agent-vmscan.timer cti-agent-nosuch.timer; do
  echo "$t=$(timer_lane $t)"
done
""")
        for want in ("cti-agent-weekly.timer=digest", "cti-agent-digest.timer=digest",
                     "cti-agent-vmscan.timer=vmscan", "cti-agent-nosuch.timer=\n"):
            self.assertIn(want, r.stdout + "\n")

    def test_a_name_that_is_no_lane_stops_the_install(self):
        r = run_installer_block("digest,nosuch", "echo REACHED")
        self.assertIn('BAD FLEET_LANES names "nosuch", which is not a lane', r.stdout)
        self.assertIn("BAIL", r.stdout)
        self.assertNotIn("REACHED", r.stdout)

    def test_off_timers_are_turned_off_and_not_reported_as_missing(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('if [ -n "$lane" ] && ! lane_in_use "$lane" && [ "$(unit_state "$unit")" = enabled ]; then', text)
        self.assertIn('run systemctl disable --now "$unit"', text)
        self.assertIn('info "$unit off: lane $lane is not in FLEET_LANES"', text)
        self.assertIn('run install -m 0644 -o root -g root "$SRC/fleet/lanes.list" "$CODE_DIR/share/lanes.list"', text)


class FleetTimers(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "share").mkdir()
        shutil.copy(FLEET / "lanes.list", self.dir / "share" / "lanes.list")
        fake = self.dir / "systemctl"
        fake.write_text("#!/bin/bash\necho TIMERS\n")
        fake.chmod(0o755)
        text = (FLEET / "bin" / "fleet-timers").read_text(encoding="utf-8")
        self.script = self.dir / "fleet-timers"
        self.script.write_text(text.replace("SYSTEMCTL=/usr/bin/systemctl", f"SYSTEMCTL={fake}"))

    def run_it(self, lanes):
        env = dict(os.environ, FLEET_CODE=str(self.dir))
        env.pop("FLEET_LANES", None)
        if lanes is not None:
            env["FLEET_LANES"] = lanes
        return subprocess.run(["bash", str(self.script), "--all"], capture_output=True, text=True, env=env, check=False)

    def test_unset_says_nothing_more(self):
        r = self.run_it(None)
        self.assertEqual((r.returncode, r.stdout), (0, "TIMERS\n"))

    def test_the_off_lanes_and_their_checks_are_named(self):
        r = self.run_it("checkin,digest,scout,vmscan")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Off on purpose (not in FLEET_LANES): patchtuesday appscan appowners domains supplier mailbox.", r.stdout)
        self.assertIn("Skip their credential checks: cti-appreport --check cti-domains --check.", r.stdout)
        self.assertNotIn("cti-vmscan --check", r.stdout)

    def test_a_value_with_odd_characters_is_not_read(self):
        r = self.run_it("digest;rm -rf /")
        self.assertIn("FLEET_LANES has characters a lane name does not; not read", r.stdout)
        self.assertNotIn("Off on purpose", r.stdout)


class TheBeatsReadOnlyWrappersGetNoSecrets(unittest.TestCase):
    def test_credentials_map(self):
        # fleet-timers once wrote its code path so that the settings generator
        # took it for a call to the cti-agent wrapper and granted it every
        # secret, which a hand run through the wrapper would then receive.
        lines = (FLEET / "credentials.map").read_text(encoding="utf-8").splitlines()
        granted = {ln.split()[0] for ln in lines if ln.strip() and not ln.startswith("#")}
        for w in ("fleet-timers", "fleet-journal", "fleet-board"):
            self.assertNotIn(w, granted, f"{w} is granted secrets in credentials.map")


class FleetConfig(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader("fleet_config", str(FLEET / "bin" / "fleet-config"))
        spec = importlib.util.spec_from_loader("fleet_config", loader)
        self.fc = importlib.util.module_from_spec(spec)
        loader.exec_module(self.fc)
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def check(self, text, manifest):
        p = self.dir / "fleet.env"
        p.write_text(text)
        return self.fc.check([p], manifest)

    def manifest(self):
        m = self.fc.load_manifest(FLEET / "settings.manifest")
        # A lane setting that is required, as a future lane's could be.
        m["SUBNETS_SHEET"] = dict(m["SUBNETS_SHEET"], required="always")
        return m

    def test_an_unused_lanes_required_setting_is_not_missing(self):
        m = self.manifest()
        self.assertEqual(m["SUBNETS_SHEET"]["file"], "vmscan")
        missing = lambda r: {x["key"] for x in r["missing"]}  # noqa: E731
        self.assertIn("SUBNETS_SHEET", missing(self.check("", m)))
        self.assertIn("SUBNETS_SHEET", missing(self.check("FLEET_LANES=digest,vmscan\n", m)))
        self.assertNotIn("SUBNETS_SHEET", missing(self.check("FLEET_LANES=digest, scout\n", m)))
        # Core settings stay required whatever the lanes.
        self.assertIn("GRAPH_MAILBOX", missing(self.check("FLEET_LANES=scout\n", m)))

    def test_a_name_that_is_no_lane_is_a_problem(self):
        r = self.check("FLEET_LANES=digest,nosuch\n", self.manifest())
        self.assertEqual(r["unknown_lanes"], ["nosuch"])
        self.assertEqual(self.check("FLEET_LANES=digest\n", self.manifest())["unknown_lanes"], [])


if __name__ == "__main__":
    unittest.main()
