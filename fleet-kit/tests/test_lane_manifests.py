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
RUN_CHECKIN = REPO / "fleet-kit" / "fleet" / "bin" / "run-checkin"


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

    def test_every_generated_file_is_tracked(self):
        # The fleet.d examples end in .env, which .gitignore ignores: they were
        # generated, tested and installed from disk, and never committed.
        m = module()
        paths = [p.relative_to(REPO) for p in m.wanted(m.load_all())]
        r = subprocess.run(["git", "-C", str(REPO), "ls-files", "--", *map(str, paths)],
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            self.skipTest("not a git checkout")
        tracked = set(r.stdout.split())
        untracked = sorted(str(p) for p in paths if str(p) not in tracked)
        self.assertEqual(untracked, [], "generated but not in git (ignored?)")

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


class TheOrchestratorKnowsEveryLane(unittest.TestCase):
    """A lane nobody oversees fails silently: on 2026-11-11 the owner lane held
    a scan and the orchestrator, never told the lane existed, said nothing.
    The table and the verdict's lane list are generated now; these hold the
    rest to them."""

    def setUp(self):
        self.lanes = module().load_all()
        self.skill = (REPO / "fleet-kit" / "fleet" / "skills" / "checkin" / "SKILL.md").read_text(encoding="utf-8")

    def test_every_timed_lane_is_in_the_table(self):
        for m in self.lanes.values():
            timed = any(u.get("timer") for u in m["unit"])
            if m["lane"] == "checkin":
                self.assertNotIn("orchestrator", m, "the check-in does not oversee itself")
                continue
            with self.subTest(lane=m["lane"]):
                self.assertTrue(timed, "a lane with no timer")
                self.assertIn("orchestrator", m, "a timed lane with no row in the orchestrator's table")

    def test_every_runner_is_some_units_command(self):
        runners = {p.name for p in (REPO / "fleet-kit" / "fleet" / "bin").glob("run-*")}
        used = {u["exec"].split()[0].rsplit("/", 1)[-1] for m in self.lanes.values() for u in m["unit"]}
        self.assertLessEqual(runners, used, "a runner no lane's unit starts")

    def test_the_skills_verdict_example_names_every_lane_once(self):
        lanes = [u["name"] for m in module().overseen(self.lanes) for u in m["unit"]]
        example = re.findall(r'\{"lane": "([a-z]+)"', self.skill)
        self.assertEqual(sorted(example), sorted(lanes), "the checkin skill's example verdict lists other lanes")
        words = {8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen"}
        self.assertIn(f"**all {words[len(lanes)]}, every beat, once each**", self.skill,
                      "the checkin skill says a different number of lanes")

    def test_the_skill_has_a_check_for_every_lane(self):
        for name in [u["name"] for m in module().overseen(self.lanes) for u in m["unit"]]:
            with self.subTest(lane=name):
                self.assertRegex(self.skill.lower(), rf"\b{name}\b", f"the checkin skill never mentions {name}")


class TheSettingsGeneratorReadsTheManifests(unittest.TestCase):
    """scripts/settings-manifest decides a setting's fleet.d file from the
    lanes' setting_prefixes, a unit's lane from the manifests, and which lane
    loads every file from all_settings. Nothing about lanes is said there."""

    def test_longest_prefix_wins(self):
        m = module()
        rules = m.setting_rules(m.load_all())
        def lane(k):
            return next((ln for pre, ln in rules if k.startswith(pre)), "core")
        self.assertEqual(lane("WAS_OWNER_CC"), "appowners")
        self.assertEqual(lane("WAS_TO"), "appscan")
        self.assertEqual(lane("JIRA_VMSCAN_PROJECT_KEY"), "vmscan")
        self.assertEqual(lane("JIRA_PROJECT_KEY"), "core")

    def test_the_weekly_is_the_digests_and_checkin_loads_everything(self):
        m = module()
        lanes = m.load_all()
        self.assertEqual(m.unit_lanes(lanes)["weekly"], "digest")
        self.assertEqual(m.all_settings_lane(lanes), "checkin")

    def test_settings_manifest_has_no_lane_list_of_its_own(self):
        text = (REPO / "scripts" / "settings-manifest").read_text(encoding="utf-8")
        self.assertNotRegex(text, r'\("[A-Z_]+", "(checkin|vmscan|digest|appscan)"\)', "a hard-coded prefix rule")
        self.assertNotIn('== "weekly"', text)
        self.assertNotIn('ALL_FILES_LANE = "', text)


class TheBeatsGrantIsDeclared(unittest.TestCase):
    """Every Bash and Read grant run-checkin gives the beat is declared by
    exactly one lane (beat_grants), and every declared one is given. The beat
    reads untrusted mail, so a capability nobody signed for is the thing to
    catch."""

    def test_the_repository_agrees(self):
        m = module()
        self.assertEqual(m.grant_problems(m.load_all()), [])
        self.assertGreaterEqual(len(m.actual_grants()), 20)

    def test_run_credcheck_knows_exactly_the_declared_checks(self):
        # Its CHECKS list is what the settings generator grants its unit from,
        # and what it refuses anything outside of.
        m = module()
        declared = sorted({c for lane in m.load_all().values() for c in lane.get("credential_checks", [])})
        src = (REPO / "fleet-kit" / "fleet" / "bin" / "run-credcheck").read_text(encoding="utf-8")
        block = src[src.index("CHECKS=("):src.index(")", src.index("CHECKS=("))]
        listed = sorted(re.findall(r'"\$FLEET_CODE/bin/([a-z-]+)"', block))
        self.assertEqual(listed, declared)
        self.assertFalse([g for g in m.declared_grants(m.load_all()) if "--check" in g], "a --check is still a beat grant")

    def scratch(self, edit):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        rc = d / "run-checkin"
        rc.write_text(edit(RUN_CHECKIN.read_text(encoding="utf-8")))
        m = module()
        m.RUN_CHECKIN = rc
        return m, m.grant_problems(m.load_all())

    def test_an_undeclared_grant_is_caught(self):
        add = 'ALLOWED_TOOLS="$ALLOWED_TOOLS,Bash($FLEET_CODE/bin/cti-mailer --lane digest:*)"\n'
        _, problems = self.scratch(lambda t: t.replace("\nDISALLOWED_TOOLS=", "\n" + add + "DISALLOWED_TOOLS=", 1))
        self.assertEqual(problems, ["run-checkin grants Bash(cti-mailer --lane digest:*), which no lane manifest declares "
                                    "(add it to that lane's beat_grants)"])

    def test_a_widened_grant_is_caught(self):
        # An exact grant becoming a prefix (:*) would let anything ride along.
        _, problems = self.scratch(lambda t: t.replace("cti-mailbox --dry-run)", "cti-mailbox --dry-run:*)"))
        self.assertIn("run-checkin grants Bash(cti-mailbox --dry-run:*), which no lane manifest declares "
                      "(add it to that lane's beat_grants)", problems)
        self.assertIn("mailbox.toml declares the beat grant Bash(cti-mailbox --dry-run), which run-checkin does not give", problems)

    def test_a_new_read_directory_is_caught(self):
        _, problems = self.scratch(lambda t: t.replace("for d in reports logs archive; do", "for d in reports logs archive state; do"))
        self.assertEqual(len(problems), 1)
        self.assertIn("Read(state/**)", problems[0])


class AScratchCopy(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.units, self.lanes = self.dir / "units", self.dir / "lanes"
        shutil.copytree(UNITS, self.units)
        shutil.copytree(LANES, self.lanes)
        self.m = module()
        self.m.UNITS, self.m.LANES = self.units, self.lanes
        # Every file --write writes goes to the scratch copy, never the repo.
        fleet = REPO / "fleet-kit" / "fleet"
        shutil.copy(fleet / "CLAUDE.md", self.dir / "CLAUDE.md")
        shutil.copy(fleet / "lanes.list", self.dir / "lanes.list")
        shutil.copy(REPO / "internal" / "checkin" / "lanes_gen.go", self.dir / "lanes_gen.go")
        shutil.copytree(fleet / "fleet.d.example", self.dir / "fleet.d.example")
        self.m.ORCHESTRATOR, self.m.LANE_LIST = self.dir / "CLAUDE.md", self.dir / "lanes.list"
        self.m.VERDICT_LANES, self.m.EXAMPLES = self.dir / "lanes_gen.go", self.dir / "fleet.d.example"

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
exec = "/opt/cti-agent/bin/cti-scout --days 1"
timeout = 60
nice = 10
''')
        self.assertEqual(self.m.main(["--write"]), 0)
        text = (self.units / "cti-agent-newlane.service").read_text()
        self.assertIn("EnvironmentFile=/etc/cti-agent/fleet.env\n", text)  # settings-manifest fills it
        self.assertIn("ExecStart=/opt/cti-agent/bin/cti-scout --days 1\nTimeoutStartSec=60\nNice=10\n", text)
        self.assertIn("SyslogIdentifier=cti-agent-newlane\n", text)
        self.assertNotIn("LogsDirectory", text)

    def test_a_hand_edit_to_the_lane_table_is_caught(self):
        orch = self.dir / "CLAUDE.md"
        shutil.copy(REPO / "fleet-kit" / "fleet" / "CLAUDE.md", orch)
        self.m.ORCHESTRATOR = orch
        self.m.VERDICT_LANES = self.dir / "lanes_gen.go"
        self.assertEqual(self.m.main(["--write"]), 0)
        self.assertEqual(self.check(), 0)
        orch.write_text(orch.read_text().replace("| `@scout` |", "| `@scouts` |"))
        self.assertEqual(self.check(), 1)
        # A new lane with a table row gets a row and a verdict entry.
        (self.lanes / "newlane.toml").write_text('''lane = "newlane"
handles = ["@newlane"]
summary = "x"
[orchestrator]
order = 99
runs = "`$FLEET_CODE/bin/cti-new`"
when = "Daily"
sends_to = "nobody"
[[unit]]
name = "newlane"
description = "A new lane"
exec = "/opt/cti-agent/bin/cti-new --for-real"
timeout = 60
nice = 10
''')
        self.m.main(["--write"])
        self.assertIn("| `@newlane` | `$FLEET_CODE/bin/cti-new` | Daily | nobody |", orch.read_text())
        self.assertIn('\t"newlane",\n}', (self.dir / "lanes_gen.go").read_text())

    def test_a_unit_that_does_not_run_for_real_is_caught(self):
        p = self.lanes / "domains.toml"
        p.write_text(p.read_text().replace("run-domains --for-real", "run-domains --dry-run"))
        self.assertEqual(self.check(), 1)
        p.write_text(p.read_text().replace("run-domains --dry-run", "run-domains"))
        self.assertEqual(self.check(), 1)

    def test_a_unit_running_an_unknown_command_is_caught(self):
        p = self.lanes / "scout.toml"
        p.write_text(p.read_text().replace("bin/cti-scout ", "bin/cti-scoutt "))
        self.assertEqual(self.check(), 1)

    def test_an_example_no_lane_generates_is_caught(self):
        self.assertEqual(self.check(), 0)
        (self.dir / "fleet.d.example" / "gone.env").write_text("# a lane that was removed\n")
        self.assertEqual(self.check(), 1)

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

    def test_a_table_cell_with_a_pipe(self):
        self.refused(re.sub(r'(?m)^runs = .*$', 'runs = "a | b"', self.good), "must be one line with no |")

    def test_two_lanes_with_one_order(self):
        lanes = self.dir / "lanes"
        lanes.mkdir()
        (lanes / "scout.toml").write_text(self.good)
        other = self.good.replace('lane = "scout"', 'lane = "other"').replace('"@scout"', '"@other"').replace('name = "scout"', 'name = "other"')
        (lanes / "other.toml").write_text(other)
        self.m.LANES = lanes
        with self.assertRaises(self.m.ManifestError) as cm:
            self.m.load_all()
        self.assertIn("both have orchestrator order", str(cm.exception))

    def test_a_prefix_claimed_twice(self):
        lanes = self.dir / "lanes"
        lanes.mkdir()
        shutil.copy(LANES / "vmscan.toml", lanes / "vmscan.toml")
        other = (LANES / "domains.toml").read_text().replace('"DOMAINS_"', '"VMSCAN_"')
        (lanes / "domains.toml").write_text(other)
        self.m.LANES = lanes
        with self.assertRaises(self.m.ManifestError) as cm:
            self.m.load_all()
        self.assertIn("setting prefix VMSCAN_ is claimed by both", str(cm.exception))

    def test_a_lower_case_prefix(self):
        self.refused(self.good.replace('summary =', 'setting_prefixes = ["vmscan_"]\nsummary ='), "setting_prefixes must be")

    def test_a_bad_grant(self):
        for bad in ["Bash(/opt/cti-agent/bin/cti-kev)", "Bash(cti-kev; rm -rf /)", "Write(reports/**)", "Read(/etc/**)"]:
            with self.subTest(grant=bad):
                self.refused(self.good.replace("summary =", f'beat_grants = ["{bad}"]\nsummary ='), "beat_grants must be")

    def test_a_unit_in_two_lanes(self):
        lanes = self.dir / "lanes"
        lanes.mkdir()
        (lanes / "scout.toml").write_text(self.good)
        (lanes / "copy.toml").write_text(re.sub(r"(?m)^order = .*$", "order = 98", self.good.replace('lane = "scout"', 'lane = "copy"')))
        self.m.LANES = lanes
        with self.assertRaises(self.m.ManifestError) as cm:
            self.m.load_all()
        self.assertIn("unit scout is in both", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
