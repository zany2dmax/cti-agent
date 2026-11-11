"""The command manifest (fleet-kit/fleet/commands.manifest) against the code.

`cti-agent` with no arguments, `cti-agent CMD --help` and the bash and zsh
completions all answer from that one file, so it is only as good as it is
current. These tests fail the build when a command exists that the manifest
does not know, or a flag exists on one side only: add it in the same change.
"""
import pathlib
import re
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "fleet-kit" / "fleet" / "commands.manifest"
USAGE = ROOT / "fleet-kit" / "fleet" / "share" / "cti-agent-usage"

# In the tree but not something an operator runs through cti-agent.
NOT_A_COMMAND = {
    "cti-agent",           # cmd/cti-agent: the original ingest binary, not installed
    "checkin-bash-guard",  # the heartbeat's PreToolUse hook, run by Claude Code
    "fleet-sanitize",      # the heartbeat wrappers' output cleaner, a filter not a command
}

GO_FLAG = re.compile(
    r"\b\w+\.(?:String|Bool|Int|Int64|Uint|Float64|Duration|Var|Func|"
    r"StringVar|BoolVar|IntVar|Int64Var|DurationVar|Float64Var)\("
    r"(?:&[\w.\[\]]+,\s*)?\"([a-z][a-z0-9-]*)\"")
PY_FLAG = re.compile(r"add_argument\(\s*\"(--[a-z][a-z0-9-]*)\"")
SH_ARM = re.compile(
    r"^\s*(-{1,2}[A-Za-z][A-Za-z0-9-]*(?:\|-{1,2}[A-Za-z][A-Za-z0-9-]*)*)\)", re.M)


def parse():
    cmds, cur = {}, None
    for n, raw in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        val = val.strip()
        if key == "command":
            if val in cmds:
                raise AssertionError(f"line {n}: {val} listed twice")
            cur = cmds[val] = {"about": "", "runs": "", "modes": [], "exempt": [],
                               "risk": {}, "flags": {}, "subs": {}}
        elif cur is None:
            raise AssertionError(f"line {n}: {key!r} before any command")
        elif key in ("about", "runs"):
            cur[key] = val
        elif key in ("modes", "exempt"):
            cur[key] = val.split()
        elif key == "risk":
            name, _, level = val.partition(" ")
            cur["risk"][name] = level.strip()
        elif key in ("flag", "sub"):
            spec, sep, desc = val.partition(" | ")
            if not sep or not desc.strip():
                raise AssertionError(f"line {n}: {key} needs 'name | what it does'")
            name = spec.split()[0]
            cur["flags" if key == "flag" else "subs"][name] = desc.strip()
        else:
            raise AssertionError(f"line {n}: unknown key {key!r}")
    return cmds


class TestCommandManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmds = parse()

    def test_every_stanza_is_complete(self):
        for name, c in self.cmds.items():
            with self.subTest(command=name):
                self.assertTrue(c["about"], "no about line")
                self.assertIn(c["runs"], ("read", "local", "effect"))
                for f in c["flags"]:
                    self.assertTrue(f.startswith("-"), f"flag {f!r} has no dash")
                for f, level in c["risk"].items():
                    self.assertIn(f, c["flags"], f"risk line for unknown flag {f}")
                    self.assertIn(level, ("safe", "writes", "changes"), f"{f}: {level}")

    def test_every_command_in_the_tree_is_listed_and_nothing_else(self):
        real = {d.name for d in (ROOT / "cmd").iterdir() if d.is_dir()}
        real |= {p.name for p in (ROOT / "fleet-kit" / "fleet" / "bin").iterdir() if p.is_file()}
        real |= {p.name for p in (ROOT / "fleet-kit" / "fleet" / "lanes").glob("*.py")}
        real -= NOT_A_COMMAND
        listed = set(self.cmds)
        self.assertEqual(sorted(real - listed), [],
                         "commands with no stanza in commands.manifest")
        self.assertEqual(sorted(listed - real), [],
                         "stanzas for commands that do not exist")

    def _real_flags(self, name):
        if name.endswith(".py"):
            text = (ROOT / "fleet-kit" / "fleet" / "lanes" / name).read_text(encoding="utf-8")
            return set(PY_FLAG.findall(text))
        d = ROOT / "cmd" / name
        if d.is_dir():
            out = set()
            for f in d.glob("*.go"):
                if not f.name.endswith("_test.go"):
                    out |= {"--" + x for x in GO_FLAG.findall(f.read_text(encoding="utf-8"))}
            return out
        text = (ROOT / "fleet-kit" / "fleet" / "bin" / name).read_text(encoding="utf-8")
        out = set()
        for arm in SH_ARM.findall(text):
            out |= set(arm.split("|"))
        return out - {"-h", "--help"}

    def test_flags_match_what_the_code_accepts(self):
        # Subcommand tools parse positional words, not flags; their sub: lines
        # are checked for presence only (below), and their flags by hand.
        positional = {"fleet-board", "fleet-db", "fleet-owners", "fleet-trace", "cti-budget"}
        for name, c in self.cmds.items():
            if name in positional:
                continue
            with self.subTest(command=name):
                real = self._real_flags(name)
                listed = set(c["flags"])
                self.assertEqual(sorted(real - listed), [],
                                 f"{name} accepts flags the manifest does not list")
                self.assertEqual(sorted(listed - real), [],
                                 f"{name}'s manifest lists flags the code does not accept")

    def test_subcommands_are_words_the_code_handles(self):
        files = {
            "fleet-board": ROOT / "fleet-kit" / "fleet" / "bin" / "fleet-board",
            "fleet-db": ROOT / "fleet-kit" / "fleet" / "bin" / "fleet-db",
            "fleet-owners": ROOT / "fleet-kit" / "fleet" / "bin" / "fleet-owners",
            "fleet-trace": ROOT / "fleet-kit" / "fleet" / "bin" / "fleet-trace",
            "cti-budget": ROOT / "cmd" / "cti-budget" / "main.go",
        }
        for name, path in files.items():
            text = path.read_text(encoding="utf-8")
            for sub in self.cmds[name]["subs"]:
                with self.subTest(command=name, sub=sub):
                    self.assertRegex(text, r"[\"'\s(|]" + re.escape(sub) + r"[\"')\s|:]",
                                     f"{name} has no {sub!r} subcommand")


class TestEveryEffectCommandMustBeToldHowToRun(unittest.TestCase):
    """The rule: a command that changes something has no default. It takes
    --dry-run or --for-real (or --to-dev where it has one), and with none it
    prints usage and exits 2 without touching anything."""

    @classmethod
    def setUpClass(cls):
        cls.cmds = parse()

    def test_the_manifest_names_the_modes_of_every_effect_command(self):
        for name, c in self.cmds.items():
            with self.subTest(command=name):
                if c["runs"] != "effect":
                    self.assertEqual(c["modes"], [], "only effect commands take a mode")
                    continue
                self.assertTrue({"--dry-run", "--for-real"} <= set(c["modes"]),
                                "an effect command must offer --dry-run and --for-real")
                for m in c["modes"] + c["exempt"]:
                    self.assertIn(m, c["flags"], f"{m} is not a flag of {name}")

    BASH = ("run-digest", "run-appscan", "run-domains", "run-appowners",
            "run-patchtuesday", "run-mailbox-cleanup", "run-checkin", "run-vmscan", "run-supplier")

    def _bash(self, name, *args):
        script = ROOT / "fleet-kit" / "fleet" / "bin" / name
        return subprocess.run(
            ["bash", str(script), *args], check=False, capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "FLEET_HOME": "/nonexistent", "HOME": "/nonexistent"})

    def test_a_runner_with_no_mode_prints_usage_and_exits_2(self):
        for name in self.BASH:
            with self.subTest(runner=name):
                r = self._bash(name)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("say how to run it", r.stderr)
                self.assertIn("--dry-run", r.stderr)
                self.assertIn("--for-real", r.stderr)

    def test_contradictory_modes_are_refused(self):
        for name in self.BASH:
            with self.subTest(runner=name):
                r = self._bash(name, "--dry-run", "--for-real")
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("contradict", r.stderr)

    def test_the_timers_say_for_real(self):
        """A unit that lost its flag must fail loudly, so each says it."""
        units = ROOT / "fleet-kit" / "fleet" / "systemd-fedora"
        for f in sorted(units.glob("*.service")):
            text = f.read_text(encoding="utf-8")
            line = next((ln for ln in text.splitlines() if ln.startswith("ExecStart=")), "")
            cmd = line.split("/")[-1].split()[0] if line else ""
            if cmd in self.cmds and self.cmds[cmd]["runs"] == "effect":
                with self.subTest(unit=f.name):
                    self.assertIn("--for-real", line, f"{f.name} does not say --for-real")

    def test_go_and_python_commands_refuse_to_run_without_a_mode(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            checks = [("cti-alert", ["--unit", "cti-agent-digest.service"]),
                      ("cti-mailbox", []), ("cti-mailer", []),
                      ("cti-jira", ["--test-ticket"])]
            for name, args in checks:
                exe = pathlib.Path(tmp) / name
                b = subprocess.run(["go", "build", "-o", str(exe), f"./cmd/{name}"], cwd=ROOT,
                                   check=False, capture_output=True, text=True)
                self.assertEqual(b.returncode, 0, b.stderr)
                with self.subTest(command=name):
                    r = subprocess.run([str(exe), *args], check=False, capture_output=True,
                                       text=True, env={"PATH": "/usr/bin:/bin", "HOME": tmp})
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertIn("say how to run it", r.stderr)
            py = subprocess.run(
                ["python3", str(ROOT / "fleet-kit" / "fleet" / "lanes" / "mailer.py"),
                 "--html", "x"], check=False, capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "HOME": tmp})
            self.assertEqual(py.returncode, 2, py.stderr)
            self.assertIn("say how to run it", py.stderr)

    def test_the_read_only_check_flags_need_no_mode(self):
        self.assertEqual(self.cmds["cti-jira"]["exempt"], ["--check", "--list"])
        self.assertEqual(self.cmds["cti-mailer"]["exempt"], ["--check", "--armed"])

    def test_the_owner_lane_question_runs_without_a_mode(self):
        """run-appowners asks `cti-mailer --lane owner --armed` before every
        real or dry run. It only reads, so it must not demand a mode: when it
        did, the owner lane could not start at all except with --to-dev."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            exe = pathlib.Path(tmp) / "cti-mailer"
            b = subprocess.run(["go", "build", "-o", str(exe), "./cmd/cti-mailer"], cwd=ROOT,
                               check=False, capture_output=True, text=True)
            self.assertEqual(b.returncode, 0, b.stderr)
            r = subprocess.run([str(exe), "--lane", "owner", "--armed"], check=False,
                               capture_output=True, text=True,
                               env={"PATH": "/usr/bin:/bin", "HOME": tmp, "FLEET_HOME": tmp,
                                    "FLEET_ENV": str(pathlib.Path(tmp) / "none.env")})
            self.assertNotIn("say how to run it", r.stderr)
            self.assertNotEqual(r.returncode, 2, r.stdout + r.stderr)


class TestCompletionAnswers(unittest.TestCase):
    """The helper the wrapper and both completions call."""

    def run_usage(self, *args):
        return subprocess.run(
            [str(USAGE), *args], check=False, capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "CTI_AGENT_MANIFEST": str(MANIFEST)})

    def test_commands_complete_to_the_whole_list(self):
        r = self.run_usage("words")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(set(r.stdout.split()), set(parse()))

    def test_a_command_completes_to_its_flags(self):
        out = self.run_usage("words", "cti-mailbox", "2").stdout.split()
        self.assertIn("--dry-run", out)
        self.assertIn("--lookback", out)

    def test_a_subcommand_tool_completes_to_its_words_only_first(self):
        first = self.run_usage("words", "fleet-db", "2").stdout.split()
        later = self.run_usage("words", "fleet-db", "3").stdout.split()
        self.assertIn("recent", first)
        self.assertNotIn("recent", later)

    def test_show_names_what_the_command_does_to_the_world(self):
        out = self.run_usage("show", "cti-jira").stdout
        self.assertIn("usage: cti-agent cti-jira", out)
        self.assertIn("effect", out)

    def test_an_unknown_command_is_refused_and_completion_stays_quiet(self):
        self.assertEqual(self.run_usage("show", "nope").returncode, 2)
        quiet = self.run_usage("words", "nope", "2")
        self.assertEqual((quiet.returncode, quiet.stdout), (0, ""))

    def test_the_completions_are_valid_shell(self):
        for name, shell in (("cti-agent.bash", "bash"), ("_cti-agent", "zsh")):
            with self.subTest(file=name):
                if shutil.which(shell) is None:
                    self.skipTest(f"no {shell} here")
                r = subprocess.run([shell, "-n", str(ROOT / "fleet-kit" / "fleet" / "share" / name)],
                                   check=False, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


class TestCompletionDisplay(unittest.TestCase):
    """What the completions show beside each candidate: how risky it is, and
    whether it is required."""

    @classmethod
    def setUpClass(cls):
        cls.cmds = parse()

    def rows(self, *args):
        r = subprocess.run(
            [str(USAGE), "complete", *args], check=False, capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "CTI_AGENT_MANIFEST": str(MANIFEST)})
        self.assertEqual(r.returncode, 0, r.stderr)
        out = [ln.split("\t") for ln in r.stdout.splitlines()]
        for row in out:
            self.assertEqual(len(row), 6, row)
        return out

    def test_a_command_is_risky_as_its_class_says(self):
        want = {"read": "safe", "local": "writes", "effect": "changes"}
        for word, group, risk, *_ in self.rows():
            self.assertEqual(group, "command")
            self.assertEqual(risk, want[self.cmds[word]["runs"]], word)

    def test_the_mode_flags_are_required_and_classed(self):
        by = {r[0]: r for r in self.rows("cti-mailbox", "2")}
        self.assertEqual((by["--dry-run"][1], by["--dry-run"][2]), ("required", "safe"))
        self.assertEqual((by["--for-real"][1], by["--for-real"][2]), ("required", "changes"))
        self.assertEqual(by["--lookback"][1], "optional")
        by = {r[0]: r for r in self.rows("run-digest", "2")}
        self.assertEqual((by["--to-dev"][1], by["--to-dev"][2]), ("required", "writes"))

    def test_exempt_and_read_only_flags_are_safe(self):
        by = {r[0]: r for r in self.rows("cti-jira", "2")}
        self.assertEqual(by["--check"][2], "safe")
        self.assertEqual(by["--list"][2], "safe")
        for r in self.rows("cti-kev", "2"):
            self.assertEqual(r[2], "safe", r)

    def test_a_flag_with_a_risk_line_carries_it(self):
        by = {r[0]: r for r in self.rows("cti-patchtuesday", "2")}
        self.assertEqual(by["--mark-sent"][2], "writes")

    def test_subcommands_are_listed_only_as_the_first_word(self):
        self.assertTrue(any(r[1] == "sub" for r in self.rows("fleet-db", "2")))
        self.assertFalse(any(r[1] == "sub" for r in self.rows("fleet-db", "3")))

    def test_bash_lists_descriptions_and_risk_when_several_match(self):
        try:
            import pty
            import select
        except ImportError:
            self.skipTest("no pty here")
        bash = shutil.which("bash")
        if bash is None or not hasattr(pty, "fork"):
            self.skipTest("no bash or pty here")
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            rc = pathlib.Path(tmp) / "rc"
            comp = (ROOT / "fleet-kit" / "fleet" / "share" / "cti-agent.bash").read_text(
                encoding="utf-8").replace("@CODE_DIR@", str(ROOT / "fleet-kit" / "fleet"))
            rc.write_text(f"export CTI_AGENT_MANIFEST={MANIFEST}\n{comp}\n", encoding="utf-8")
            pid, fd = pty.fork()
            if pid == 0:  # pragma: no cover - the child
                os.environ.update(PS1="$ ", TERM="xterm", HOME=tmp)
                os.execvp(bash, [bash, "--norc", "--noprofile", "-i"])

            def read(t=0.8):
                out = b""
                while select.select([fd], [], [], t)[0]:
                    try:
                        d = os.read(fd, 4096)
                    except OSError:
                        break
                    if not d:
                        break
                    out += d
                return out.decode("utf8", "replace")

            read(1.0)
            os.write(fd, f". {rc}\n".encode())
            read(0.5)
            os.write(fd, b"cti-agent cti-mailbox --")
            read(0.5)
            os.write(fd, b"\t")
            read(0.5)
            os.write(fd, b"\t")
            shown = read(1.0)
            os.write(fd, b"\x03exit\n")
            os.close(fd)
            os.waitpid(pid, 0)
        self.assertIn("REQUIRED, one of; safe", shown)
        self.assertIn("REQUIRED, one of; CHANGES", shown)
        self.assertIn("show the plan and move nothing", shown)
        self.assertIn("--lookback DURATION", shown)


if __name__ == "__main__":
    unittest.main()
