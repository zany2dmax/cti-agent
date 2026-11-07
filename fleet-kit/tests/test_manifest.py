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
            cur = cmds[val] = {"about": "", "runs": "", "flags": {}, "subs": {}}
        elif cur is None:
            raise AssertionError(f"line {n}: {key!r} before any command")
        elif key in ("about", "runs"):
            cur[key] = val
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
        positional = {"fleet-board", "fleet-db", "fleet-owners", "cti-budget"}
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
            "cti-budget": ROOT / "cmd" / "cti-budget" / "main.go",
        }
        for name, path in files.items():
            text = path.read_text(encoding="utf-8")
            for sub in self.cmds[name]["subs"]:
                with self.subTest(command=name, sub=sub):
                    self.assertRegex(text, r"[\"'\s(|]" + re.escape(sub) + r"[\"')\s|:]",
                                     f"{name} has no {sub!r} subcommand")


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


if __name__ == "__main__":
    unittest.main()
