"""scripts/sbom.py: the SBOM, and the proof that the fleet has no third-party code.

Run from fleet-kit: python3 -m unittest discover -s tests
"""
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sbom.py"


def load():
    spec = importlib.util.spec_from_file_location("sbom_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SbomBase(unittest.TestCase):
    def setUp(self):
        self.sbom = load()

    def tree(self, gomod, lanes=None, cmds=("cti-one",)):
        """A throwaway repo root for the script to read."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(d)])
        (d / "go.mod").write_text(gomod)
        for c in cmds:
            (d / "cmd" / c).mkdir(parents=True)
            (d / "cmd" / c / "main.go").write_text("package main\n")
        (d / "fleet-kit" / "fleet" / "lanes").mkdir(parents=True)
        for name, body in (lanes or {}).items():
            (d / "fleet-kit" / "fleet" / "lanes" / name).write_text(body)
        self.sbom.ROOT = str(d)
        return d



class Sbom(SbomBase):
    # ---- the real repository ------------------------------------------------

    def test_the_repository_follows_its_own_rule(self):
        """No third-party Go module and no third-party Python import. If this
        fails, a dependency was added: the CLAUDE.md rule is to push back."""
        r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_sbom_lists_every_command_and_says_what_it_rests_on(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "x.cdx.json"
            r = subprocess.run([sys.executable, str(SCRIPT), "--out", str(out), "--version", "9.9.9"],
                               capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            bom = json.loads(out.read_text())
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.5"))
        self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        apps = {c["name"] for c in bom["components"] if c["type"] == "application"}
        commands = {p.name for p in (ROOT / "cmd").iterdir() if (p / "main.go").exists()}
        self.assertTrue(commands <= apps, f"missing from the SBOM: {sorted(commands - apps)}")
        self.assertIn("fleet-kit-lanes", apps)
        libs = [c for c in bom["components"] if c["type"] == "library"]
        self.assertEqual([c["name"] for c in libs], ["go-standard-library"], "no third-party library is in use")
        # the fleet's own applications carry its version; the Claude CLI is host software with none
        self.assertTrue(all(c["version"] == "9.9.9" for c in bom["components"]
                            if c["type"] == "application" and c["name"] != "claude-code"))
        props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
        self.assertTrue(props["dependencies.third-party"].startswith("none"))
        self.assertIn("Claude Code", props["dependencies.third-party"], "the CLI the lanes run must not be hidden by 'none'")
        # every dependency edge points at a component that exists
        refs = {c["bom-ref"] for c in bom["components"]}
        for dep in bom["dependencies"]:
            self.assertIn(dep["ref"], refs)
            for target in dep["dependsOn"]:
                self.assertIn(target, refs)

    def test_the_same_tree_gives_the_same_sbom(self):
        a = self.sbom.build("1.0.0")
        b = self.sbom.build("1.0.0")
        for bom in (a, b):
            bom["metadata"].pop("timestamp")
        self.assertEqual(a, b)
        self.assertNotEqual(self.sbom.build("1.0.1")["serialNumber"], a["serialNumber"])

    # ---- the rule, on trees built to break it ------------------------------

    def test_a_go_dependency_is_refused(self):
        self.tree("module x\n\ngo 1.26\n\nrequire github.com/some/dep v1.2.3\n")
        with self.assertRaises(self.sbom.Rule) as cm:
            self.sbom.check()
        self.assertIn("github.com/some/dep v1.2.3", str(cm.exception))
        self.tree("module x\n\ngo 1.26\n\nrequire (\n\tgolang.org/x/text v0.3.0 // indirect\n)\n")
        with self.assertRaises(self.sbom.Rule):
            self.sbom.check()

    def test_a_third_party_python_import_is_refused_and_stdlib_and_local_are_not(self):
        self.tree("module x\n\ngo 1.26\n", lanes={
            "a.py": "import json, os\nfrom urllib.request import urlopen\nimport b\n",
            "b.py": "import yaml\n",
        })
        with self.assertRaises(self.sbom.Rule) as cm:
            self.sbom.check()
        self.assertIn("yaml", str(cm.exception))
        self.assertNotIn("json", str(cm.exception))
        self.assertEqual(list(self.sbom.third_party_imports()), ["yaml"])

    def test_an_extensionless_python_script_is_read_too(self):
        d = self.tree("module x\n\ngo 1.26\n")
        (d / "fleet-kit" / "fleet" / "bin").mkdir(parents=True)
        (d / "fleet-kit" / "fleet" / "bin" / "tool").write_text("#!/usr/bin/python3 -sE\nimport requests\n")
        self.assertEqual(list(self.sbom.third_party_imports()), ["requests"])

    def test_a_clean_tree_passes_and_has_no_libraries_but_the_standard_library(self):
        self.tree("module x\n\ngo 1.26\n", lanes={"a.py": "import json\n"})
        self.sbom.check()
        libs = [c["name"] for c in self.sbom.build("1.0.0")["components"] if c["type"] == "library"]
        self.assertEqual(libs, ["go-standard-library"])

    def test_a_dirty_run_exits_nonzero_and_writes_nothing(self):
        d = self.tree("module x\n\ngo 1.26\n\nrequire github.com/some/dep v1.2.3\n")
        out = d / "dist.json"
        rc = self.sbom.main(["--out", str(out)])
        self.assertEqual(rc, 1)
        self.assertFalse(out.exists())


class SbomFoundByReview(SbomBase):
    """Cases a reviewer showed could get third-party code past the first version
    of the check."""

    def test_an_indented_or_inline_require_is_still_a_dependency(self):
        for gomod in ("module x\n\ngo 1.26\n\n  require github.com/x/y v1.0.0\n",
                      "module x\n\ngo 1.26\n\n\trequire (\n\t\tgithub.com/x/y v1.0.0\n\t)\n",
                      'module x\n\ngo 1.26\n\nrequire "github.com/x/y" v1.0.0\n',
                      "module x\r\n\r\ngo 1.26\r\n\r\nrequire github.com/x/y v1.0.0\r\n"):
            self.tree(gomod)
            with self.assertRaises(self.sbom.Rule, msg=repr(gomod)) as cm:
                self.sbom.check()
            self.assertIn("github.com/x/y", str(cm.exception))

    def test_go_work_and_vendor_are_refused(self):
        d = self.tree("module x\n\ngo 1.26\n")
        (d / "go.work").write_text("go 1.26\n")
        with self.assertRaises(self.sbom.Rule):
            self.sbom.check()
        (d / "go.work").unlink()
        (d / "vendor").mkdir()
        with self.assertRaises(self.sbom.Rule):
            self.sbom.check()

    def test_a_module_in_another_directory_does_not_excuse_an_import(self):
        d = self.tree("module x\n\ngo 1.26\n", lanes={"a.py": "import requests\n"})
        (d / "fleet-kit" / "fleet" / "bin").mkdir(parents=True)
        (d / "fleet-kit" / "fleet" / "bin" / "requests.py").write_text("x = 1\n")  # not on lanes/'s path
        self.assertEqual(list(self.sbom.third_party_imports()), ["requests"])

    def test_the_scan_is_recursive(self):
        d = self.tree("module x\n\ngo 1.26\n")
        (d / "fleet-kit" / "fleet" / "lanes" / "sub").mkdir()
        (d / "fleet-kit" / "fleet" / "lanes" / "sub" / "deep.py").write_text("import yaml\n")
        (d / "scripts" / "hooks").mkdir(parents=True)
        (d / "scripts" / "hooks" / "hook.py").write_text("import numpy\n")
        self.assertEqual(sorted(self.sbom.third_party_imports()), ["numpy", "yaml"])

    def test_a_dynamic_import_cannot_be_checked_so_it_is_refused(self):
        self.tree("module x\n\ngo 1.26\n", lanes={
            "a.py": "m = __import__('requests')\n", "b.py": "import importlib\nimportlib.import_module('yaml')\n"})
        got = self.sbom.third_party_imports()
        self.assertEqual(list(got), ["<dynamic import>"])
        self.assertEqual(len(got["<dynamic import>"]), 2)
        with self.assertRaises(self.sbom.Rule):
            self.sbom.check()

    def test_python_inside_a_shell_script_is_scanned(self):
        d = self.tree("module x\n\ngo 1.26\n")
        (d / "fleet-kit" / "fleet" / "bin").mkdir(parents=True)
        (d / "fleet-kit" / "fleet" / "bin" / "run-x").write_text(
            "#!/usr/bin/env bash\npython3 -I - <<'PY'\nimport json\nimport requests\nPY\n"
            "python3 -c 'import sys; import yaml'\n"
            "python3 -c \"import os\"\n")
        self.assertEqual(sorted(self.sbom.third_party_imports()), ["requests", "yaml"])

    def test_standard_library_python_in_shell_is_fine(self):
        d = self.tree("module x\n\ngo 1.26\n")
        (d / "scripts").mkdir()
        (d / "scripts" / "ok.sh").write_text("#!/bin/sh\npython3 - <<'EOF'\nimport json, os\nfrom datetime import date\nEOF\n")
        self.assertEqual(self.sbom.third_party_imports(), {})

    def test_missing_tools_and_unparseable_files_are_one_clean_line_not_a_traceback(self):
        self.tree("module x\n\ngo 1.26\n", lanes={"broken.py": "def (:\n"})
        self.assertEqual(self.sbom.main(["--check"]), 1)
        d2 = self.tree("module x\n\ngo 1.26\n")
        orig = self.sbom.run

        def no_tools(*cmd):
            raise FileNotFoundError(cmd[0])
        self.sbom.run = no_tools
        try:
            self.assertEqual(self.sbom.main(["--check"]), 1, "go is needed to read go.mod")
            self.assertEqual(self.sbom.git_version(), "unknown")
            self.assertEqual(self.sbom.git_commit(), "")
        finally:
            self.sbom.run = orig
        self.assertTrue(d2.exists())

    def test_the_serial_differs_between_two_dirty_trees_at_one_commit(self):
        self.tree("module x\n\ngo 1.26\n")
        calls = iter(["diff one", "diff two"])
        self.sbom.tree_fingerprint = lambda: hashlib.sha256(next(calls).encode()).hexdigest()[:16]
        a, b = self.sbom.build("1.0.0"), self.sbom.build("1.0.0")
        self.assertNotEqual(a["serialNumber"], b["serialNumber"])

    def test_the_claude_cli_is_listed_as_what_the_lanes_execute(self):
        self.tree("module x\n\ngo 1.26\n")
        bom = self.sbom.build("1.0.0")
        names = {c["name"] for c in bom["components"]}
        self.assertIn("claude-code", names)
        lanes = [d for d in bom["dependencies"] if d["ref"].endswith("#fleet-kit-lanes")][0]
        self.assertIn("platform:claude-code", lanes["dependsOn"])


if __name__ == "__main__":
    unittest.main()
