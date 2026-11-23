#!/usr/bin/env python3
"""Tests for the fleet lanes. Stdlib unittest only - no pip install.

    python3 -m unittest discover -s fleet-kit/tests -v
    task test:lanes

Network is never touched: the enrichment fetchers are stubbed, so these run
offline and deterministically. What they cover is the logic that decides what a
human sees - priority assignment, report parsing and digest rendering. The
mailer's gate is Go now (internal/mailer, cmd/cti-mailer) and tested there.
"""
import contextlib
import datetime
import fcntl
import json
import os
import pathlib
import re
import sys
import shlex
import shutil
import subprocess
import tempfile
import time
import unicodedata
import unittest

KIT = pathlib.Path(__file__).resolve().parents[1]
LANES = KIT / "fleet" / "lanes"


def _go_helpers_on_path():
    """cti-lock, which every runner's fleet_lock calls, built from this
    checkout and put on PATH: in a test the runners' bin/ holds stubs."""
    d = tempfile.mkdtemp(prefix="cti-test-bin-")
    names = ("cti-lock", "cti-checkin-check", "checkin-bash-guard", "fleet-trace")
    for name in names:
        subprocess.run(["go", "build", "-o", os.path.join(d, name), f"./cmd/{name}"],
                       cwd=KIT.parent, check=True, capture_output=True)
    os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
    return tuple(pathlib.Path(d) / n for n in names)


# A test that sets its own PATH copies these into its runner's bin/ instead.
# The guard and fleet-trace are the ones the box runs (cmd/), built here.
CTI_LOCK, CTI_CHECKIN_CHECK, GUARD_BIN, FLEET_TRACE_BIN = _go_helpers_on_path()


class DigestSendLedger(unittest.TestCase):
    """`was-sent` is the duplicate-send guard, and it never once fired.

    `fleet-db sent` read kind from args[6], the same index as the message id,
    so every row was stored with the Graph request id as its kind. was-sent
    queries by kind, so it always answered "no" - and UNIQUE(kind, day) never
    collided either, because each request id was unique.

    Exercised through the CLI rather than the function, because the bug was in
    positional argument parsing: a test that called the handler with keywords
    would have passed against the broken code.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "state"), exist_ok=True)
        self.env = dict(os.environ, FLEET_HOME=self.home)
        self.db = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "fleet", "bin", "fleet-db")

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def run_db(self, *args):
        return subprocess.run([sys.executable, self.db, *args],
                              env=self.env, capture_output=True, text=True, check=False)

    def test_a_sent_digest_is_remembered_as_its_kind(self):
        self.run_db("init")
        # Exactly how run-digest calls it: day, five counts, message id, kind.
        self.run_db("sent", "2026-10-01", "3", "2", "1", "0", "5",
                    "req-abc-123", "daily")
        r = self.run_db("was-sent", "2026-10-01", "daily")
        self.assertEqual(r.stdout.strip(), "yes",
                         "was-sent did not find a digest that was just logged")
        self.assertEqual(r.returncode, 0)

    def test_the_message_id_is_not_mistaken_for_the_kind(self):
        # The bug itself: the request id ended up in the kind column.
        self.run_db("init")
        self.run_db("sent", "2026-10-01", "0", "0", "0", "0", "0",
                    "req-abc-123", "daily")
        r = self.run_db("was-sent", "2026-10-01", "req-abc-123")
        self.assertEqual(r.stdout.strip(), "no",
                         "the message id is being stored as the kind")

    def test_weekly_and_daily_do_not_shadow_each_other(self):
        # UNIQUE(kind, day) only separates them if kind is real. With the bug
        # both landed under different request ids and neither was findable.
        self.run_db("init")
        self.run_db("sent", "2026-10-01", "1", "0", "0", "0", "0", "mid-1", "daily")
        self.assertEqual(self.run_db("was-sent", "2026-10-01", "daily").stdout.strip(), "yes")
        self.assertEqual(self.run_db("was-sent", "2026-10-01", "weekly").stdout.strip(), "no")
        self.run_db("sent", "2026-10-01", "1", "0", "0", "0", "0", "mid-2", "weekly")
        self.assertEqual(self.run_db("was-sent", "2026-10-01", "weekly").stdout.strip(), "yes")

    def test_an_unsent_day_is_still_no(self):
        self.run_db("init")
        r = self.run_db("was-sent", "2026-09-30", "daily")
        self.assertEqual(r.stdout.strip(), "no")
        self.assertNotEqual(r.returncode, 0, "a miss must exit non-zero for the shell guard")

    def test_last_sent_says_how_far_back_the_next_daily_must_read(self):
        # run-digest reads back to the last daily that went out, so a day the
        # daily failed is read by the next run instead of never.
        import sqlite3
        from datetime import datetime, timezone, timedelta
        self.run_db("init")
        self.assertEqual(self.run_db("last-sent", "daily", "--hours").returncode, 1,
                         "never sent must say so, not print 0")
        con = sqlite3.connect(os.path.join(self.home, "state", "memory.db"))
        for kind, ago in (("daily", 50.5), ("daily", 74), ("weekly", 1.5)):
            ts = (datetime.now(timezone.utc) - timedelta(hours=ago)).isoformat(timespec="seconds")
            con.execute("INSERT INTO digests(kind,day,ts) VALUES(?,?,?)",
                        (kind, f"d{ago}", ts))
        con.commit()
        con.close()
        r = self.run_db("last-sent", "daily", "--hours")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "51", "newest daily, whole hours rounded up")
        self.assertEqual(self.run_db("last-sent", "weekly", "--hours").stdout.strip(), "2")

    def test_run_digest_reads_back_to_the_last_daily(self):
        # The window rule itself, read from the runner: an operator's
        # --lookback wins, the configured window is the floor, and a week is
        # the cap.
        src = (pathlib.Path(self.db).parent / "run-digest").read_text(encoding="utf-8")
        block = src[src.index("READ BACK TO THE LAST DAILY"):src.index('say "ingest: reading')]
        self.assertIn('[ "$KIND" = daily ] && [ -z "$LOOKBACK" ]', block)
        self.assertIn('"$DB" last-sent daily --hours', block)  # the fallback
        self.assertIn('[ "$BEHIND_M" -gt $((CONF_H * 60 + 10)) ]', block)
        self.assertIn("CATCHUP_MAX_H=168", block)
        self.assertIn('[ "$CONF_H" -gt "$CATCHUP_MAX_H" ] && CATCHUP_MAX_H="$CONF_H"', block)
        self.assertIn('LOOKBACK="${WANT_M}m"', block)
        # Where the last sent daily started reading is saved only after its
        # send is recorded, so a dry run or a failed send never moves it.
        rec = src[src.index('"$DB" sent "$DAY"'):src.index('"$KIND digest sent: Sev5')]
        self.assertIn('"$READ_START_FILE"', rec)


class EverySendGoesThroughCtiMailer(unittest.TestCase):
    """Since 1.6.6 every runner sends through the Go cti-mailer, and the
    Python mailer.py was removed after 1.7.2. This keeps it from coming back."""

    def test_the_python_mailer_is_gone(self):
        self.assertFalse((LANES / "mailer.py").exists())

    def test_no_runner_calls_the_python_mailer(self):
        # The box's runners and the checkout's dev tools. Any mention on a
        # line that is not a comment counts, however the path is spelled.
        for d in (KIT / "fleet" / "bin", KIT / "bin"):
            for p in sorted(d.iterdir()):
                if not p.is_file():
                    continue
                src = p.read_text(encoding="utf-8", errors="replace")
                code = [l for l in src.splitlines() if not l.lstrip().startswith("#")]
                with self.subTest(script=f"{d.name}/{p.name}"):
                    self.assertEqual([l for l in code if "mailer.py" in l], [],
                                     f"{p.name} calls mailer.py; use cti-mailer")

    def test_the_digest_and_patch_tuesday_send_with_cti_mailer(self):
        for name in ("run-digest", "run-patchtuesday"):
            src = (KIT / "fleet" / "bin" / name).read_text(encoding="utf-8")
            with self.subTest(runner=name):
                self.assertRegex(src, r'RESULT=\$\("\$FLEET_CODE/bin/cti-mailer"\s+--html')


class ReleaseNotesAndWorkflow(unittest.TestCase):
    """A tag's GitHub Release takes its notes from CHANGELOG.md through
    scripts/release-notes.sh (.github/workflows/release.yml, RUNBOOK 11i)."""

    ROOT = KIT.parent
    SCRIPT = KIT.parent / "scripts" / "release-notes.sh"
    WORKFLOW = KIT.parent / ".github" / "workflows" / "release.yml"
    LOG = ("# Changelog\n\n## Unreleased\n\nnext\n\n---\n\n"
           "## 1.6.10 — 2026-12-01\n\nten\n\n---\n\n"
           "## 1.6.1 — 2026-11-09\n\n**Upgrade:** nothing.\n\n- one fix\n\n---\n\n"
           "## 1.6 — 2026-11-08\n\nsix\n\n## 1.5 — 2026-11-01\n\n")

    def notes(self, ver, text=None):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "CHANGELOG.md"
            f.write_text(self.LOG if text is None else text, encoding="utf-8")
            return subprocess.run(["bash", str(self.SCRIPT), ver, str(f)],
                                  capture_output=True, text=True, check=False)

    def test_a_version_gets_its_own_section_and_nothing_else(self):
        r = self.notes("1.6.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "**Upgrade:** nothing.\n\n- one fix\n")

    def test_a_shorter_version_is_not_matched_inside_a_longer_one(self):
        self.assertEqual(self.notes("1.6").stdout, "six\n")
        self.assertEqual(self.notes("1.6.1").stdout.count("ten"), 0)

    def test_a_v_prefix_on_the_tag_is_ignored(self):
        self.assertEqual(self.notes("v1.6.10").stdout, "ten\n")

    def test_a_version_with_no_section_or_an_empty_one_fails(self):
        for ver in ("1.6.7", "1.5"):
            with self.subTest(ver=ver):
                r = self.notes(ver)
                self.assertEqual(r.returncode, 1)
                self.assertEqual(r.stdout, "")
                self.assertIn("date its heading", r.stderr)

    def test_a_release_candidate_gets_its_own_section(self):
        text = self.LOG.replace("## 1.6.10", "## 2.0-rc1 \u2014 2026-12-02\n\ncandidate\n\n---\n\n## 1.6.10")
        self.assertEqual(self.notes("2.0-rc1", text).stdout, "candidate\n")
        self.assertEqual(self.notes("2.0", text).returncode, 1, "2.0 must not match the 2.0-rc1 heading")

    def test_something_that_is_not_a_version_is_refused(self):
        for ver in ("1.6.*", "Unreleased", "1.6.1; rm -rf /", "", "2.0-rc", "2.0-RC1", "2.0-rc1x"):
            with self.subTest(ver=ver):
                self.assertEqual(self.notes(ver).returncode, 2)

    def test_every_tagged_version_in_the_real_changelog_has_notes(self):
        text = (self.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = re.findall(r"^## (\d+(?:\.\d+){1,2}(?:-rc\d+)?) ", text, flags=re.M)
        self.assertIn("1.0", versions)
        for v in versions:
            with self.subTest(version=v):
                r = subprocess.run(["bash", str(self.SCRIPT), v, str(self.ROOT / "CHANGELOG.md")],
                                   capture_output=True, text=True, check=False)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_workflow_is_guarded(self):
        wf = self.WORKFLOW.read_text(encoding="utf-8")
        # Skipped in the company repo, which merges this file into its main.
        self.assertIn("if: github.repository == 'zany2dmax/cti-agent'", wf)
        self.assertIn("contents: write", wf)
        self.assertNotRegex(wf, r"(?m)^\s*-?\s*uses:", "no third-party actions")
        # Event data reaches the script as env, never spliced into it.
        run = wf[wf.index("run: |"):]
        self.assertNotIn("${{", run)
        self.assertIn("--verify-tag", run)
        self.assertIn("already exists - left as it is", run)
        self.assertIn('release-notes.sh" "$tag"', run)
        # The SBOM: made from the tag's tree, attached to the Release, run with a
        # scrubbed environment so the token is not in its reach.
        self.assertIn("scripts/sbom.py", run)
        self.assertIn(".cdx.json", run)
        self.assertIn("gh release upload", run)
        self.assertRegex(run, r'env -i PATH="\$PATH" HOME="\$RUNNER_TEMP" python3 "\$src/scripts/sbom\.py"')


class ReleaseWorkflowMakesTheSbom(unittest.TestCase):
    """The Release workflow's own script, run against a stubbed gh and a local
    git repo: a tag gets a Release WITH its SBOM; a manual run adds a missing
    SBOM to an existing Release and touches nothing else; a tag that broke the
    no-dependency rule gets no Release."""

    ROOT = KIT.parent
    TAG = "9.9.9"
    REPO = "zany2dmax/cti-agent"

    def setUp(self):
        wf = (self.ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        body = wf[wf.index("run: |\n") + len("run: |\n"):]
        self.script = "\n".join(l[10:] if l.startswith(" " * 10) else l for l in body.splitlines()) + "\n"
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "gh.log"
        self.runner = self.tmp / "runner"
        self.runner.mkdir()
        # what `gh api .../contents/F` returns: the real files
        self.contents = self.tmp / "contents"
        self.contents.mkdir()
        shutil.copy(self.ROOT / "scripts" / "release-notes.sh", self.contents / "release-notes.sh")
        shutil.copy(self.ROOT / "scripts" / "sbom.py", self.contents / "sbom.py")
        (self.contents / "CHANGELOG.md").write_text(f"# Changelog\n\n## {self.TAG} \u2014 2026-12-01\n\nthe notes\n\n---\n")
        gh = self.bin / "gh"
        gh.write_text(f"""#!/bin/bash
echo "gh $*" >> "{self.log}"
case "$1 $2" in
  "api repos/{self.REPO}/git/ref/tags/{self.TAG}") exit 0 ;;
  "release view")
      if [ "$GH_EXISTS" != 1 ]; then exit 1; fi
      case "$*" in *--json*) printf '%s\\n' $GH_ASSETS ;; esac
      exit 0 ;;
  "release create"|"release upload") exit 0 ;;
esac
case "$*" in
  *"/tags --paginate"*) echo "{self.TAG}"; exit 0 ;;
  *"contents/"*) all="$*"; f="${{all##*contents/}}"; f="${{f%%\\?*}}"; cat "{self.contents}/${{f##*/}}"; exit 0 ;;
esac
echo "gh stub: unhandled: $*" >&2; exit 9
""")
        gh.chmod(0o755)

    def repo(self, gomod="module x\n\ngo 1.26\n", with_script=True):
        """A local repo with one tag: the tree the workflow clones."""
        r = self.tmp / "origin"
        (r / "cmd" / "one").mkdir(parents=True)
        (r / "cmd" / "one" / "main.go").write_text("package main\n")
        (r / "go.mod").write_text(gomod)
        (r / "fleet-kit" / "fleet" / "lanes").mkdir(parents=True)
        (r / "fleet-kit" / "fleet" / "lanes" / "a.py").write_text("import json\n")
        if with_script:
            (r / "scripts").mkdir()
            shutil.copy(self.ROOT / "scripts" / "sbom.py", r / "scripts" / "sbom.py")
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "commit", "-q", "-m", "x"], ["git", "tag", "-a", self.TAG, "-m", "x"]):
            subprocess.run(cmd, cwd=r, env=env, check=True, capture_output=True)
        return r

    def run_workflow(self, origin, event="push", exists="0", assets=""):
        env = {
            # the same python3 the rest of the suite uses (the system one can be too old)
            "PATH": f"{self.bin}:{os.path.dirname(sys.executable)}:/usr/bin:/bin:" + os.path.dirname(shutil.which("go") or "/usr/bin/go"),
            "HOME": str(self.tmp), "GH_TOKEN": "SECRET-TOKEN", "REPO": self.REPO, "EVENT": event,
            "PUSHED_TAG": self.TAG, "INPUT_TAG": self.TAG, "SHA": "abc123", "RUNNER_TEMP": str(self.runner),
            "GH_EXISTS": exists, "GH_ASSETS": assets,
            # the workflow clones https://github.com/<repo>.git: point that at the local repo
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"url.file://{origin}.insteadOf",
            "GIT_CONFIG_VALUE_0": f"https://github.com/{self.REPO}.git",
        }
        return subprocess.run(["bash", "-c", self.script], env=env, capture_output=True, text=True,
                              timeout=120, check=False)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_the_script_parses_as_bash(self):
        r = subprocess.run(["bash", "-n", "-c", self.script], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_new_tag_gets_a_release_with_its_sbom_attached(self):
        r = self.run_workflow(self.repo())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        create = [c for c in self.calls() if c.startswith("gh release create")]
        self.assertEqual(len(create), 1, self.calls())
        self.assertIn(f"cti-agent-{self.TAG}.cdx.json", create[0], "the SBOM must be the release's asset")
        if "-rc" not in self.TAG:
            self.assertNotIn("--prerelease", create[0], "a final version is not a pre-release")
        sbom = self.runner / f"cti-agent-{self.TAG}.cdx.json"
        bom = json.loads(sbom.read_text())
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.5"))
        self.assertEqual(bom["metadata"]["component"]["version"], self.TAG)
        self.assertIn("one", {c["name"] for c in bom["components"]})
        notes = (self.runner / "notes.md").read_text()
        self.assertIn("the notes", notes)
        self.assertIn(f"cti-agent-{self.TAG}.cdx.json", notes)
        self.assertFalse([c for c in self.calls() if c.startswith("gh release upload")])

    def test_the_token_is_not_in_the_sbom_scripts_environment(self):
        origin = self.repo()
        # a tagged script that would leak the token if it could see it
        (origin / "scripts" / "sbom.py").write_text(
            "import os, sys\nopen(os.path.join(os.environ.get('RUNNER_TEMP','/tmp'),'leak'),'w').write(os.environ.get('GH_TOKEN','absent'))\n"
            "sys.argv=sys.argv\nimport runpy\n")
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        for cmd in (["git", "add", "-A"], ["git", "commit", "-q", "-m", "y"], ["git", "tag", "-f", "-a", self.TAG, "-m", "y"]):
            subprocess.run(cmd, cwd=origin, env=env, check=True, capture_output=True)
        self.run_workflow(origin)
        self.assertEqual((self.runner / "leak").read_text() if (self.runner / "leak").exists() else "absent", "absent",
                         "the SBOM script could see the workflow's token")

    def test_a_manual_run_adds_a_missing_sbom_to_an_existing_release_and_touches_nothing_else(self):
        r = self.run_workflow(self.repo(), event="workflow_dispatch", exists="1", assets="")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.calls()
        self.assertTrue([c for c in calls if c.startswith("gh release upload")], calls)
        self.assertIn(f"cti-agent-{self.TAG}.cdx.json", [c for c in calls if c.startswith("gh release upload")][0])
        self.assertFalse([c for c in calls if c.startswith("gh release create")], "an existing Release must not be recreated")
        self.assertFalse((self.runner / "notes.md").exists(), "an existing Release's notes must not be touched")

    def test_an_existing_release_that_has_its_sbom_or_a_push_is_left_alone(self):
        origin = self.repo()
        for event, assets in (("workflow_dispatch", f"cti-agent-{self.TAG}.cdx.json"), ("push", "")):
            self.log.unlink(missing_ok=True)
            r = self.run_workflow(origin, event=event, exists="1", assets=assets)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("already exists - left as it is", r.stdout)
            self.assertFalse([c for c in self.calls() if c.startswith(("gh release create", "gh release upload"))], event)

    def test_a_tag_older_than_the_script_is_read_with_the_script_from_the_run_commit(self):
        r = self.run_workflow(self.repo(with_script=False))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.runner / f"cti-agent-{self.TAG}.cdx.json").exists())
        self.assertTrue([c for c in self.calls() if "contents/scripts/sbom.py" in c], self.calls())

    def test_a_tag_that_broke_the_no_dependency_rule_gets_no_release(self):
        r = self.run_workflow(self.repo(gomod="module x\n\ngo 1.26\n\nrequire github.com/some/dep v1.2.3\n"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no-dependency rule", r.stdout + r.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith(("gh release create", "gh release upload"))], self.calls())



class ReleaseWorkflowForACandidate(ReleaseWorkflowMakesTheSbom):
    """The same workflow for a release candidate tag: every test above, and
    the Release is a pre-release that never takes the Latest badge."""

    TAG = "9.9.9-rc1"

    def test_a_candidate_is_a_prerelease_and_never_latest(self):
        r = self.run_workflow(self.repo())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        create = [c for c in self.calls() if c.startswith("gh release create")]
        self.assertEqual(len(create), 1, self.calls())
        self.assertIn("--prerelease", create[0])
        self.assertIn("--latest=false", create[0])


class RemediationNote(unittest.TestCase):
    """A ticketed finding must stop reporting as un-actioned.

    `findings --stale-days N` uses "remediation_note IS NULL" to decide what
    has been ignored, and nothing could write that column. So the orchestrator
    escalated three KEV CVEs as having "no remediation_note on any" on the same
    night their Jira tickets were filed.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "state"), exist_ok=True)
        self.env = dict(os.environ, FLEET_HOME=self.home)
        self.db = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "fleet", "bin", "fleet-db")
        self.run_db("init")
        self.run_db("finding", stdin=json.dumps({
            "cve": "CVE-2026-85046", "status": "PRESENT", "priority": "Sev5",
            "host_count": 227, "kev": 1,
        }))

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def run_db(self, *args, stdin=""):
        # stdin is explicit and ALWAYS supplied. `fleet-db finding` reads its
        # payload from stdin when no extra argv is given, so a test that
        # forgets this does not fail - it blocks forever waiting for input.
        # The timeout turns that into a visible failure rather than a hung
        # suite, which is how this was found.
        return subprocess.run([sys.executable, self.db, *args],
                              env=self.env, capture_output=True, text=True,
                              input=stdin, timeout=30, check=False)

    def findings(self, *extra):
        r = self.run_db("findings", *extra)
        return json.loads(r.stdout or "[]")

    def backdate(self, cve, **delta):
        """Age a row, writing the SAME string format the lane itself writes.

        Two things this has to get right, and the first version got neither.

        The timestamp must be ISO-8601 with a T and an offset, because that is
        what fleet-db's now() produces. Writing sqlite's own "YYYY-MM-DD
        HH:MM:SS" form instead cannot reproduce the off-by-a-day bug at all -
        the bug exists precisely because the two formats differ.

        And the age must not land exactly on the cutoff: --stale-days N asks
        for rows strictly older than N days ago, so a row aged exactly N days
        is correctly excluded. Testing on that boundary tests the comparison
        operator, not the behaviour.
        """
        import sqlite3
        stamp = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(**delta)).isoformat(timespec="seconds")
        db = os.path.join(self.home, "state", "memory.db")
        con = sqlite3.connect(db)
        con.execute("UPDATE findings SET updated=? WHERE cve=?", (stamp, cve))
        con.commit()
        con.close()

    def test_an_old_finding_is_stale_until_it_is_noted(self):
        # The whole point: before, a ticketed finding stayed on this list
        # forever, so the orchestrator kept reporting handed-off work as
        # ignored.
        self.backdate("CVE-2026-85046", days=5)
        self.assertEqual(len(self.findings("--stale-days", "2")), 1,
                         "a five-day-old un-noted finding should be stale")

        self.run_db("note", "CVE-2026-85046", "CR-1234 https://x/browse/CR-1234")
        self.assertEqual(len(self.findings("--stale-days", "2")), 0,
                         "a ticketed finding is still reported as un-actioned")

    def test_yesterdays_finding_is_not_missed_by_an_off_by_a_day_comparison(self):
        # `updated` is stored ISO-8601 with a T and an offset; sqlite's
        # datetime() yields "YYYY-MM-DD HH:MM:SS". Comparing them as raw
        # strings sorts the stored form above whenever the date portion
        # matches, because 'T' > ' ' - so --stale-days 1 silently skipped
        # everything from yesterday.
        # One second OLDER than the cutoff, so it falls on the same calendar
        # day as the cutoff - which is the only situation where the raw string
        # comparison goes wrong.
        self.backdate("CVE-2026-85046", days=1, seconds=1)
        self.assertEqual(len(self.findings("--stale-days", "1")), 1,
                         "a finding from yesterday was not counted as stale")

    def test_the_note_is_readable_not_just_a_flag(self):
        # Somebody reading the database row should get the ticket key, not
        # merely the knowledge that something happened.
        self.run_db("note", "CVE-2026-85046", "CR-1234 https://x/browse/CR-1234")
        row = self.findings()[0]
        self.assertIn("CR-1234", row["remediation_note"])
        self.assertIn("https://x/browse/CR-1234", row["remediation_note"])

    def test_the_nightly_upsert_does_not_clobber_the_note(self):
        # cti-enrich re-upserts every finding each night. If that wiped the
        # note, the orchestrator would resume nagging about ticketed work the
        # following morning and nobody would know why.
        self.run_db("note", "CVE-2026-85046", "CR-1234")
        self.run_db("finding", stdin=json.dumps({
            "cve": "CVE-2026-85046", "status": "PRESENT", "priority": "Sev5",
            "host_count": 346, "kev": 1,
        }))
        row = self.findings()[0]
        self.assertEqual(row["remediation_note"], "CR-1234",
                         "the nightly upsert wiped the remediation note")
        self.assertEqual(row["host_count"], 346, "the upsert did not apply")

    def test_a_note_for_an_unknown_cve_is_not_an_error(self):
        # cti-jira can file a ticket for a CVE the findings table has not seen
        # yet. Failing here would make a filed ticket look unfiled.
        r = self.run_db("note", "CVE-9999-0001", "CR-1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no finding", r.stdout)

    def test_a_note_can_be_cleared(self):
        self.run_db("note", "CVE-2026-85046", "CR-1234")
        self.run_db("note", "CVE-2026-85046")
        self.assertIsNone(self.findings()[0]["remediation_note"])
        self.backdate("CVE-2026-85046", days=5)
        self.assertEqual(len(self.findings("--stale-days", "2")), 1,
                         "clearing the note should make it stale again")


class DeadFeedsAreNamedAsDead(unittest.TestCase):
    """A feed that starts serving HTML must not be reported as malformed XML.

    msrc.microsoft.com/blog/feed began 302-ing to a human-readable page. For
    four days and twenty-four consecutive runs the lane logged the identical
    "mismatched tag: line 124, column 158" - a true statement about a stable
    HTML document and a thoroughly misleading one about the cause.

    That wording sends you looking for a bad byte in somebody's XML. The
    suggested fixes it invites - strip invalid characters, wait for the
    publisher - could never have worked, because the response was never XML.
    Every beat recorded it as "known, persists" and nobody re-read the error,
    because a line and column number is the most specific-looking thing in a
    log and reads as though the diagnosis is already done.

    Microsoft advisory coverage was dark for four days as a result.

    The parser is cti-scout's now, and so are its tests (cmd/cti-scout:
    TestMSRCBlogPageIsNotAFeed, the golden corpus, TestFetch): an HTML page is
    NOT A FEED, a BOM is not HTML, malformed XML still says so, a feed that
    declares entities is refused, and only https is fetched. What stays here is
    the feed list.
    """

    def test_the_dead_msrc_blog_feed_is_no_longer_polled(self):
        # Belt and braces: the URL is commented out in feeds.txt, and a future
        # edit that reinstates it should fail here rather than go dark again.
        feeds = (LANES / "feeds.txt").read_text(encoding="utf-8")
        live = [ln.strip() for ln in feeds.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertNotIn("https://msrc.microsoft.com/blog/feed", live)
        self.assertTrue(
            any("msrc.microsoft.com" in u or "microsoft.com" in u for u in live),
            "something must still cover Microsoft advisories")


class WeeklyRollsUpStoredFindings(unittest.TestCase):
    """The weekly covers a week, and says where its numbers came from.

    cti-agent-weekly.service runs run-digest with no --lookback, so the weekly
    read GRAPH_LOOKBACK_HOURS - the same 24 hours as the daily. It had never
    been a week. On 2026-10-05 both briefs reported reading the same four
    emails, an hour apart.

    Widening the mailbox read does not fix it: the cleanup lane archives
    advisories 48 hours after a completed run has read them, so a 7-day
    mailbox query sees only what happened not to be archived. That is a
    partial week presented as a whole one.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "state"), exist_ok=True)
        self.env = dict(os.environ, FLEET_HOME=self.tmp)
        self.db = str(LANES.parent / "bin" / "fleet-db")
        subprocess.run([sys.executable, self.db, "init"], env=self.env,
                       capture_output=True, check=True)
        self.seed()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self):
        import sqlite3
        from datetime import datetime, timezone, timedelta

        def iso(days):
            return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(
                timespec="seconds")

        con = sqlite3.connect(os.path.join(self.tmp, "state", "memory.db"))
        overdue = (datetime.now(timezone.utc) - timedelta(days=9)).date().isoformat()
        rows = [
            ("CVE-A", "PRESENT", "Sev5", 12, 1, overdue, iso(-2), iso(0)),
            ("CVE-B", "PRESENT", "Sev4", 3, 0, None, iso(-20), iso(-1)),
            # Untouched for a month: outside the window, must not appear.
            ("CVE-C", "NOT_PRESENT", "Sev1", 0, 0, None, iso(-30), iso(-25)),
        ]
        for cve, st, pr, hc, kev, due, fs, up in rows:
            con.execute(
                "INSERT OR REPLACE INTO findings(cve,status,priority,host_count,"
                "kev,kev_due,first_seen,updated) VALUES(?,?,?,?,?,?,?,?)",
                (cve, st, pr, hc, kev, due, fs, up))
        con.commit()
        con.close()

    def rollup(self, days=7):
        r = subprocess.run([sys.executable, self.db, "rollup", "--days", str(days)],
                           env=self.env, capture_output=True, text=True, check=True)
        return json.loads(r.stdout)

    def test_every_band_is_counted_even_when_empty(self):
        """run-digest logs counts['Sev5'] etc. after the send. A week with no
        Sev5 had no key, the step died with KeyError after the mail went out,
        and the send was never recorded - so a re-run would mail it twice."""
        counts = self.rollup()["counts"]
        for band in ("Sev5", "Sev4", "Sev3", "Sev2", "Sev1"):
            self.assertIn(band, counts)

    def test_the_window_excludes_findings_nothing_has_touched(self):
        cves = {f["cve"] for f in self.rollup()["findings"]}
        self.assertEqual(cves, {"CVE-A", "CVE-B"},
                         "a finding untouched for a month was included")

    def test_a_finding_still_open_from_before_is_not_called_new(self):
        by = {f["cve"]: f for f in self.rollup()["findings"]}
        self.assertTrue(by["CVE-A"]["is_new"], "first seen 2 days ago")
        self.assertFalse(by["CVE-B"]["is_new"],
                         "first seen 20 days ago - still open, but not new")

    def test_it_does_not_claim_to_have_read_a_mailbox(self):
        d = self.rollup()
        meta = d["source_meta"]
        self.assertIn("rollup", meta)
        self.assertIn("no mailbox read", meta["rollup"])
        for k in ("mailbox", "emails", "with_cves"):
            self.assertNotIn(k, meta,
                             f"{k} in a run that read no mail would report zero, "
                             f"which reads as 'the mailbox was empty'")

    def test_the_emails_read_section_is_absent_not_zero(self):
        # cti-brief drops the section when email_subjects is missing. Setting it
        # to [] would render "0 total", which is a different claim.
        self.assertNotIn("email_subjects", self.rollup())

    def test_deadlines_are_computed_the_same_way_the_daily_reports_them(self):
        kev = self.rollup()["kev_deadlines"]
        self.assertEqual(kev["overdue"], 1)
        self.assertEqual(kev["worst_overdue_days"], 9)

    def test_a_deadline_on_a_cve_not_found_here_is_not_overdue(self):
        # The weekly once counted every stored row with a passed date and said
        # "9 KEV deadlines OVERDUE" on weeks cti-kev said none (2026-11-09).
        import sqlite3
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        up = now.isoformat(timespec="seconds")
        past = (now - timedelta(days=30)).date().isoformat()
        soon = (now + timedelta(days=5)).date().isoformat()
        con = sqlite3.connect(os.path.join(self.tmp, "state", "memory.db"))
        for cve, st, hc, due in (("CVE-D", "NOT_PRESENT", 0, past),
                                 ("CVE-E", "UNKNOWN", 0, past),
                                 ("CVE-F", "PRESENT", 0, past),  # PRESENT, no hosts
                                 ("CVE-G", "PRESENT", 4, soon)):
            con.execute(
                "INSERT INTO findings(cve,status,priority,host_count,kev,kev_due,"
                "first_seen,updated) VALUES(?,?,'Sev3',?,1,?,?,?)",
                (cve, st, hc, due, up, up))
        con.commit()
        con.close()
        d = self.rollup()
        kev = d["kev_deadlines"]
        self.assertEqual(kev["overdue"], 1, kev)
        self.assertEqual(kev["overdue_cves"], ["CVE-A"])
        self.assertEqual(kev["due_within_14d"], 1)
        # The same answer the daily gives for the same rows: the rule in
        # internal/enrich kevSummary, restated here so fleet-db cannot drift
        # from it. Present (with hosts) and dated rows only.
        today = now.date()
        days = {f["cve"]: (datetime.fromisoformat(f["kev_due"][:10]).date() - today).days
                for f in d["findings"] if f.get("kev_due")
                and f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0}
        overdue = sorted(c for c, n in days.items() if n < 0)
        self.assertEqual(kev["overdue"], len(overdue))
        self.assertEqual(sorted(kev["overdue_cves"]), overdue)
        self.assertEqual(kev["due_within_14d"], sum(1 for n in days.values() if 0 <= n <= 14))
        self.assertEqual(kev["worst_overdue_days"], max([-n for n in days.values() if n < 0], default=0))

    def test_the_rendered_weekly_states_its_provenance(self):
        d = self.rollup()
        enriched = os.path.join(self.tmp, "enriched.json")
        with open(enriched, "w", encoding="utf-8") as f:
            json.dump(d, f)
        out = os.path.join(self.tmp, "w.html")
        # fleet-db (Python) writes the rollup, cti-brief (Go) renders it: the
        # one place the two meet, so it is tested across the languages.
        exe = os.path.join(self.tmp, "cti-brief")
        subprocess.run(["go", "build", "-o", exe, "./cmd/cti-brief"], cwd=KIT.parent,
                       capture_output=True, check=True)
        subprocess.run([exe, "--weekly", "--enriched", enriched, "--out", out],
                       capture_output=True, check=True)
        html = pathlib.Path(out).read_text(encoding="utf-8")
        self.assertIn("no mailbox read this run", html)
        self.assertNotIn("EMAILS READ THIS RUN", html)


class TestFileShape(unittest.TestCase):
    """Nothing may be defined after unittest.main().

    Four tests were appended below the main block and silently never ran:
    `python3 test_lanes.py` exits inside unittest.main() before the class is
    defined, so the suite reported 84 passing while 88 existed. They passed
    when run as `python3 -m unittest test_lanes.DigestSendLedger`, because
    importing the module defines everything first - which is exactly why it
    went unnoticed. Verifying with a different command than the gate uses
    proves nothing about the gate.
    """

    def test_every_script_is_executable_in_git(self):
        """install-fedora.sh lost its executable bit in a commit on 2026-10-12
        and `./fleet-kit/install-fedora.sh` stopped working - the box saw
        "Permission denied" as the installer having gone. The installer copies
        runners with -m 0755, so the box hid it for everything else."""
        root = KIT.parent
        try:
            out = subprocess.run(["git", "-C", str(root), "ls-files", "-s"],
                                 capture_output=True, text=True, timeout=30, check=True).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("not a git checkout")
        bad = []
        for line in out.splitlines():
            meta, _, path = line.partition("\t")
            mode = meta.split()[0]
            f = root / path
            try:
                with f.open("rb") as fh:
                    shebang = fh.read(2) == b"#!"
            except OSError:
                continue
            if shebang and mode != "100755":
                bad.append(path)
        self.assertEqual(bad, [], "git update-index --chmod=+x these")

    def test_runners_expand_arrays_safely_on_macos_bash(self):
        """macOS ships bash 3.2, where an EMPTY "${A[@]}" is an unbound
        variable under set -u. run-patchtuesday's "${MONTH_ARG[@]}" passed on
        the box (bash 5) for months and failed the first time a test ran the
        runner on the Mac. ${A[@]+"${A[@]}"} works on both."""
        bad = re.compile(r'(?<![+])"\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\}"')
        for path in sorted((KIT / "fleet" / "bin").glob("run-*")):
            with self.subTest(runner=path.name):
                hits = [f"{i}: {line.strip()}"
                        for i, line in enumerate(path.read_text().splitlines(), 1)
                        if bad.search(line.replace('[@]+"${', '[@]+"X{'))]
                self.assertEqual(hits, [], "use ${A[@]+\"${A[@]}\"} instead")

    def test_nothing_is_defined_after_the_main_block(self):
        src = pathlib.Path(__file__).read_text(encoding="utf-8")
        # Anchored at column 0: this test's own copy of the string is
        # indented, and index() on the bare string found it first, so every
        # class defined after this one failed the check.
        marker = '\nif __name__ == "__main__":'
        self.assertIn(marker, src)
        after = src[src.rindex(marker):]
        for kw in ("\nclass ", "\ndef "):
            self.assertNotIn(
                kw, after,
                f"a top-level {kw.strip()} appears after unittest.main() - "
                "it will never run under `python3 test_lanes.py`")

    def test_every_command_is_built_by_the_installer_and_the_taskfile(self):
        """A command nobody builds is a command nobody has.

        Both lists are hand-written. That is exactly how run-mailbox-cleanup
        shipped uninstalled for weeks: one place named the files by hand and
        another asserted they existed, and the two disagreed silently. The
        same shape applies to cmd/ - a new binary that the installer never
        builds produces "command not found" on the box, long after the commit
        that added it looked complete.

        This does not derive the lists, because restructuring the installer's
        build section is a riskier change than checking it. It makes the drift
        impossible to ship instead.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        cmds = sorted(p.name for p in (root / "cmd").iterdir()
                      if p.is_dir() and not p.name.startswith("."))
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        taskfile = (root / "Taskfile.yml").read_text(encoding="utf-8")

        missing = []
        for c in cmds:
            if f"./cmd/{c}" not in installer:
                missing.append(f"cmd/{c} is never built by fleet-kit/install-fedora.sh")
            if f"./cmd/{c}" not in taskfile:
                missing.append(f"cmd/{c} is never built by the Taskfile build target")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_the_first_deployment_steps_live_in_the_runbook(self):
        """The installer used to end with seven numbered steps, on every run.

        On a box where the fleet already runs, that told the operator "No timer
        is enabled yet" after an upgrade. The steps now live once, in RUNBOOK
        section 9, and the installer points there: it says the fleet is running
        when any timer is enabled, and names the section on a new box.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        runbook = (root / "RUNBOOK.md").read_text(encoding="utf-8")
        self.assertNotIn("Enable ONLY the daily digest", installer,
                         "the steps belong in RUNBOOK section 9, not the installer")
        self.assertIn("The fleet is running", installer)
        self.assertIn("RUNBOOK.md section 9", installer)
        section = runbook.split("## 9. Enabling the timers, in order", 1)[1].split("\n## 10.", 1)[0]
        for step in ("### On a new deployment", "sudo cti-agent cti-mailer --check",
                     "sudo cti-agent run-digest daily --dry-run",
                     "sudo systemctl enable --now cti-agent-digest.timer",
                     "sudo systemctl enable --now cti-agent-checkin.timer",
                     "sudo systemctl enable --now cti-agent-scout.timer cti-agent-weekly.timer",
                     "sudo cti-agent run-patchtuesday --month",
                     "sudo systemctl enable --now cti-agent-mailbox.timer",
                     "sudo ausearch -m avc -ts recent"):
            self.assertIn(step, section, f"RUNBOOK section 9 lost: {step}")

    def test_every_shipped_timer_is_in_the_runbook_enable_order(self):
        """RUNBOOK section 9's table is the order and the gate for each timer.

        It listed 9 of the 11 timers: vmscan and supplier were documented
        further down but never given a place in the order, so an operator
        enabling lanes from the table would never turn them on.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        runbook = (root / "RUNBOOK.md").read_text(encoding="utf-8")
        table = runbook.split("### Every timer, and its gate", 1)[1].split("```", 1)[0]
        shipped = sorted(t.name for t in (root / "fleet-kit" / "fleet" / "systemd-fedora").glob("*.timer"))
        self.assertTrue(shipped, "no timers found - the path moved")
        missing = [t for t in shipped if f"| `{t}` |" not in table]
        self.assertEqual(missing, [], "timers missing from RUNBOOK section 9's table")

    def test_the_vmscan_day_setting_takes_day_names_only(self):
        """FLEET_VMSCAN_DAY goes into an OnCalendar line, so only day names pass.

        The check is run as the installer runs it, from the installer's own
        lines, so the test cannot drift from what ships.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        self.assertIn('"cti-agent-vmscan.timer:$VMSCAN_DAY *-*-* $VMSCAN_AT"', installer)
        dayre = [l.strip() for l in installer.splitlines() if l.strip().startswith("_dayre=")]
        self.assertEqual(len(dayre), 1, "expected one _dayre= line in the installer")
        check = dayre[0] + '\nprintf %s "$1" | grep -Eqx "${_dayre}(,${_dayre})*"'
        def ok(value):
            return subprocess.run(["bash", "-c", check, "check", value], check=False).returncode == 0
        for good in ("Mon", "Fri", "Sun", "Mon,Fri", "Tue,Wed,Thu"):
            self.assertTrue(ok(good), good)
        for bad in ("", "fri", "Friday", "Fri ", "Fri,", "Fri *-*-* 00:00", "Fri;reboot", "Mon,,Fri"):
            self.assertFalse(ok(bad), repr(bad))

    def test_no_unquoted_heredoc_in_the_installer_runs_a_command(self):
        """The wrapper's heredoc is unquoted so it can expand $FLEET_USER and the
        paths, which means a backtick or $( inside it is a command substitution that
        RUNS at install time. A comment saying `cti-agent` ran cti-agent on every
        install since 1.6.1, and when the file found through PATH was a stale copy,
        unexecutable, or being written, the install stopped at the wrapper with
        "Text file busy" or "Permission denied". Backticks in an unquoted heredoc
        must be escaped (\\`)."""
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        bad = []
        for m in re.finditer(r"<<-?(?P<w>[A-Z_]+)\n(?P<body>.*?)\n(?P=w)\n", installer, re.S):
            for n, line in enumerate(m.group("body").splitlines(), 1):
                if re.search(r"(?<!\\)`", line):
                    bad.append(f"<<{m.group('w')} line {n}: {line.strip()[:70]}")
        self.assertEqual(bad, [], "unescaped backtick inside an unquoted heredoc")

    def test_the_wrapper_and_updater_are_replaced_by_rename_not_overwritten(self):
        """`cat > /usr/local/bin/cti-agent` truncates the file in place, and Linux
        refuses ("Text file busy") while anything is executing it, which stopped
        an update part-way. The installer now writes a temporary file beside it and
        renames it over, so a running command keeps its old copy. replace_file is
        run here from the installer's own text; the old file is held open for
        execution (a copy of sleep), which is what makes a plain overwrite fail on
        Linux; the rename must work either way and leave nothing behind."""
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        m = re.search(r"replace_file\(\) \{.*?\n\}\n", installer, re.S)
        self.assertIsNotNone(m, "replace_file is not in the installer")
        for dest in ("/usr/local/bin/cti-agent <<WRAP", "/usr/local/sbin/cti-agent-update <<UPDATER"):
            self.assertIn("replace_file " + dest.split()[0] + " 0755 " + dest.split()[1], installer)
            self.assertNotIn("cat > " + dest.split()[0], installer)
        with tempfile.TemporaryDirectory() as d:
            busy = pathlib.Path(d) / "cti-agent"
            shutil.copy("/bin/sleep", busy)
            busy.chmod(0o755)
            proc = subprocess.Popen([str(busy), "30"])
            try:
                time.sleep(0.3)
                r = subprocess.run(["bash", "-c", m.group(0) + '\nprintf "new\\n" | replace_file "$1" 0755',
                                    "x", str(busy)], capture_output=True, text=True, check=False)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(busy.read_text(), "new\n")
                self.assertEqual(busy.stat().st_mode & 0o777, 0o755)
                self.assertEqual(sorted(p.name for p in pathlib.Path(d).iterdir()), ["cti-agent"],
                                 "a temporary file was left behind")
            finally:
                proc.kill()
                proc.wait()

    def test_a_disabled_timer_is_reported_once(self):
        """`systemctl is-enabled` prints its state AND exits non-zero.

        The installer's `... || echo disabled` therefore printed "disabled"
        twice, on two lines, for every disabled timer in its Timer status.
        unit_state is run here, from the installer's own text, against a fake
        systemctl that behaves like the real one.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        m = re.search(r"^unit_state\(\) \{\n.*?^\}\n", installer, re.S | re.M)
        self.assertIsNotNone(m, "unit_state() not found in the installer")
        # The helper and the comment above it are the only place it may appear.
        start = installer.rfind("\n\n", 0, m.start()) + 2
        outside = installer[:start] + installer[m.end():]
        self.assertNotIn("systemctl is-enabled", outside,
                         "call unit_state, not systemctl is-enabled, so the state is read one way")
        with tempfile.TemporaryDirectory() as d:
            fake = pathlib.Path(d) / "systemctl"
            fake.write_text('#!/bin/sh\ncase "$2" in\n'
                            '  on.timer) echo enabled; exit 0 ;;\n'
                            '  off.timer) echo disabled; exit 1 ;;\n'
                            '  *) echo "Failed to get unit file state" >&2; exit 1 ;;\n'
                            'esac\n', encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"])
            for unit, want in (("on.timer", "enabled"), ("off.timer", "disabled"),
                               ("gone.timer", "not-found")):
                out = subprocess.run(["bash", "-c", m.group(0) + 'unit_state "$1"', "t", unit],
                                     capture_output=True, text=True, env=env, check=False)
                self.assertEqual(out.stdout, want, unit)

    def test_the_hosts_fleet_env_names_are_checked_after_config(self):
        """The installer said "checked after config" and never checked.

        It printed "also needed: your Qualys pod (QUALYS_BASE_URL) - checked
        after config", and nothing after config looked at QUALYS_BASE_URL, Jira
        or any other host fleet.env names. Now a section after config does. Its
        helpers run here from the installer's own text: a host comes out of a
        URL, a placeholder or anything that is not a plain host name is never
        dialled (the installer runs as root, and the value comes from a file),
        and a real host is.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        installer = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        # One connectivity section, after config (2026-11-19: it used to be
        # split, the fixed hosts long before the ones fleet.env names).
        self.assertEqual(installer.count('bold "Outbound connectivity'), 1,
                         "every connectivity check belongs in the one section")
        section = installer.find('bold "Outbound connectivity"')
        config = installer.find('if [ -f "$CONF_DIR/fleet.env" ]; then')
        self.assertGreater(section, config, "connectivity is checked after config")
        self.assertGreater(installer.find("graph.microsoft.com", section), section,
                           "the fixed hosts are checked in that section too")
        self.assertGreater(installer.find('reach_cfg "Qualys pod"', section), section)
        self.assertNotIn('bash -c "</dev/tcp/$', installer,
                         "pass the host to bash as an argument, never inside the -c string")
        helpers = ""
        for name in ("urlhost", "reach_cfg"):
            m = re.search(r"^%s\(\) \{\n.*?^\}\n" % name, installer, re.S | re.M)
            self.assertIsNotNone(m, name + "() not found in the installer")
            helpers += m.group(0)
        stubs = ('ok() { echo "ok $*"; }\ninfo() { echo "info $*"; }\nwarn() { echo "warn $*"; }\n'
                 'reach() { echo "DIAL $1 ${2:-443}"; }\n')

        def sh(call, *args):
            return subprocess.run(["bash", "-c", stubs + helpers + call, "t", *args],
                                  capture_output=True, text=True, check=False).stdout

        for url, host in (("https://qualysapi.qg3.apps.qualys.com", "qualysapi.qg3.apps.qualys.com"),
                          ("https://qualysapi.qualys.com/api/2.0/", "qualysapi.qualys.com"),
                          ("https://api.us-2.crowdstrike.com:443/x?y=1", "api.us-2.crowdstrike.com"),
                          ("api.godaddy.com", "api.godaddy.com"), ("", "")):
            self.assertEqual(sh('urlhost "$1"', url), host, url)
        self.assertEqual(sh('reach_cfg Jira "$1"', "acme.atlassian.net"), "DIAL acme.atlassian.net 443\n")
        self.assertEqual(sh('reach_cfg Jira "$1"', ""), "")
        for placeholder in ("yourorg.atlassian.net", "qualysapi.example.com", "<pod>"):
            out = sh('reach_cfg X "$1"', placeholder)
            self.assertNotIn("DIAL", out, placeholder)
            self.assertIn("placeholder", out, placeholder)
        for bad in ("a.com;reboot", "$(id)", "a b", "-oProxyCommand=x", "a.com/../x", "a`id`"):
            out = sh('reach_cfg X "$1"', bad)
            self.assertNotIn("DIAL", out, bad)
            self.assertTrue(out.startswith("warn") or out.startswith("info"), (bad, out))

    def test_every_runner_sources_fleet_env(self):
        """The runners load the config; the Go binaries only read the environment.

        internal/config reads os.Getenv and never opens fleet.env. The
        `sudo cti-agent` wrapper passes FLEET_ENV through --preserve-env and
        strips everything else, so credentials can only reach a lane if its
        runner sources the file.

        run-appscan did not, and cti-appscan reported "missing required
        environment variables: CLIENT_ID CLIENT_SECRET GRAPH_MAILBOX
        TENANT_ID" on a box where all four were set. The error was accurate
        and pointed at the wrong thing - it reads as a fleet.env problem when
        the file was fine and the runner never read it.

        An unwritten convention that four runners follow and the fifth does
        not is a convention waiting to be broken again.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        missing = []
        for runner in sorted((root / "fleet-kit" / "fleet" / "bin").glob("run-*")):
            text = runner.read_text(encoding="utf-8")
            if ". \"$FLEET_ENV\"" not in text:
                missing.append(f"{runner.name} never sources fleet.env, so any "
                               f"binary it calls runs without credentials")
            elif "_inj_home" not in text:
                missing.append(f"{runner.name} sources fleet.env without "
                               f"preserving the injected FLEET_HOME, so a stale "
                               f"value in the config file would redirect its output")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_every_systemd_timer_has_a_service_and_a_runner(self):
        """A timer pointing at nothing fires and fails, or fires and does nothing.

        Each .timer must name a .service that exists, and that service's
        ExecStart must point at a runner that is actually in the kit, or at a
        Go command in cmd/ that the installer builds (cti-scout).
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        units = root / "fleet-kit" / "fleet" / "systemd-fedora"
        problems = []
        for timer in sorted(units.glob("*.timer")):
            service = units / (timer.stem + ".service")
            if not service.exists():
                problems.append(f"{timer.name} has no matching .service")
                continue
            m = re.search(r"^ExecStart=(.+)$", service.read_text(encoding="utf-8"), re.M)
            if not m:
                problems.append(f"{service.name} has no ExecStart")
                continue
            # Every token, not just the first: a unit that ran an interpreter
            # ("/usr/bin/python3 .../scout.py", until cti-scout) names the
            # thing that must exist as an argument, not the program.
            kit = root / "fleet-kit" / "fleet"
            inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
            found = any(
                (kit / "bin" / pathlib.Path(tok).name).exists()
                or ((root / "cmd" / pathlib.Path(tok).name).is_dir()
                    and f"./cmd/{pathlib.Path(tok).name} )" in inst)
                for tok in m.group(1).split()
            )
            if not found:
                problems.append(
                    f"{service.name} runs {m.group(1)!r}, none of which is in "
                    f"fleet/bin/ or a Go command the installer builds")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    # ── the orchestrator's grant, and what its instructions say ─────────────

    @staticmethod
    def _orchestrator_grant():
        """The --allowedTools rules run-checkin passes, with $FLEET_CODE literal.

        Executes run-checkin's own assignment block rather than re-parsing it,
        so a loop or a conditional in the grant is evaluated the way bash
        evaluates it - a regex over the file is how a grant and a test about
        the grant quietly start describing different things.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "fleet-kit" / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        start = src.index('ALLOWED_TOOLS=""')
        end = src.index('echo "[run-checkin', start)
        block = src[start:end]
        out = subprocess.run(
            ["bash", "-c", "FLEET_CODE='$FLEET_CODE'\n" + block + '\nprintf "%s" "$ALLOWED_TOOLS"'],
            capture_output=True, text=True, check=True).stdout
        return [r for r in out.split(",") if r]

    @staticmethod
    def _allowed(rules, command):
        """Claude Code's Bash rule semantics: Bash(P:*) is a prefix, Bash(P) exact."""
        command = " ".join(command.split())
        for r in rules:
            m = re.fullmatch(r"Bash\((.*)\)", r)
            if not m:
                continue
            pat = m.group(1)
            if pat.endswith(":*"):
                if command.startswith(pat[:-2]):
                    return True
            elif command == pat:
                return True
        return False

    @staticmethod
    def _commands_in(text):
        """Commands an instruction file tells the agent to run.

        Backticked spans and fenced-code lines that start with $FLEET_CODE/,
        python3, journalctl or systemctl - with backslash continuations
        joined. `sudo cti-agent ...` is the operator's form and is not
        matched, which is the point: it is how an instruction names a command
        for a person rather than for the agent.
        """
        found = []
        start = re.compile(r'^"?(\$FLEET_CODE/|python3 |(/usr/bin/)?journalctl|(/usr/bin/)?systemctl )')
        for block in re.findall(r"```[^\n]*\n(.*?)```", text, re.S):
            joined = re.sub(r"\\\n\s*", " ", block)
            for line in joined.split("\n"):
                line = line.split("  #")[0].strip()
                if start.match(line):
                    found.append(line.replace('"$FLEET_CODE', "$FLEET_CODE").replace('fleet-db"', "fleet-db"))
        # Prose, not tables. A table row naming a script is a description -
        # the lanes table lists what the timers run - and the On a beat
        # column has its own test below.
        prose = re.sub(r"```.*?```", "", text, flags=re.S)
        prose = "\n".join(l for l in prose.split("\n") if not l.lstrip().startswith("|"))
        for span in re.findall(r"`([^`\n]+)`", prose):
            if start.match(span):
                found.append(span)
        # Placeholders are arguments, not part of the command's identity.
        return [re.split(r"\s[\[<…]|\s\.\.\.", c)[0].strip() for c in found]

    def test_the_heartbeat_cannot_edit_files(self):
        """A beat reads untrusted advisories and mail; it must not write files.

        It ran with --permission-mode acceptEdits, which auto-approves Edit and
        Write, though nothing in /checkin writes a file. A security scan showed
        the chain: a hostile message steers the beat, the beat rewrites a runner
        it can write, and the next timer run executes it. The grant is gone and
        the edit tools are disallowed by name.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "fleet-kit" / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        code = "\n".join(l for l in src.split("\n") if not l.lstrip().startswith("#"))
        self.assertNotIn("acceptEdits", code)
        self.assertNotIn("bypassPermissions", code)
        self.assertIn('--disallowedTools "$DISALLOWED_TOOLS"', code)
        m = re.search(r'^DISALLOWED_TOOLS="([^"]*)"', code, re.M)
        self.assertIsNotNone(m)
        self.assertEqual(set(m.group(1).split(",")), {"Edit", "Write", "NotebookEdit"})
        self.assertFalse(any(r.split("(")[0] in ("Edit", "Write", "NotebookEdit")
                             for r in self._orchestrator_grant()))

    def _checkin_box(self, overrides=None, plant=(), claude_json=None,
                     guard="#!/bin/sh\ncat >/dev/null\nexit 2\n", settings=None, extra_env=None,
                     trace=False, stream=None, claude_rc=0, verdict=None, home_files=None):
        """A fake Linux box for run-checkin: a FLEET_CODE laid out the way
        install-fedora.sh lays it out, read-only to this test's user, and a
        fake stat(1) that reports root ownership unless told otherwise.

        overrides maps a path relative to the box to {"u": uid, "a": mode} for
        stat to report, so a single wrong entry can be tested on its own.
        plant lists paths relative to HOME to create before the run.
        trace installs the real fleet-trace and a cti-budget stub; stream is
        the stream-json the fake claude prints when asked for it, and
        claude_rc its exit status. verdict, when given, is the body of a fake
        cti-checkin-verdict; home_files maps paths under HOME to their content.
        Returns (CompletedProcess, what the fake claude and fleet-board saw).
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        self.addCleanup(subprocess.run, ["chmod", "-R", "u+w", str(d)])
        code, home, fake, tmp = d / "code", d / "home", d / "fakebin", d / "tmp"
        for p in (code / "bin", code / "share",
                  code / "orchestrator" / ".claude" / "skills" / "checkin",
                  home, fake, tmp):
            p.mkdir(parents=True)
        ran = d / "ran"
        shutil.copy(root / "fleet-kit" / "fleet" / "bin" / "run-checkin", code / "bin" / "run-checkin")
        # Sourced by every runner that changes something (the "say how" rule).
        shutil.copy(root / "fleet-kit" / "fleet" / "share" / "fleet-mode.sh",
                    code / "share" / "fleet-mode.sh")
        # The model-lane library (HARNESS H4): sourced next to it.
        shutil.copy(root / "fleet-kit" / "fleet" / "share" / "model-lane.sh",
                    code / "share" / "model-lane.sh")
        for name in ("fleet-board", "fleet-db", "fleet-journal", "cti-alert") + (
                ("cti-budget",) if trace else ()):
            (code / "bin" / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{ran}"\n')
        # The real checks (settings, steering, trips), built from this checkout.
        shutil.copy(CTI_CHECKIN_CHECK, code / "bin" / "cti-checkin-check")
        if trace:
            shutil.copy(FLEET_TRACE_BIN, code / "bin" / "fleet-trace")
        if verdict is not None:
            (code / "bin" / "cti-checkin-verdict").write_text(
                f'#!/bin/sh\necho "cti-checkin-verdict $*" >> "{ran}"\n{verdict}')
        for rel, body in (home_files or {}).items():
            (home / rel).parent.mkdir(parents=True, exist_ok=True)
            (home / rel).write_text(body)
        stream_file = d / "stream.jsonl"
        stream_file.write_text("".join(json.dumps(e) + "\n" if isinstance(e, dict) else e + "\n"
                                       for e in (stream or [])))
        # run-checkin pipes a redirect through the guard and wants exit 2.
        (code / "bin" / "checkin-bash-guard").write_text(guard)
        (code / "checkin-settings.json").write_text(json.dumps(settings if settings is not None else {
            "disableAllHooks": False, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": f"{code}/bin/checkin-bash-guard"}]}]}}) + "\n")
        (code / "orchestrator" / "CLAUDE.md").write_text("# test\n")
        (code / "orchestrator" / ".claude" / "skills" / "checkin" / "SKILL.md").write_text("# test\n")
        (fake / "claude").write_text(
            f'#!/bin/sh\n{{ echo "claude cwd=$PWD"; for a; do echo "arg $a"; done; }} >> "{ran}"\n'
            f'case " $* " in *" --output-format stream-json "*) cat "{stream_file}";; esac\n'
            f'exit {int(claude_rc)}\n')
        (fake / "uname").write_text("#!/bin/sh\necho Linux\n")
        (fake / "python3").symlink_to(sys.executable)
        table = d / "stat.json"
        table.write_text(json.dumps({str(d / k): v for k, v in (overrides or {}).items()}))
        # stat -L -c FMT PATH, as run-checkin calls it. Ownership from the
        # table (default root), mode and mtime from the real file.
        (fake / "stat").write_text(f"""#!{sys.executable}
import json, os, sys
args = [a for a in sys.argv[1:] if a != "-L"]
fmt, path = args[args.index("-c") + 1], args[-1]
st = os.stat(path)
o = json.load(open({str(table)!r})).get(path, {{}})
print({{"%u": o.get("u", 0), "%a": o.get("a", format(st.st_mode & 0o7777, "o")),
        "%Y": int(st.st_mtime)}}[fmt])
""")
        for rel in plant:
            p = home / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}\n" if rel.endswith(".json") else "planted\n")
        if claude_json is not None:
            (home / ".claude.json").write_text(json.dumps(claude_json))
        for f in fake.iterdir():
            if not f.is_symlink():
                f.chmod(0o555)
        # Read-only to us, which is what "writable by nobody else, us
        # included" means for a non-root test. Files first, then directories.
        for p in sorted(code.rglob("*"), key=lambda p: -len(p.parts)):
            p.chmod(0o555 if p.is_dir() or p.parent.name == "bin" else 0o444)
        code.chmod(0o555)
        env = {"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(home),
               "FLEET_HOME": str(home), "FLEET_CODE": str(code),
               "FLEET_ENV": str(d / "none.env"), "TMPDIR": str(tmp),
               "CLAUDE_BIN": str(fake / "claude"),
               "ANTHROPIC_API_KEY": "test-placeholder"}
        env.update(extra_env or {})
        r = subprocess.run(["bash", str(code / "bin" / "run-checkin"), "--for-real"], env=env,
                           capture_output=True, text=True, check=False)
        return r, (ran.read_text() if ran.exists() else "")

    def test_the_heartbeat_refuses_to_run_code_the_service_can_write(self):
        """run-checkin fails closed when its code is not root-owned.

        Each case leaves the rest of the box correct and gets one entry wrong,
        so the refusal is about that entry - including the $FLEET_CODE/bin/*
        commands the beat is granted, and the orchestrator files that steer
        it. It must exit 1 before it posts to the board or starts claude -
        both of which would be running the very files that failed.
        """
        for rel, bad in (
            ("code/bin/run-checkin", {"u": 1000}),
            ("code/bin", {"a": "775"}),
            ("code/bin/fleet-db", {"u": 1000}),
            ("code/bin/fleet-journal", {"a": "557"}),
            ("code/bin/cti-alert", {"a": "575"}),
            ("code/checkin-settings.json", {"u": 1000}),
            ("code/orchestrator", {"u": 1000}),
            ("code/orchestrator/CLAUDE.md", {"a": "666"}),
            ("code/orchestrator/.claude/skills/checkin/SKILL.md", {"u": 1000}),
            ("fakebin/claude", {"u": 1000}),
        ):
            with self.subTest(path=rel):
                r, ran = self._checkin_box(overrides={rel: bad})
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("REFUSING to start", r.stderr)
                self.assertIn(rel.split("/")[-1], r.stderr)
                self.assertNotIn("claude cwd", ran)
                self.assertNotIn("fleet-board", ran)

    def test_the_heartbeat_refuses_a_guard_that_would_fail_open(self):
        """A hook that exits anything but 2 lets the call through, so a guard
        that is unwired, switched off, or cannot run is no guard."""
        for label, kw in (
            ("guard allows", {"guard": "#!/bin/sh\ncat >/dev/null\nexit 0\n"}),
            ("guard crashes", {"guard": "#!/no/such/python\n"}),
            ("hooks disabled", {"settings": {"disableAllHooks": True}}),
            ("no hook", {"settings": {"disableAllHooks": False}}),
            ("wrong matcher", {"settings": {"disableAllHooks": False, "hooks": {"PreToolUse": [
                {"matcher": "Read", "hooks": [{"type": "command", "command": "x"}]}]}}}),
        ):
            with self.subTest(label):
                r, ran = self._checkin_box(**kw)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("REFUSING to start", r.stderr)
                self.assertNotIn("claude cwd", ran)

    def test_the_heartbeat_starts_on_a_correct_layout(self):
        """The check must also let a correct box beat - a fail-closed check
        that refuses everything looks exactly like one that works, until the
        heartbeat has been silent for a day. And when it does beat, claude
        runs in the root-owned orchestrator dir with project settings only,
        the root-owned settings file and no MCP servers."""
        r, ran = self._checkin_box()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = ran.splitlines()
        self.assertTrue(any(l.startswith("claude cwd=") and l.endswith("/code/orchestrator")
                            for l in lines), ran)
        args = [l[4:] for l in lines if l.startswith("arg ")]
        for flag, value in (("--setting-sources", "project"),
                            ("--permission-mode", "default"),
                            ("--disallowedTools", "Edit,Write,NotebookEdit")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertTrue(args[args.index("--settings") + 1].endswith("/code/checkin-settings.json"))
        self.assertIn("--strict-mcp-config", args)
        grant = args[args.index("--allowedTools") + 1]
        self.assertIn("/code/bin/fleet-journal:*)", grant)
        # systemctl list-timers took --host=user@box (ssh to anywhere); the
        # beat reaches timers only through fleet-timers.
        self.assertNotIn("systemctl", grant)
        self.assertIn("/code/bin/fleet-timers:*)", grant)
        self.assertNotIn("journalctl", grant)

    def test_checkin_model_is_the_operators_choice_and_checked(self):
        """CHECKIN_MODEL picks the beat's model; unset keeps the account
        default; anything that is not a model name refuses the beat rather
        than silently running the default."""
        r, ran = self._checkin_box()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("arg --model", ran)
        self.assertIn("model: account default", r.stdout)
        for model in ("sonnet", "opus", "claude-sonnet-5-5"):
            with self.subTest(model=model):
                r, ran = self._checkin_box(extra_env={"CHECKIN_MODEL": model})
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                args = [l[4:] for l in ran.splitlines() if l.startswith("arg ")]
                self.assertEqual(args[args.index("--model") + 1], model)
                self.assertIn(f"model: {model}", r.stdout)
        for bad in ("gpt-4", "Sonnet", "claude-", "sonnet --dangerously-skip-permissions",
                    "claude-x\n--model", "claude-é"):
            with self.subTest(bad=bad):
                r, ran = self._checkin_box(extra_env={"CHECKIN_MODEL": bad})
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("is not a model", r.stderr)
                self.assertNotIn("claude cwd=", ran)
                self.assertIn("fleet-board post @you @operator ERROR", ran)

    def test_the_heartbeat_refuses_steering_files_the_account_could_plant(self):
        """A beat steered once must not leave behind something that steers
        every beat after it. Claude Code loads skills, commands, agents,
        CLAUDE.md and settings from the account's HOME and config dir, and
        MCP servers from ~/.claude.json; the account can write all of them."""
        for plant in (".claude/skills/checkin/SKILL.md", ".claude/commands/checkin.md",
                      ".claude/agents/x.md", ".claude/CLAUDE.md", ".mcp.json",
                      ".claude/settings.local.json"):
            with self.subTest(plant=plant):
                r, ran = self._checkin_box(plant=[plant])
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("files that could steer the beat", r.stderr)
                # A directory is reported as the directory.
                self.assertIn("/home/" + "/".join(plant.split("/")[:2]) + ":", r.stderr)
                self.assertNotIn("claude cwd", ran)
                self.assertIn("fleet-board post @you @operator ERROR", ran)
        for name, cj in (
            ("mcpServers", {"mcpServers": {"x": {"command": "/bin/sh"}}}),
            ("project mcpServers", {"projects": {"/x": {"mcpServers": {"x": {}}}}}),
            ("project allowedTools", {"projects": {"/x": {"allowedTools": ["Bash"]}}}),
        ):
            with self.subTest(claude_json=name):
                r, ran = self._checkin_box(claude_json=cj)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(".claude.json", r.stderr)
                self.assertNotIn("claude cwd", ran)
        # What Claude Code writes there itself is not a finding.
        r, ran = self._checkin_box(claude_json={
            "numStartups": 3, "projects": {"/x": {"allowedTools": [], "mcpServers": {}}}})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("claude cwd", ran)

    # ── the beat trace (HARNESS.md, H1) ──────────────────────────────────────

    BEAT = [
        {"type": "system", "subtype": "init", "model": "test-model", "tools": ["Bash", "Read"],
         "mcp_servers": [], "permissionMode": "default", "apiKeySource": "ANTHROPIC_API_KEY",
         "claude_code_version": "0.0.0"},
        {"type": "assistant", "message": {"content": [
            {"type": "text", "text": "Checking the board."},
            {"type": "tool_use", "id": "t1", "name": "Bash",
             "input": {"command": "$FLEET_CODE/bin/fleet-board read"}}]}},
        # Untrusted text the beat read: it says every word cti-budget matches.
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "is_error": False,
             "content": "advisory: billing quota exceeded, HTTP 429, rate limit"}]}},
        {"type": "result", "subtype": "success", "is_error": False, "num_turns": 2,
         "duration_ms": 4290, "total_cost_usd": 0.0429,
         "usage": {"input_tokens": 4290, "output_tokens": 429},
         "permission_denials": [], "result": "Beat done, nothing to escalate."},
    ]

    def test_the_beat_is_traced_and_budget_sees_only_what_text_mode_printed(self):
        """A traced beat runs with stream-json, keeps every event in a 0600
        file under state/traces, and prints a timeline to the journal - but
        cti-budget classifies only the final result, never the tool output or
        the token counts, or this ordinary beat would read as a rate limit."""
        r, ran = self._checkin_box(trace=True, stream=self.BEAT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        args = [l[4:] for l in ran.splitlines() if l.startswith("arg ")]
        self.assertEqual(args[args.index("--output-format") + 1], "stream-json")
        self.assertIn("--verbose", args)
        self.assertIn("[trace] turn 1 tool Bash: $FLEET_CODE/bin/fleet-board read", r.stdout)
        self.assertIn("[trace] end: ok", r.stdout)
        self.assertNotIn("billing quota", r.stdout)  # tool output stays out of the journal
        record = ran[ran.index("cti-budget record"):]
        self.assertIn("Beat done, nothing to escalate.", record)
        for word in ("429", "quota", "billing", "rate limit"):
            self.assertNotIn(word, record.lower())
        m = re.search(r"\[trace\] kept in (\S+)", r.stdout)
        self.assertIsNotNone(m, r.stdout)
        path = pathlib.Path(m.group(1))
        self.assertEqual(path.parent.name, "traces")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        lines = [json.loads(l) for l in path.read_text().splitlines()]
        self.assertEqual(lines[0]["type"], "fleet_trace")
        self.assertEqual([l["type"] for l in lines[1:]], [e["type"] for e in self.BEAT])

    def test_an_out_of_credit_beat_still_reaches_the_classifier(self):
        """The 24 September outage: the credit message must reach cti-budget
        through the trace path exactly as it did in text mode."""
        stream = [
            {"type": "system", "subtype": "init", "model": "m", "tools": []},
            {"type": "assistant", "is_api_error_message": True, "error": "billing_error",
             "message": {"content": [{"type": "text", "text": "Credit balance is too low"}]}},
            {"type": "result", "subtype": "success", "is_error": True, "num_turns": 1,
             "terminal_reason": "api_error", "result": "Credit balance is too low"},
            "some stderr line",
        ]
        r, ran = self._checkin_box(trace=True, stream=stream, claude_rc=1)
        self.assertIn("--exit 1", ran)
        record = ran[ran.index("cti-budget record"):]
        self.assertIn("Credit balance is too low", record)
        self.assertIn("some stderr line", record)
        self.assertIn("[trace] API ERROR (billing_error)", r.stdout)
        self.assertIn("[trace] end: ERROR (api_error)", r.stdout)

    # ─── the verdict (HARNESS H3) ───────────────────────────────────────────

    def test_a_bad_verdict_is_one_info_line_to_all_never_the_operator(self):
        """A beat whose cti-checkin/1 verdict does not check out gets a board
        line - INFO to @all, because the next beat emails anything addressed
        to @operator and treats an ERROR as an incident - and no alert."""
        bad = 'echo "verdict: MISSING - the beat\'s final message has no cti-checkin/1 object"\nexit 1\n'
        r, ran = self._checkin_box(trace=True, stream=self.BEAT, verdict=bad)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        call = [l for l in ran.splitlines() if l.startswith("cti-checkin-verdict ")]
        self.assertEqual(len(call), 1, ran)
        self.assertIn("--trace ", call[0])
        self.assertIn("--out ", call[0])
        self.assertIn("verdict: MISSING", r.stdout)
        post = [l for l in ran.splitlines() if l.startswith("fleet-board post") and "cti-checkin/1" in l]
        self.assertEqual(len(post), 1, ran)
        self.assertTrue(post[0].startswith("fleet-board post @you @all INFO "), post[0])
        self.assertNotIn("@operator", post[0])
        self.assertFalse([l for l in ran.splitlines() if l.startswith("cti-alert ")], ran)

    def test_the_same_verdict_problem_posts_once_a_day(self):
        bad = 'echo "verdict: MISMATCH - board_writes is 1; the guard counted 0"\nexit 1\n'
        today = time.strftime("%Y-%m-%d")
        r, ran = self._checkin_box(trace=True, stream=self.BEAT, verdict=bad,
                                   home_files={"state/checkin-verdict-posted": f"{today} MISMATCH\n"})
        self.assertIn("verdict: MISMATCH", r.stdout)  # still in the journal
        self.assertNotIn("cti-checkin/1 verdict did not check out", ran)
        # A different kind the same day still gets its one line.
        r, ran = self._checkin_box(trace=True, stream=self.BEAT, verdict=bad.replace("MISMATCH", "INVALID"),
                                   home_files={"state/checkin-verdict-posted": f"{today} MISMATCH\n"})
        self.assertIn("cti-checkin/1 verdict did not check out", ran)

    def test_a_valid_verdict_is_a_journal_line_only(self):
        ok = 'echo "verdict: valid - status ok, 10 lanes, 0 escalation(s)"\nexit 0\n'
        r, ran = self._checkin_box(trace=True, stream=self.BEAT, verdict=ok)
        self.assertIn("verdict: valid", r.stdout)
        self.assertNotIn("cti-checkin/1 verdict did not check out", ran)

    def test_a_failed_beat_has_no_verdict_to_check(self):
        r, ran = self._checkin_box(trace=True, stream=self.BEAT, claude_rc=1,
                                   verdict='echo "verdict: valid"\n')
        self.assertNotIn("cti-checkin-verdict ", ran)

    def test_traces_off_runs_the_beat_as_before(self):
        """CHECKIN_TRACE_DAYS=0, or no fleet-trace on the box, is text mode;
        a value that is not a number warns and keeps the default."""
        for label, kw in (("days 0", {"trace": True, "extra_env": {"CHECKIN_TRACE_DAYS": "0"}}),
                          ("no fleet-trace", {})):
            with self.subTest(label):
                r, ran = self._checkin_box(stream=self.BEAT, **kw)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertNotIn("arg --output-format", ran)
                self.assertNotIn("[trace]", r.stdout)
        r, ran = self._checkin_box(trace=True, stream=self.BEAT,
                                   extra_env={"CHECKIN_TRACE_DAYS": "two weeks"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("is not a number of days; using 14", r.stderr)
        self.assertIn("arg stream-json", ran)

    def test_the_beat_cannot_read_its_own_traces(self):
        """A trace holds every advisory the beat read. The beat's Read grant
        covers reports, logs and archive; never state/, where traces live,
        and fleet-trace is not a granted command."""
        rules = self._orchestrator_grant()
        self.assertFalse(any("state" in r for r in rules if r.startswith("Read(")), rules)
        self.assertFalse(any("fleet-trace" in r for r in rules), rules)

    def _fleet_trace(self, home, *args, stdin=""):
        return subprocess.run(
            [str(FLEET_TRACE_BIN), *args],
            input=stdin, capture_output=True, text=True, check=False,
            env={"PATH": "/usr/bin:/bin", "FLEET_HOME": str(home)})

    def test_fleet_trace_keeps_reading_when_it_cannot_write(self):
        """If fleet-trace stopped reading, claude would die of SIGPIPE mid-beat.
        An unwritable trace stops the trace, not the timeline or --plain."""
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            plain = d / "plain"
            plain.write_text("")
            stdin = "".join(json.dumps(e) + "\n" for e in self.BEAT)
            r = self._fleet_trace(d, "tee", "--out", str(d / "no" / "such" / "x.jsonl"),
                                  "--plain", str(plain), stdin=stdin)
            self.assertEqual(r.returncode, 1)
            self.assertIn("cannot create", r.stderr)
            self.assertIn("[trace] end: ok", r.stdout)
            self.assertEqual(plain.read_text(), "Beat done, nothing to escalate.\n")

    def test_fleet_trace_caps_the_file_and_wraps_text(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "plain").write_text("")
            out = d / "t.jsonl"
            big = json.dumps({"type": "user", "message": {"content": "x" * 700000}})
            # --keep full: in the default mode a 700 KB message is kept as a
            # stub and never reaches the cap, which is the point of the default.
            r = self._fleet_trace(d, "tee", "--out", str(out), "--plain", str(d / "plain"),
                                  "--max-mb", "1", "--keep", "full",
                                  stdin="not json\n" + (big + "\n") * 3 + json.dumps(self.BEAT[-1]) + "\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("trace stopped at 1 MB", r.stderr)
            self.assertIn("[trace] end: ok", r.stdout)  # read to the end regardless
            lines = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(lines[1], {"type": "fleet_trace_text", "text": "not json"})
            self.assertTrue(lines[-1].get("truncated"))
            self.assertLessEqual(out.stat().st_size, 1024 * 1024 + 200)

    def test_fleet_trace_show_strips_terminal_escapes(self):
        """`show` puts untrusted text on the operator's terminal. An ANSI
        escape in an advisory must not be able to rewrite what it says."""
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d)
            self.assertEqual(self._fleet_trace(home, "init").returncode, 0)
            t = home / "state" / "traces" / "checkin-20260101T000000.jsonl"
            evil = "ok\x1b[2J\x1b]0;pwned\x07\u202eevil"
            t.write_text(json.dumps({"type": "assistant", "message": {"content": [
                {"type": "text", "text": evil}]}}) + "\n" + json.dumps(self.BEAT[-1]) + "\n")
            for args in (("show", "--last"), ("show", "--last", "--full"), ("list",)):
                with self.subTest(args=args):
                    r = self._fleet_trace(home, *args)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertNotIn("\x1b", r.stdout)
                    self.assertNotIn("\x07", r.stdout)
                    self.assertNotIn("\u202e", r.stdout)
            self.assertIn("checkin-20260101T000000.jsonl", r.stdout)

    def test_fleet_trace_prune_removes_only_old_traces(self):
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d)
            self._fleet_trace(home, "init")
            tdir = home / "state" / "traces"
            old, new, other = (tdir / "checkin-20250101T000000.jsonl",
                               tdir / "checkin-20260101T000000.jsonl", tdir / "keep.txt")
            for f in (old, new, other):
                f.write_text("{}\n")
            past = time.time() - 30 * 86400
            os.utime(old, (past, past))
            os.utime(other, (past, past))
            r = self._fleet_trace(home, "prune", "--days", "14")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())
            self.assertTrue(other.exists())

    # ─── what a trace keeps (CHECKIN_TRACE_KEEP) ─────────────────────────────

    CONTENT_BEAT = [
        {"type": "system", "subtype": "init", "model": "m", "tools": ["Bash"], "mcp_servers": []},
        {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "SECRET-THINKING about the mail"},
            {"type": "text", "text": "Reading the mailbox."},
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "fleet-board read"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "is_error": False,
             "content": "SECRET-MAIL-BODY " + "x" * 5000}]},
         "tool_use_result": {"stdout": "SECRET-STDOUT"}},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "cti-alert"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t2", "is_error": True,
             "content": [{"type": "text", "text": "DENIED by the guard: " + "e" * 600}]}]}},
        {"type": "result", "subtype": "success", "is_error": False, "num_turns": 2,
         "duration_ms": 1000, "total_cost_usd": 0.01,
         "usage": {"input_tokens": 100, "output_tokens": 10},
         "permission_denials": [], "result": "VERDICT-TEXT the beat's final message"},
    ]

    def _tee(self, d, *extra):
        stdin = "SECRET-STDERR " + "s" * 3000 + "\n" + "".join(json.dumps(e) + "\n" for e in self.CONTENT_BEAT)
        (d / "plain").write_text("")
        out = d / "t.jsonl"
        r = self._fleet_trace(d, "tee", "--out", str(out), "--plain", str(d / "plain"), *extra, stdin=stdin)
        return r, out

    def test_the_default_trace_keeps_decisions_not_what_the_beat_read(self):
        """A trace used to be a second copy of whatever the beat read: mail
        bodies, advisories, report text. Now it keeps what the model said and
        did, what it cost and what it concluded, and for everything it read
        only the size and a short hash."""
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            r, out = self._tee(d)
            self.assertEqual(r.returncode, 0, r.stderr)
            text = out.read_text()
            for secret in ("SECRET-MAIL-BODY", "SECRET-STDOUT", "SECRET-THINKING"):
                self.assertNotIn(secret, text)
            lines = [json.loads(l) for l in text.splitlines()]
            self.assertEqual(lines[0]["keep"], "minimal")
            # what the model did survives
            self.assertIn("fleet-board read", text)
            self.assertIn("Reading the mailbox.", text)
            # a success's content became a size and a short hash
            red = [b for l in lines if l.get("type") == "user"
                   for b in l["message"]["content"] if not b.get("is_error")][0]["content"][0]
            self.assertEqual(red["type"], "fleet_trace_redacted")
            self.assertEqual(red["chars"], len("SECRET-MAIL-BODY ") + 5000)
            self.assertRegex(red["sha256"], r"^[0-9a-f]{16}$")
            # a failed call keeps its reason, capped
            err = [b for l in lines if l.get("type") == "user"
                   for b in l["message"]["content"] if b.get("is_error")][0]["content"]
            self.assertTrue(err.startswith("DENIED by the guard: "))
            self.assertLess(len(err), 400)
            # stray stderr is capped
            self.assertLess(len(lines[1]["text"]), 2100)
            # the verdict and the cost are intact: cti-checkin-verdict and `list` read them
            self.assertEqual(lines[-1]["result"], "VERDICT-TEXT the beat's final message")
            self.assertEqual(lines[-1]["total_cost_usd"], 0.01)
            self.assertEqual(lines[-1]["usage"], {"input_tokens": 100, "output_tokens": 10})
            # the journal timeline still says how much the tool returned
            self.assertIn("-> ok, 5017 chars", r.stdout)

    def test_a_shape_the_code_has_not_seen_is_not_kept_by_default(self):
        """minimize() is an allowlist: content in any event shape other than the
        few it knows is kept only as a size and a hash."""
        odd = [
            {"type": "system", "subtype": "init", "model": "m", "tools": [], "mcp_servers": []},
            {"type": "system", "subtype": "hook_response", "stdout": "SECRET-HOOK-OUTPUT"},
            {"type": "user", "message": {"content": "SECRET-COMPACTION-SUMMARY of the mail"}},
            {"type": "user", "message": {"content": [
                {"type": "text", "text": "SECRET-META-TEXT"}, "SECRET-BARE-STRING",
                {"type": "tool_result", "tool_use_id": "t1", "is_error": "false", "structuredContent": {"x": "SECRET-STRUCTURED"},
                 "content": "SECRET-STRING-FLAG-IS-NOT-AN-ERROR"}]}},
            {"type": "assistant", "message": {"content": [
                {"type": "web_fetch_tool_result", "content": "SECRET-SERVER-RESULT"},
                {"type": "tool_result", "content": "SECRET-RESULT-IN-ASSISTANT"},
                {"type": "text", "text": "kept: what the model said"}]}},
            {"type": "user", "mcp_output": "SECRET-MCP-KEY", "toolUseResult": {"stdout": "SECRET-TOOLUSERESULT"},
             "message": {"content": [{"type": "tool_result", "tool_use_id": "t2", "is_error": False,
                                      "content": [{"type": "text", "text": 12345}]}]}},  # a non-string text must not crash
            {"type": "brand_new_event", "payload": "SECRET-NEW-EVENT"},
            {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "total_cost_usd": 0.01,
             "usage": {}, "permission_denials": [], "result": "verdict"},
        ]
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "plain").write_text("")
            out = d / "t.jsonl"
            r = self._fleet_trace(d, "tee", "--out", str(out), "--plain", str(d / "plain"),
                                  stdin="".join(json.dumps(e) + "\n" for e in odd))
            self.assertEqual(r.returncode, 0, r.stderr)
            text = out.read_text()
            self.assertNotIn("SECRET", text)
            self.assertIn("kept: what the model said", text)
            lines = [json.loads(l) for l in text.splitlines()]
            self.assertEqual(len(lines), 1 + len(odd), "every event must leave a record, even a malformed one")
            self.assertEqual(lines[-1]["result"], "verdict")
            # a string "false" is not an error, so its content is not kept
            tr = [b for l in lines if l.get("type") == "user" for b in (l.get("message") or {}).get("content", [])
                  if isinstance(b, dict) and b.get("tool_use_id") == "t1"][0]
            self.assertFalse(tr["is_error"])
            self.assertEqual(tr["content"][0]["type"], "fleet_trace_redacted")

    def test_full_keeps_every_event_as_it_came(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            r, out = self._tee(d, "--keep", "full")
            self.assertEqual(r.returncode, 0, r.stderr)
            text = out.read_text()
            for kept in ("SECRET-MAIL-BODY", "SECRET-STDOUT", "SECRET-THINKING", "SECRET-STDERR"):
                self.assertIn(kept, text)
            self.assertEqual(json.loads(text.splitlines()[0])["keep"], "full")

    def test_keep_takes_minimal_or_full_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            r, _ = self._tee(d, "--keep", "everything")
            self.assertEqual(r.returncode, 2)
            self.assertIn("--keep takes minimal or full", r.stderr)

    def test_show_on_a_minimal_trace_says_the_content_was_not_kept(self):
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d)
            self._fleet_trace(home, "init")
            _, out = self._tee(home)
            traces = home / "state" / "traces"
            (traces / "checkin-20260101T000000.jsonl").write_text(out.read_text())
            for args in (("show", "--last"), ("show", "--last", "--full"), ("list",)):
                with self.subTest(args=args):
                    r = self._fleet_trace(home, *args)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    for secret in ("SECRET-MAIL-BODY", "SECRET-STDOUT", "SECRET-THINKING"):
                        self.assertNotIn(secret, r.stdout)
            r = self._fleet_trace(home, "show", "--last", "--full")
            self.assertIn("[content not kept: 5017 chars, sha256 ", r.stdout)
            self.assertIn("-> ok, 5017 chars", r.stdout)
            self.assertIn("$0.0100", self._fleet_trace(home, "show", "--last").stdout)

    def test_the_runner_defaults_to_minimal_and_a_typo_cannot_widen_it(self):
        header = {}
        for label, env in (("default", {}), ("full", {"CHECKIN_TRACE_KEEP": "full"}),
                           ("typo", {"CHECKIN_TRACE_KEEP": "ful"})):
            r, ran = self._checkin_box(trace=True, stream=self.BEAT, extra_env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            m = re.search(r"\[trace\] kept in (\S+)", r.stdout)
            self.assertIsNotNone(m, r.stdout)
            header[label] = json.loads(pathlib.Path(m.group(1)).read_text().splitlines()[0])["keep"]
            if label == "typo":
                self.assertIn("CHECKIN_TRACE_KEEP='ful' is not minimal or full; using minimal", r.stderr)
        self.assertEqual(header, {"default": "minimal", "full": "full", "typo": "minimal"})

    def test_fleet_journal_reads_the_fleets_units_and_nothing_else(self):
        """journalctl:* granted --cursor-file=PATH, which overwrites PATH as the
        service account: state/budget.json (resetting the quota) or memory.db.
        The wrapper passes -u cti-agent-*, --since, -n and --no-pager, each as
        --opt=VALUE so a value cannot become an option, and nothing else."""
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "fleet-kit" / "fleet" / "bin" / "fleet-journal").read_text(encoding="utf-8")
        self.assertIn("\nJOURNALCTL=/usr/bin/journalctl\n", src)
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            fake = d / "journalctl"
            fake.write_text('#!/bin/sh\nfor a; do echo "$a"; done\n')
            fake.chmod(0o755)
            w = d / "fleet-journal"
            w.write_text(src.replace("\nJOURNALCTL=/usr/bin/journalctl\n", f"\nJOURNALCTL={fake}\n"))

            def run(*args):
                return subprocess.run(["bash", str(w), *args], capture_output=True, text=True, check=False)

            for args, want in (
                (["-u", "cti-agent-*", "--since", "-3h", "--no-pager"],
                 ["--no-pager", "--unit=cti-agent-*", "--since=-3h"]),
                (["-u", "cti-agent-appscan.service", "--since", "today", "--no-pager"],
                 ["--no-pager", "--unit=cti-agent-appscan.service", "--since=today"]),
                (["-u", "cti-agent-checkin.service", "-n", "100"],
                 ["--no-pager", "--unit=cti-agent-checkin.service", "--lines=100"]),
                (["-u", "cti-agent-alert@x.service", "--since", "2026-11-03 06:00:00"],
                 ["--no-pager", "--unit=cti-agent-alert@x.service", "--since=2026-11-03 06:00:00"]),
            ):
                with self.subTest(args=args):
                    r = run(*args)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout.splitlines(), want)
            for args in (
                ["-u", "cti-agent-x", "--cursor-file=/var/lib/cti-agent/state/budget.json"],
                ["-u", "cti-agent-x", "--cursor-file", "/tmp/x"],
                ["-u", "cti-agent-x", "--after-cursor=x"],
                ["-u", "cti-agent-x", "--output-fields=MESSAGE"],
                ["-u", "cti-agent-x", "-D", "/var/log/journal"],
                ["-u", "cti-agent-x", "--file=/etc/shadow"],
                ["-u", "cti-agent-x", "--vacuum-size=1"],
                ["-u", "sshd"],
                ["-u", "x-cti-agent-x"],
                ["-u", "cti-agent-x;id"],
                ["-u", "cti-agent-x", "--since", "today; id"],
                ["-u", "cti-agent-x", "--since", "$(id)"],
                ["-u", "cti-agent-x", "-n", "-1"],
                ["-u", "cti-agent-x", "-n", "10", "_PID=1"],
                ["--no-pager"],
                [],
            ):
                with self.subTest(refused=args):
                    r = run(*args)
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertEqual(r.stdout, "")

    def test_the_orchestrator_is_told_to_write_escalations_in_plain_english(self):
        """The operator reads an escalation on a phone: what is being asked, and
        what happens if nothing is done, come before any detail. The example the
        skill gives must itself get past the Bash guard, or the beat copies a
        command that costs it a turn."""
        root = pathlib.Path(__file__).resolve().parents[2]
        claude = (root / "fleet-kit" / "fleet" / "CLAUDE.md").read_text(encoding="utf-8")
        skill = (root / "fleet-kit" / "fleet" / "skills" / "checkin" / "SKILL.md").read_text(encoding="utf-8")
        for name, text in (("CLAUDE.md", claude), ("SKILL.md", skill)):
            with self.subTest(name):
                self.assertIn("what happens if", text)
                self.assertIn("plain English", text)
        m = re.search(r'--reason "([^"<>]*If you do nothing[^"<>]*)"', skill)
        self.assertIsNotNone(m, "the skill shows an example escalation that says what happens if nothing is done")
        guard = GUARD_BIN
        cmd = ('/opt/cti-agent/bin/cti-alert --unit cti-agent-checkin.service --for-real '
               '--kind ESCALATION --reason "%s"' % m.group(1))
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        r = subprocess.run([str(guard)], input=payload,
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_bash_guard_refuses_shell_syntax_and_fails_closed(self):
        """A prefix grant names a command, not the shell around it. The guard
        hook lets through one granted command with plain arguments and
        blocks (exit 2) redirection, pipes, chaining, substitution and line
        breaks - and anything it cannot parse."""
        guard = GUARD_BIN  # cmd/checkin-bash-guard, built from this checkout

        def run(payload):
            data = payload if isinstance(payload, str) else json.dumps(payload)
            return subprocess.run([str(guard)], input=data,
                                  capture_output=True, text=True, check=False)

        def bash(cmd):
            return run({"tool_name": "Bash", "tool_input": {"command": cmd}})

        for cmd in (
            "/opt/cti-agent/bin/fleet-timers --all",
            "/opt/cti-agent/bin/fleet-journal -u 'cti-agent-*' --since '-3h' --no-pager",
            '/opt/cti-agent/bin/fleet-board say @all INFO "orchestrator up"',
            '/opt/cti-agent/bin/fleet-db remember checkin beat_1 "quiet beat, 0 findings"',
            "/opt/cti-agent/bin/cti-budget status",
            "/opt/cti-agent/bin/fleet-board say @all INFO 'costs $5? [maybe] ~later'",
            # An apostrophe inside double quotes is a literal, not a quote.
            '/opt/cti-agent/bin/fleet-db remember checkin beat_1 "the digest didn\'t run"',
            "/opt/cti-agent/bin/fleet-board say @all INFO 'say \"hi\" here'",
            # Inside quotes these are plain characters to bash (2026-11-15: a
            # week of beats lost a turn on each quoted semicolon or question).
            '/opt/cti-agent/bin/fleet-board say @all INFO "done; nothing new"',
            '/opt/cti-agent/bin/fleet-board say @operator INFO "May I hold it until Monday?"',
            '/opt/cti-agent/bin/fleet-db remember checkin t "A & B, a->b, x|y, ~30 min, [cut], *"',
            "/opt/cti-agent/bin/fleet-board say @all INFO 'it is done; ok?'",
        ):
            with self.subTest(allowed=cmd):
                r = bash(cmd)
                self.assertEqual(r.returncode, 0, r.stderr)
        for cmd in (
            "/opt/cti-agent/bin/fleet-timers > /var/lib/cti-agent/state/budget.json",
            "/opt/cti-agent/bin/fleet-timers >> x",
            "/opt/cti-agent/bin/fleet-db recent < /etc/passwd",
            "/opt/cti-agent/bin/fleet-db recent | sh",
            "/opt/cti-agent/bin/fleet-db recent; id",
            "/opt/cti-agent/bin/fleet-db recent && id",
            "/opt/cti-agent/bin/fleet-db recent & id",
            "/opt/cti-agent/bin/fleet-board post @you @all INFO $(id)",
            "/opt/cti-agent/bin/fleet-board post @you @all INFO `id`",
            "/opt/cti-agent/bin/fleet-board post @you @all INFO ${HOME}",
            "/opt/cti-agent/bin/fleet-db recent\nid",
            "/opt/cti-agent/bin/fleet-db recent\rid",
            # Plain expansion: the beat's environment carries fleet.env.
            "/opt/cti-agent/bin/fleet-board say @all INFO $CLIENT_SECRET",
            '/opt/cti-agent/bin/cti-alert --reason "$QUALYS_PASSWORD"',
            "$FLEET_CODE/bin/cti-budget status",
            "/opt/cti-agent/bin/fleet-board say @all INFO $'\\x41'",
            # PrimeSec 10969091: a ' that is not a single quote to bash (in
            # double quotes, or escaped) hid what lay between two of them.
            "/opt/cti-agent/bin/fleet-board say @all INFO \"'\" $(id) \"'\"",
            "/opt/cti-agent/bin/fleet-board say @all INFO \"'\" $CLIENT_SECRET \"'\"",
            "/opt/cti-agent/bin/fleet-board say @all INFO \\' $(id) \\'",
            "/opt/cti-agent/bin/fleet-board say @all INFO \"it's\" $(id) \"it's\"",
            '/opt/cti-agent/bin/cti-alert --reason "a\\"b $(id) c"',
            "/opt/cti-agent/bin/fleet-board say @all INFO \\$HOME",
            '/opt/cti-agent/bin/fleet-board say @all INFO "unclosed',
            "/opt/cti-agent/bin/fleet-board say @all INFO /etc/cti-agent/*",
            "/opt/cti-agent/bin/fleet-board say @all INFO ~root",
            "/opt/cti-agent/bin/fleet-board say @all INFO x?",
            "/opt/cti-agent/bin/fleet-board say @all INFO 'open quote $HOME",
            "FLEET_HOME= /opt/cti-agent/bin/cti-kev --enriched /tmp/enriched-x.json",
            " X=1 /opt/cti-agent/bin/cti-kev",
            # The operators still mean what they mean outside quotes, however
            # close to a quote they sit.
            '/opt/cti-agent/bin/fleet-board say @all INFO "x"; id',
            '/opt/cti-agent/bin/fleet-board say @all INFO "x";id',
            '/opt/cti-agent/bin/fleet-board say @all INFO "x"|sh',
            '/opt/cti-agent/bin/fleet-board say @all INFO "x"&id',
            '/opt/cti-agent/bin/fleet-board say @all INFO "x">/tmp/y',
            '/opt/cti-agent/bin/fleet-board say @all INFO "a;"b;id',
            "/opt/cti-agent/bin/fleet-board say @all INFO 'a;'b;id",
            # $ and backticks still expand inside double quotes.
            '/opt/cti-agent/bin/fleet-board say @all INFO "ok; $(id)"',
            '/opt/cti-agent/bin/fleet-board say @all INFO "ok? $CLIENT_SECRET"',
            '/opt/cti-agent/bin/fleet-board say @all INFO "ok; `id`"',
            '/opt/cti-agent/bin/fleet-board say @all INFO "a\\;" id',
        ):
            with self.subTest(refused=cmd):
                r = bash(cmd)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("checkin-bash-guard:", r.stderr)
        # Fails closed on input it cannot read, and on a Bash call with no
        # command; other tools pass through untouched.
        for payload in ("", "not json", "[]", {"tool_name": "Bash", "tool_input": {}}):
            with self.subTest(bad_input=payload):
                self.assertEqual(run(payload).returncode, 2)
        self.assertEqual(run({"tool_name": "Read", "tool_input": {"file_path": "/x>y"}}).returncode, 0)


    def _guard(self):
        return GUARD_BIN

    def _run_guard(self, cmd, env=None):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        e = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
        e.update(env or {})
        return subprocess.run([str(self._guard())], input=payload,
                              capture_output=True, text=True, check=False, env=e)

    def test_the_guard_holds_each_granted_command_to_its_arguments(self):
        """PrimeSec design review 39260, Scenario-223: a prefix grant such as
        cti-alert:* lets any arguments through, so the guard also holds a table
        of what each granted command may be given."""
        b = "/opt/cti-agent/bin/"
        allowed = (
            b + "fleet-board read", b + "fleet-board read @all", b + "fleet-board tail 6",
            b + "fleet-board tail -n 8", b + "fleet-db findings --cve CVE-2026-124194",
            b + "fleet-board resolve q17", b + "fleet-board expire 7",
            b + 'fleet-board say @all INFO "braces {ok} and (parens) inside double quotes"',
            b + "fleet-board say @all INFO 'a #hash and {braces} in single quotes'",
            b + "fleet-db task done 12", b + "fleet-db mail ack 3",
            b + 'fleet-board say @all INFO "quiet beat"',
            b + "fleet-db recent", b + "fleet-db findings --status UNKNOWN",
            b + "fleet-db findings --priority Sev5 --stale-days 7",
            b + "fleet-db was-sent 2026-11-10 daily", b + "fleet-db rollup --days 7",
            b + "fleet-db task list", b + "fleet-db ack 12", b + "fleet-db vacuum",
            b + "fleet-db mail inbox ingest",
            b + "cti-budget status", b + "cti-kev --horizon 14", b + "cti-kev",
            b + "cti-patchtuesday --dry-run --month 2026-11",
            b + "cti-mailbox --dry-run",
            b + "fleet-timers --all", b + "fleet-timers 'cti-agent-*'",
            b + "fleet-journal -u cti-agent-domains.service --since today --no-pager",
            b + "fleet-journal -u 'cti-agent-*' --since '-3h' -n 200 --no-pager",
            b + 'cti-alert --unit cti-agent-checkin.service --for-real --kind ESCALATION '
                '--reason "Please approve X. If you do nothing it waits. Detail: CVE."',
            b + "cti-alert --unit cti-agent-checkin.service --dry-run --kind ESCALATION --reason 'x'",
        )
        for cmd in allowed:
            with self.subTest(allowed=cmd):
                r = self._run_guard(cmd)
                self.assertEqual(r.returncode, 0, r.stderr)
        refused = (
            "/usr/bin/id", "/tmp/fleet-board read", "fleet-board read",
            b + "fleet-board", b + "fleet-board post @you @operator A x",
            b + "fleet-board prune .", b + "fleet-board say @attacker INFO x",
            b + "fleet-board say @all FORGED x", b + "fleet-board say @all INFO",
            b + "fleet-board say @all INFO " + "x" * 401,
            b + "fleet-board say @all INFO 'caf\u00e9'",
            b + "fleet-board tail 99999", b + "fleet-board expire 1",
            b + "fleet-board tail -n", b + "fleet-board tail -n 999", b + "fleet-board tail -n 8 9",
            b + "fleet-db findings CVE-2026-124194", b + "fleet-db findings --cve 'x OR 1=1'",
            b + "fleet-db findings --cve CVE-2026-\u0661\u0662\u0663\u0664",
            b + "fleet-db was-sent 2026-11-1\u0665 daily",
            b + "fleet-board say @all WARN x",
            b + "fleet-db sent 2026-11-10 1 2 3 4 5 m", b + "fleet-db finding upsert '{}'",
            b + "fleet-db note CVE-2026-1 x", b + "fleet-db init",
            b + "fleet-db remember checkin one", b + "fleet-db remember BAD topic text",
            b + "fleet-db findings --db /tmp/x", b + "fleet-db recent 1 2",
            b + "cti-budget record --exit 0", b + "cti-budget",
            b + "cti-kev --enriched /tmp/e.json", b + "cti-kev --horizon=14",
            b + "cti-kev --horizon 0", b + "cti-kev --horizon 14 --horizon 15",
            b + "cti-patchtuesday --mark-sent", b + "cti-patchtuesday --dry-run --out /tmp/x",
            b + "cti-patchtuesday --dry-run --url-msrc http://example.test",
            b + "cti-patchtuesday --month 2026-11 --dry-run",
            b + "cti-mailbox", b + "cti-mailbox --dry-run --for-real",
            b + "fleet-timers --host=user@box", b + "fleet-timers ssh",
            b + "fleet-journal -u sshd", b + "fleet-journal --cursor-file x -u cti-agent-x",
            b + "fleet-journal --since today",
            b + "cti-alert --unit cti-agent-checkin.service --kind ESCALATION --reason x",
            b + "cti-alert --unit cti-agent-checkin.service --for-real --dry-run --kind ESCALATION --reason x",
            b + "cti-alert --unit cti-agent-digest.service --for-real --kind ESCALATION --reason x",
            b + "cti-alert --unit cti-agent-checkin.service --for-real --kind FAILED --reason x",
            b + "cti-alert --unit cti-agent-checkin.service --for-real --kind ESCALATION --reason x --to-dev",
            b + "cti-alert --unit cti-agent-checkin.service --for-real --kind ESCALATION --reason " + "'" + "x" * 801 + "'",
            b + "cti-mailer --lane was", b + "run-digest daily --for-real",
            # Review of design review 39260: brace expansion, comments, extglob.
            b + "fleet-board say @all INFO {a,b}{a,b}{a,b}{a,b}{a,b}{a,b}",
            b + "fleet-db remember checkin t {a,b}{a,b}{a,b}",
            b + "fleet-board say @all INFO hello #hidden",
            b + "fleet-board say @all INFO +(a|b)",
            b + "fleet-db task done abc", b + "fleet-db ack abc", b + "fleet-db mail ack abc",
        )
        for cmd in refused:
            with self.subTest(refused=cmd):
                r = self._run_guard(cmd)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("checkin-bash-guard:", r.stderr)

    def test_the_orchestrator_knows_every_lane_that_has_a_timer(self):
        """The orchestrator's job is to oversee every lane. A lane added without
        telling it is a lane nobody checks: the owner lane held a scan on
        2026-11-11 and the orchestrator, which had never been told the lane
        existed, said nothing. So every cti-agent-*.timer must be named in its
        instructions (fleet/CLAUDE.md), and the lane table must name each
        runner's handle. Add the lane there, and a check to the checkin skill's
        'Scheduled work' table, when a lane is created."""
        root = pathlib.Path(__file__).resolve().parents[1] / "fleet"
        orch = (root / "CLAUDE.md").read_text(encoding="utf-8")
        skill = (root / "skills" / "checkin" / "SKILL.md").read_text(encoding="utf-8")
        timers = sorted(p.name[: -len(".timer")] for p in (root / "systemd-fedora").glob("cti-agent-*.timer"))
        self.assertGreaterEqual(len(timers), 10)
        for t in timers:
            with self.subTest(timer=t):
                self.assertIn(t, orch, f"{t} is not named in fleet/CLAUDE.md: the orchestrator does not know this lane")
        # A lane with its own runner has a handle on the board and a row in the table.
        for runner in sorted(p.name for p in (root / "bin").glob("run-*")):
            if runner in ("run-checkin", "run-digest"):
                continue  # the orchestrator itself; the digest is @ingest/@brief
            with self.subTest(runner=runner):
                self.assertIn("bin/" + runner, orch, f"{runner} has no row in the orchestrator's lane table")
        # Every timer's service can be read through the beat's journal wrapper
        # (any cti-agent-* unit), and the skill says where to look for the ones
        # that report a result.
        for t in ("cti-agent-appowners", "cti-agent-appscan", "cti-agent-domains", "cti-agent-supplier"):
            with self.subTest(journal=t):
                self.assertIn(t + ".service", skill, f"the checkin skill has no 'did it run' check for {t}")

    def test_every_command_the_beat_is_granted_has_an_argument_policy(self):
        """The table in the guard and run-checkin's grant must not drift:
        a granted command with no row would be refused, and a row with no grant
        is dead weight that suggests a capability the beat does not have."""
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "cmd" / "checkin-bash-guard" / "policy.go").read_text(encoding="utf-8")
        table = src.split("var policy = map[string]func([]string) string{", 1)[1].split("\n}", 1)[0]
        policy = set(re.findall(r'^\s*"([a-z-]+)":', table, re.M))
        run = (root / "fleet-kit" / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        granted = set()
        for line in run.splitlines():
            if "ALLOWED_TOOLS" in line:
                granted.update(re.findall(r"\$FLEET_CODE/bin/([a-z-]+)", line))
        self.assertTrue(granted, "found no grants in run-checkin")
        self.assertEqual(granted, policy,
                         "run-checkin's Bash grants and the guard's policy table differ")

    def test_the_guard_counts_a_beats_calls_and_refuses_past_the_limit(self):
        """Scenario-224: per-beat counters, set by run-checkin and kept where
        the beat cannot read or write them; the Nth+1 call is refused."""
        import tempfile
        b = "/opt/cti-agent/bin/"
        with tempfile.TemporaryDirectory() as home:
            env = {"CHECKIN_BEAT_ID": "beat-1", "FLEET_HOME": home,
                   "CHECKIN_MAX_BASH": "5", "CHECKIN_MAX_BOARD_WRITES": "2"}
            say = b + 'fleet-board say @all INFO "x"'
            for _ in range(2):
                self.assertEqual(self._run_guard(say, env).returncode, 0)
            r = self._run_guard(say, env)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("limit for board write", r.stderr)
            # Reads are not board writes, but every call counts toward the total
            # (2 writes + 1 refused write so far = 3 of 5).
            self.assertEqual(self._run_guard(b + "fleet-board read", env).returncode, 0)
            self.assertEqual(self._run_guard(b + "fleet-board read", env).returncode, 0)
            r = self._run_guard(b + "fleet-board read", env)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("limit for bash", r.stderr)
            counts = json.loads((pathlib.Path(home) / "state" / "checkin-counts" / "beat-1.json").read_text())
            self.assertEqual(sorted(counts["tripped"]), ["bash", "board_write"])
            self.assertEqual(oct((pathlib.Path(home) / "state" / "checkin-counts").stat().st_mode & 0o777), "0o700")
            # Another beat starts at zero.
            env2 = dict(env, CHECKIN_BEAT_ID="beat-2")
            self.assertEqual(self._run_guard(say, env2).returncode, 0)
            # A counter that cannot be kept refuses rather than going quiet.
            bad = dict(env2, FLEET_HOME="/proc/no-such-dir")
            r = self._run_guard(say, bad)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("counter", r.stderr)
            # With no beat id (a hand run) nothing is counted.
            self.assertEqual(self._run_guard(b + "fleet-board read").returncode, 0)


    def _bin(self, name):
        return pathlib.Path(__file__).resolve().parents[1] / "fleet" / "bin" / name

    def _wrapper_bin(self, d, with_cleaner=True):
        """A bin directory holding fleet-board and fleet-db beside a cti-sanitize
        built from this checkout, the way the installer lays them out: the
        wrappers find the cleaner beside themselves."""
        d = pathlib.Path(d) / "bin"
        d.mkdir()
        for name in ("fleet-board", "fleet-db"):
            shutil.copy(self._bin(name), d / name)
        if with_cleaner:
            root = pathlib.Path(__file__).resolve().parents[2]
            b = subprocess.run(["go", "build", "-o", str(d / "cti-sanitize"), "./cmd/cti-sanitize"],
                               cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(b.returncode, 0, b.stderr)
        return d

    def test_the_cleaner_is_go_and_the_wrappers_call_it(self):
        """Scenario-222. The Python fleet-sanitize kept a second copy of
        internal/sanitize's rules; cti-sanitize is the package itself, and
        cmd/cti-sanitize's tests run the shared cases through it."""
        self.assertFalse(self._bin("fleet-sanitize").exists())
        for name in ("fleet-board", "fleet-journal", "fleet-db"):
            src = self._bin(name).read_text(encoding="utf-8")
            with self.subTest(name):
                self.assertIn("cti-sanitize", src)
                self.assertNotIn("fleet-sanitize", src)

    def test_a_beat_without_the_cleaner_reads_nothing(self):
        """Raw output is not an option inside a beat: a missing cleaner means
        the beat gets no board and no memory, and says why on stderr."""
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            (pathlib.Path(home) / "board.md").write_text(
                "[2026-11-10 09:00] @scout -> @you INFO id=x1 ok \x1b[2J\n", encoding="utf-8")
            d = self._wrapper_bin(home, with_cleaner=False)
            env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
            env.update({"FLEET_HOME": home, "CHECKIN_BEAT_ID": "b-1"})
            r = subprocess.run(["/bin/bash", str(d / "fleet-board"), "read"],
                               capture_output=True, text=True, check=False, env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, "")
            self.assertIn("cti-sanitize is missing", r.stderr)
            r = subprocess.run(["/usr/bin/python3", "-sE", str(d / "fleet-db"), "recent"],
                               capture_output=True, text=True, check=False, env=env)
            self.assertEqual((r.returncode, r.stdout), (2, ""))
            self.assertIn("cti-sanitize is missing", r.stderr)

    def test_a_beat_reads_the_board_and_memory_cleaned_and_a_lane_reads_them_raw(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            board = pathlib.Path(home) / "board.md"
            board.write_text("[2026-11-10 09:00] @scout -> @you INFO id=x1 ok \x1b[2Jhidden \r EVIL\n"
                             "[2026-11-10 09:01] @scout -> @you INFO " + "y" * 3000 + "\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
            env.update({"FLEET_HOME": home})
            beat = dict(env, CHECKIN_BEAT_ID="b-1")
            d = self._wrapper_bin(home)

            def board_read(e):
                return subprocess.run(["/bin/bash", str(d / "fleet-board"), "read"],
                                      capture_output=True, text=True, check=False, env=e)
            raw, clean = board_read(env), board_read(beat)
            self.assertIn("\x1b", raw.stdout)
            self.assertNotIn("\x1b", clean.stdout)
            self.assertNotIn("\r", clean.stdout)
            self.assertIn("[cut ", clean.stdout)
            self.assertLess(max(len(x) for x in clean.stdout.splitlines()), 1100)
            # The same for fleet-db: what a memory says reaches the beat cleaned.
            # fleet-db now refuses control characters on write, so the hostile
            # text is put in the way another writer could have: straight into
            # the table. The cleaning on read is a second line, not the first.
            subprocess.run(["/usr/bin/python3", "-sE", str(d / "fleet-db"), "init"],
                           check=True, env=env, capture_output=True)
            import sqlite3
            db = sqlite3.connect(os.path.join(env["FLEET_HOME"], "state", "memory.db"))
            db.execute("INSERT INTO memories(category,topic,content,ts) VALUES(?,?,?,?)",
                       ("scout", "t1", "note \x1b[31mred\x1b[0m", "2026-11-19T00:00:00+00:00"))
            db.commit()
            db.close()

            def db_recent(e):
                return subprocess.run(["/usr/bin/python3", "-sE", str(d / "fleet-db"), "recent"],
                                      capture_output=True, text=True, check=False, env=e)
            self.assertIn("\x1b", db_recent(env).stdout)
            r = db_recent(beat)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("\x1b", r.stdout)
            self.assertIn("note [31mred[0m", r.stdout)

    def test_the_runner_gives_each_beat_an_id_and_reads_its_counts_afterwards(self):
        """Scenario-224: the id and limits are set by run-checkin, which the
        beat cannot change, and the notice is sent by the runner."""
        run = self._bin("run-checkin").read_text(encoding="utf-8")
        self.assertIn('export CHECKIN_BEAT_ID', run)
        self.assertIn("checkin-counts", run)
        self.assertIn("checkin-trips", run)
        # The email is the second trip of a day (once, marked), sent by cti-alert from the runner.
        self.assertIn('checkin-trips-emailed', run)
        self.assertIn("--kind HOLD", run)
        # Every wrapper the beat reads through cleans only inside a beat.
        for name in ("fleet-journal", "fleet-board", "fleet-db"):
            with self.subTest(name):
                self.assertIn("CHECKIN_BEAT_ID", self._bin(name).read_text(encoding="utf-8"))

    def test_the_board_takes_one_line_per_post_and_the_beat_cannot_prune_it(self):
        """A newline in a handle or kind wrote a second, forged board line
        (an @systemd ERROR, an @operator answer). And `fleet-board prune .`
        and `cti-budget record` were inside the beat's grant."""
        root = pathlib.Path(__file__).resolve().parents[2]
        board_bin = root / "fleet-kit" / "fleet" / "bin" / "fleet-board"
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "FLEET_HOME": d}

            def post(*args):
                return subprocess.run(["bash", str(board_bin), "post", *args],
                                      env=env, capture_output=True, text=True, check=False)

            board = pathlib.Path(d) / "board.md"
            self.assertEqual(post("@you", "@all", "INFO", "ok", "line\r\nnext\x1b[2J").returncode, 0)
            say = subprocess.run(["bash", str(board_bin), "say", "@all", "INFO", "said"],
                                 env=env, capture_output=True, text=True, check=False)
            self.assertEqual(say.returncode, 0, say.stderr)
            for h in ("(.*)*x", "@a|.*", "you"):
                with self.subTest(read=h):
                    r = subprocess.run(["bash", str(board_bin), "read", h],
                                       env=env, capture_output=True, text=True, check=False)
                    self.assertEqual(r.returncode, 2)
            for args in (
                ("@you\n[2026-11-03 06:00] @systemd", "@operator", "ERROR", "x"),
                ("@you", "@operator\n[x] @operator -> @you A", "INFO", "x"),
                ("@you", "@all", "INFO\nERROR", "x"),
                ("@you", "@all", "info", "x"),
                ("you", "@all", "INFO", "x"),
                ("@you", "@all;id", "INFO", "x"),
            ):
                with self.subTest(refused=args):
                    self.assertEqual(post(*args).returncode, 2)
            lines = board.read_text().splitlines()
            self.assertEqual(len(lines), 2, lines)
            self.assertTrue(lines[0].endswith("INFO     ok line next[2J"), lines[0])
            self.assertRegex(lines[1], r"\] @you +-> @all +INFO +said$")
        rules = self._orchestrator_grant()
        board = [r for r in rules if "fleet-board" in r]
        self.assertEqual(sorted(board), sorted(
            f"Bash($FLEET_CODE/bin/fleet-board {s}:*)" for s in ("say", "read", "tail", "resolve", "expire")))
        self.assertFalse(self._allowed(rules, "$FLEET_CODE/bin/fleet-board prune ."))
        self.assertFalse(self._allowed(rules, "$FLEET_CODE/bin/fleet-board post @operator @you A re:q1 yes"))
        self.assertFalse(self._allowed(rules, "$FLEET_CODE/bin/cti-budget record --exit 0"))
        self.assertFalse(self._allowed(rules, "$FLEET_CODE/bin/cti-budget check"))
        self.assertTrue(self._allowed(rules, "$FLEET_CODE/bin/cti-budget status"))

    def test_the_beat_prunes_the_board_only_by_id_or_age(self):
        """The heartbeat keeps the board tidy, but free-pattern prune let it
        archive everything (`prune .`), alerts included. resolve takes one
        board id; expire takes an age, and keeps ERROR lines a week."""
        root = pathlib.Path(__file__).resolve().parents[2]
        board_bin = root / "fleet-kit" / "fleet" / "bin" / "fleet-board"
        now = datetime.datetime.now()

        def ts(days):
            return (now - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M")

        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "FLEET_HOME": d}
            home = pathlib.Path(d)
            (home / "archive").mkdir()
            lines = [
                f"[{ts(1)}] @enrich  -> @you     Q        id=q17 NVD rate-limited",
                f"[{ts(1)}] @you     -> @enrich  A        re:q17 yes",
                f"[{ts(1)}] @you     -> @enrich  A        re:q170 a different id",
                f"[{ts(1)}] @you     -> @all     INFO     mentions id=q17x not q17",
                f"[{ts(10)}] @digest  -> @all     INFO     old news",
                f"[{ts(10)}] @systemd -> @operator ERROR    old failure",
                f"[{ts(3)}] @systemd -> @operator ERROR    recent failure",
                f"[{ts(3)}] @scout   -> @all     INFO     three days old",
                "no timestamp at all",
            ]
            (home / "board.md").write_text("\n".join(lines) + "\n")

            def board(*args):
                return subprocess.run(["bash", str(board_bin), *args], env=env,
                                      capture_output=True, text=True, check=False)

            self.assertEqual(board("resolve", "q17").returncode, 0)
            left = (home / "board.md").read_text()
            self.assertNotIn("id=q17 NVD", left)
            self.assertNotIn("re:q17 yes", left)
            self.assertIn("re:q170", left)
            self.assertIn("id=q17x", left)

            r = board("expire", "2")
            self.assertEqual(r.returncode, 0, r.stderr)
            left = (home / "board.md").read_text()
            for gone in ("old news", "old failure", "three days old"):
                self.assertNotIn(gone, left)
            for kept in ("recent failure", "re:q170", "no timestamp at all"):
                self.assertIn(kept, left)
            archived = (home / "archive" / "board-archive.md").read_text()
            for moved in ("id=q17 NVD", "re:q17 yes", "old news", "old failure"):
                self.assertIn(moved, archived)

            for args in (("resolve", "."), ("resolve", ".*"), ("resolve", "q1|q2"),
                         ("resolve", ""), ("expire", "0"), ("expire", "1"),
                         ("expire", "-5"), ("expire", "x"), ("expire", "9999")):
                with self.subTest(refused=args):
                    self.assertEqual(board(*args).returncode, 2)
        rules = self._orchestrator_grant()
        self.assertTrue(self._allowed(rules, "$FLEET_CODE/bin/fleet-board resolve q17"))
        self.assertTrue(self._allowed(rules, "$FLEET_CODE/bin/fleet-board expire 7"))
        self.assertFalse(self._allowed(rules, "$FLEET_CODE/bin/fleet-board prune ."))

    def test_fleet_timers_lists_the_fleets_timers_and_nothing_else(self):
        """systemctl list-timers:* could not stop or disable anything, but it
        took --host=user@box, which runs the query over ssh to any machine,
        and --machine. The wrapper passes --all and cti-agent-* patterns,
        after --, and nothing else."""
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "fleet-kit" / "fleet" / "bin" / "fleet-timers").read_text(encoding="utf-8")
        self.assertIn("\nSYSTEMCTL=/usr/bin/systemctl\n", src)
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            fake = d / "systemctl"
            fake.write_text('#!/bin/sh\nfor a; do echo "$a"; done\n')
            fake.chmod(0o755)
            w = d / "fleet-timers"
            w.write_text(src.replace("\nSYSTEMCTL=/usr/bin/systemctl\n", f"\nSYSTEMCTL={fake}\n"))

            def run(*args):
                return subprocess.run(["bash", str(w), *args], capture_output=True, text=True, check=False)

            for args, want in (
                ([], ["list-timers", "--no-pager", "--", "cti-agent-*"]),
                (["--all"], ["list-timers", "--no-pager", "--all", "--", "cti-agent-*"]),
                (["cti-agent-domains.timer"],
                 ["list-timers", "--no-pager", "--", "cti-agent-domains.timer"]),
                (["--all", "cti-agent-*"], ["list-timers", "--no-pager", "--all", "--", "cti-agent-*"]),
                (["-a"], ["list-timers", "--no-pager", "--all", "--", "cti-agent-*"]),
            ):
                with self.subTest(args=args):
                    r = run(*args)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout.splitlines(), want)
            for args in (
                ["--host=user@example.com"],
                ["-H", "user@example.com"],
                ["--all", "--host", "user@example.com"],
                ["--machine=x"],
                ["-M", "x"],
                ["--user"],
                ["--output=json"],
                ["sshd.timer"],
                ["cti-agent-x;id"],
                ["cti-agent-x", "--host=y"],
                ["cti-agent-$(id)"],
                ["cti-agent-[a-z]*"],
                ["cti-agent-?"],
                ["cti-agent-x\n--host=y"],
                ["cti-agent-x=y"],
            ):
                with self.subTest(refused=args):
                    r = run(*args)
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertEqual(r.stdout, "")

    def test_the_orchestrator_files_are_installed_root_owned(self):
        """CLAUDE.md and the skills steer the beat. The installer put them in
        the service account's state dir, owned by it; they now go to a
        root-owned directory under the code, and the old copies - and
        anything else Claude Code would load from there - are moved aside."""
        root = pathlib.Path(__file__).resolve().parents[2]
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        code = "\n".join(l for l in inst.split("\n") if not l.lstrip().startswith("#"))
        self.assertIn('AGENT_DIR="$CODE_DIR/orchestrator"', code)
        for line in re.findall(r"^\s*run install [^\n]*(?:\\\n[^\n]*)*", code, re.M):
            if "CLAUDE.md" in line or "skills" in line or "checkin-settings" in line:
                self.assertIn("-o root -g root", line, line)
                self.assertNotIn("$STATE_DIR", line, line)
        self.assertIn('"$CODE_DIR/bin/run-checkin" --audit', code)
        self.assertIn('run mv "$p" "$QUARANTINE/$rel"', code)
        self.assertTrue((root / "fleet-kit" / "fleet" / "checkin-settings.json").exists())
        settings = json.loads((root / "fleet-kit" / "fleet" / "checkin-settings.json").read_text())
        # Hooks on, and exactly one: the root-owned Bash guard. Project
        # settings are the only other source loaded, and they are root-owned.
        self.assertIs(settings["disableAllHooks"], False)
        self.assertEqual(settings["hooks"], {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "/opt/cti-agent/bin/checkin-bash-guard"}]}]})
        self.assertIs(settings["enableAllProjectMcpServers"], False)
        self.assertTrue({"Edit", "Write", "NotebookEdit"} <= set(settings["permissions"]["deny"]))

    def test_the_installer_quarantines_everything_the_audit_refuses(self):
        """run-checkin --audit refuses a beat over any steering file in the
        account's reach; install-fedora.sh is meant to move those aside first.
        The two lists drifted: the audit added auto-memory
        (~/.claude/projects/*/memory) and workflows, the installer did not, so
        an upgraded box failed its own install with a refusal it said the
        installer would fix."""
        root = pathlib.Path(__file__).resolve().parents[2]
        rc = (root / "fleet-kit" / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        audit = rc[rc.index("steering_problems() {"):]
        audit = audit[:audit.index("done")]
        quarantine = inst[inst.index('for p in "$STATE_DIR/CLAUDE.md"'):]
        quarantine = quarantine[:quarantine.index("; do")]
        missing = []
        # HOME and the config dir are the state dir on the Fedora layout;
        # AGENT_DIR is root-owned code and is not the service account's.
        for var, base in (("$CLAUDE_CFG", "$STATE_DIR/.claude"), ("$HOME", "$STATE_DIR")):
            for m in re.finditer(r'"' + re.escape(var) + r'"?(/[^"\s]*)"?', audit):
                tail = m.group(1)
                want = base + tail
                variants = {f'"{want}"', f'"{base}{tail.split("/*")[0]}"' + tail[len(tail.split("/*")[0]):]}
                if not any(v in quarantine for v in variants):
                    missing.append(f"{var}{tail} -> {want}")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_the_cti_agent_wrapper_runs_fleet_commands_by_name_only(self):
        """`sudo cti-agent ../../../usr/bin/env` joined the argument onto bin/
        and ran env as the service account with fleet.env loaded, printing
        every secret; ../../bin/bash was a shell. The wrapper now takes a name
        that is a regular file in bin/ and nothing else."""
        root = pathlib.Path(__file__).resolve().parents[2]
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        body = inst[inst.index("replace_file /usr/local/bin/cti-agent 0755 <<WRAP\n") + len("replace_file /usr/local/bin/cti-agent 0755 <<WRAP\n"):]
        body = body[:body.index("\nWRAP\n") + 1]
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            code, state, fake = d / "code", d / "state", d / "fakebin"
            for p in (code / "bin", code / "lanes", state, fake):
                p.mkdir(parents=True)
            (code / "bin" / "fleet-db").write_text("#!/bin/sh\n")
            (code / "bin" / "linked").symlink_to("/usr/bin/env")
            (fake / "sudo").write_text('#!/bin/sh\nfor a; do echo "$a"; done\n')
            (fake / "sudo").chmod(0o755)
            wrapper = d / "cti-agent"
            render = subprocess.run(
                ["bash", "-c", f'CODE_DIR="{code}" STATE_DIR="{state}" CONF_DIR="{d}" '
                 f'FLEET_USER=ctiagent; cat <<WRAP\n{body}WRAP\n'],
                capture_output=True, text=True, check=True)
            wrapper.write_text(render.stdout)
            env = {"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(d)}

            def run(*args):
                return subprocess.run(["bash", str(wrapper), *args], env=env,
                                      capture_output=True, text=True, check=False)

            # fleet-owners runs as root, never through sudo -u: as anyone
            # else it is refused before anything runs.
            (code / "bin" / "fleet-owners").write_text("#!/bin/sh\n")
            if os.geteuid() != 0:
                r = run("fleet-owners", "list")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(r.stdout, "", "sudo must not have been reached")
            r = run("fleet-db", "recent")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"{code}/bin/fleet-db", r.stdout.splitlines())
            # There is no lanes/ to run from: a .py there (left by an old
            # install) is not a fleet command.
            (code / "lanes" / "scout.py").write_text("")
            for cmd in ("../../../../usr/bin/env", "../../../../bin/bash", "/usr/bin/env",
                        "fleet-db/../../../x", "..", ".hidden", "Fleet-DB", "env",
                        "linked", "nope", "x.py", "scout.py", "../lanes/scout.py", "fleet-db\nid"):
                with self.subTest(refused=cmd):
                    r = run(cmd, "-c", "id")
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertEqual(r.stdout, "", "sudo must not have been reached")

    def test_a_hand_run_gets_its_timers_credentials_through_systemd_run(self):
        """Step 2 of splitting fleet.env: once a secret a command needs is
        stored as a credential, the wrapper runs the command as a transient
        unit with that command's ImportCredential= grants; until then it uses
        sudo, as before. No secret value ever reaches a command line."""
        root = pathlib.Path(__file__).resolve().parents[2]
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        start = "replace_file /usr/local/bin/cti-agent 0755 <<WRAP\n"
        body = inst[inst.index(start) + len(start):]
        body = body[:body.index("\nWRAP\n") + 1]
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            code, state, fake, store = d / "code", d / "state", d / "fakebin", d / "store"
            for p in (code / "bin", code / "share", state, fake, store):
                p.mkdir(parents=True)
            (code / "bin" / "cti-jira").write_text("#!/bin/sh\n")
            (code / "bin" / "fleet-db").write_text("#!/bin/sh\n")
            (code / "share" / "credentials.map").write_text("# comment\ncti-jira CLIENT_SECRET JIRA_API_TOKEN\n")
            for tool in ("sudo", "systemd-run"):
                (fake / tool).write_text(f'#!/bin/sh\necho "{tool}"\nfor a; do echo "$a"; done\n')
                (fake / tool).chmod(0o755)
            units = d / "units"
            units.mkdir()
            (units / "cti-agent-jira.service").write_text(
                f'ExecStart={code}/bin/cti-jira --for-real\n'
                'Environment="FLEET_ENV_FILES=/etc/x/00-core.env /etc/x/jira.env"\n')
            render = subprocess.run(
                ["bash", "-c", f'CODE_DIR="{code}" STATE_DIR="{state}" CONF_DIR="{d}" CREDSTORE_DIR="{store}" '
                 f'UNIT_DIR="{units}" FLEET_USER=ctiagent FLEET_GROUP=ctiagent; cat <<WRAP\n{body}WRAP\n'],
                capture_output=True, text=True, check=True)
            wrapper = d / "cti-agent"
            wrapper.write_text(render.stdout)
            env = {"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(d), "SUDO_USER": "operator",
                   "JIRA_API_TOKEN": "secret-value-x"}

            def run(*args):
                return subprocess.run(["bash", str(wrapper), *args], env=env,
                                      capture_output=True, text=True, check=False)

            r = run("cti-jira", "--check")
            self.assertEqual(r.stdout.splitlines()[0], "sudo", "nothing stored yet: the old path")
            (store / "JIRA_API_TOKEN").write_text("ciphertext")
            r = run("cti-jira", "--check")
            lines = r.stdout.splitlines()
            self.assertEqual(lines[0], "systemd-run", r.stdout + r.stderr)
            for want in ("ImportCredential=CLIENT_SECRET", "ImportCredential=JIRA_API_TOKEN", "User=ctiagent",
                         "--pipe", "--wait", "--expand-environment=no", f"{code}/bin/cti-jira", "--check"):
                self.assertIn(want, lines, want)
            self.assertTrue(any(l.startswith("--description=manual: cti-jira (by operator)") for l in lines))
            # Not a runner, so every settings file (there are none here).
            self.assertIn("--setenv=FLEET_ENV_FILES=", lines)
            self.assertNotIn("secret-value-x", r.stdout)
            r = run("fleet-db", "recent")
            self.assertEqual(r.stdout.splitlines()[0], "sudo", "a command that needs no secret keeps the old path")

    def test_the_generic_installer_stays_retired(self):
        """install.sh left the fleet's code owned by the service account.

        Retired for that reason; install-fedora.sh is the one installer, with
        code root-owned in /opt/cti-agent. Its units went with it.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        self.assertFalse((root / "fleet-kit" / "install.sh").exists())
        self.assertFalse((root / "fleet-kit" / "fleet" / "systemd").exists())

    def test_the_heartbeat_is_told_to_run_only_what_it_is_granted(self):
        """An instruction the grant cannot satisfy fails silently on a beat.

        CLAUDE.md said "you may act without asking on: running any lane", and
        the /checkin skill said to check timers with systemctl, recover with
        run-digest and escalate through mailer.py. None was granted. On an
        unattended beat a denied command has nobody to approve it, so the
        instruction simply does not happen - which is how "spotting that a
        timer got disabled", a headline duty in ARCHITECTURE.md, could not
        work at all.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        rules = self._orchestrator_grant()
        missing = []
        for name in ("fleet-kit/fleet/CLAUDE.md", "fleet-kit/fleet/skills/checkin/SKILL.md"):
            for cmd in self._commands_in((root / name).read_text(encoding="utf-8")):
                if not self._allowed(rules, cmd):
                    missing.append(f"{name}: {cmd!r} is not granted")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_every_yes_in_the_on_a_beat_column_is_granted_and_every_no_is_not(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        rules = self._orchestrator_grant()
        text = (root / "fleet-kit/fleet/CLAUDE.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| `([^`]+)` \| (yes[^|]*|no) \|", text, re.M)
        self.assertGreater(len(rows), 5, "the On a beat table was not found")
        wrong = []
        for cmd, beat in rows:
            cmd = re.split(r"\s[\[<]", cmd)[0].strip()
            if beat.startswith("yes, by subcommand"):
                continue  # checked against "What a beat can run" below
            if beat.startswith("yes") and not self._allowed(rules, cmd):
                wrong.append(f"says yes, not granted: {cmd}")
            if beat == "no" and self._allowed(rules, cmd):
                wrong.append(f"says no, but granted: {cmd}")
        self.assertEqual(wrong, [], "\n" + "\n".join(wrong))

    def test_the_what_a_beat_can_run_table_is_the_grant(self):
        """The table CLAUDE.md calls "the whole of your grant" must be granted,
        row by row. A bare subcommand in a row - `findings` after
        `$FLEET_CODE/bin/fleet-db recent` - belongs to that row's binary."""
        root = pathlib.Path(__file__).resolve().parents[2]
        rules = self._orchestrator_grant()
        text = (root / "fleet-kit/fleet/CLAUDE.md").read_text(encoding="utf-8")
        table = text[text.index("### What a beat can run"):text.index("**You cannot run any lane")]
        checked, wrong = 0, []
        for row in re.findall(r"^\| (.+?) \|", table, re.M):
            spans = re.findall(r"`([^`]+)`", row)
            if not spans or spans[0] == "Command":
                continue
            binary = None
            for span in spans:
                span = re.split(r"\s[\[<(…]|\s…", span)[0].replace(" …", "").strip()
                if span.startswith(("$FLEET_CODE/", "journalctl", "systemctl")):
                    binary = span.split()[0]
                    cmd = span
                elif binary:
                    cmd = binary + " " + span
                else:
                    continue
                checked += 1
                if not self._allowed(rules, cmd):
                    wrong.append(cmd)
        self.assertGreater(checked, 10, "the table was not parsed")
        self.assertEqual(wrong, [], "documented as granted but not: " + ", ".join(wrong))

    def test_what_the_prompt_forbids_is_not_granted(self):
        """A prohibition that lives only in the prompt is not a control.

        fleet-db:* granted `sent`, which fakes a delivered digest so run-digest
        skips the real one, and `finding`, which rewrites what the digest
        reports. cti-patchtuesday:* granted --mark-sent, which makes the daily
        drop a whole release's CVEs. The orchestrator reads text written by
        people who would like it to do exactly these things.
        """
        rules = self._orchestrator_grant()
        F = "$FLEET_CODE"
        for cmd in (
            f"{F}/bin/cti-patchtuesday --mark-sent",
            f"{F}/bin/cti-patchtuesday --month 2026-09 --mark-sent",
            f"{F}/bin/fleet-db sent 2026-10-06 0 0 0 0 0 x daily",
            f"{F}/bin/fleet-db finding upsert {{}}",
            f"{F}/bin/fleet-db note CVE-2026-0001 handled",
            f"{F}/bin/fleet-db init",
            f"{F}/bin/cti-mailbox",
            f"{F}/bin/cti-mailbox --for-real",
            f"{F}/bin/cti-mailbox --dry-run --lookback 8760h",
            f"{F}/bin/run-digest daily",
            f"{F}/bin/run-patchtuesday",
            f"{F}/bin/run-appscan",
            f"{F}/bin/run-mailbox-cleanup",
            f"{F}/bin/run-mailbox-cleanup --for-real",
            f"{F}/bin/cti-mailer --to someone@example.com",
            f"{F}/bin/cti-appscan --since 336h",
            f"python3 {F}/lanes/mailer.py --to-operator",
            "systemctl stop cti-agent-digest.timer",
            "systemctl disable cti-agent-digest.timer",
            "cat /etc/cti-agent/fleet.env",
        ):
            self.assertFalse(self._allowed(rules, cmd), f"granted: {cmd}")

    def test_the_mailbox_plan_is_granted_only_as_a_dry_run(self):
        """cti-mailbox moves mail unless --dry-run, so the grant is that exact
        command: not the bare one, not --for-real, nothing appended."""
        rules = self._orchestrator_grant()
        F = "$FLEET_CODE"
        self.assertTrue(self._allowed(rules, f"{F}/bin/cti-mailbox --dry-run"))
        for cmd in (f"{F}/bin/cti-mailbox", f"{F}/bin/cti-mailbox --for-real",
                    f"{F}/bin/cti-mailbox --dry-run --lookback 8760h"):
            self.assertFalse(self._allowed(rules, cmd), f"granted: {cmd}")

    def test_dry_run_cannot_mark_a_manifest_sent(self):
        """The grant is `cti-patchtuesday --dry-run:*`, which is safe only if
        no invocation starting with --dry-run can write. --mark-sent's branch
        returns before --dry-run is looked at, so the refusal has to come
        first."""
        root = pathlib.Path(__file__).resolve().parents[2]
        src = (root / "cmd" / "cti-patchtuesday" / "main.go").read_text(encoding="utf-8")
        guard = src.find("if *markSent && *dryRun {")
        branch = src.find("if *markSent {")
        self.assertGreater(guard, 0, "no refusal of --mark-sent with --dry-run")
        self.assertLess(guard, branch, "the refusal comes after the --mark-sent branch")

    def test_the_heartbeat_is_never_told_to_read_the_config_file(self):
        """fleet.env holds the Graph secret, the Qualys password and a Claude
        token. What the model reads is sent with its context."""
        root = pathlib.Path(__file__).resolve().parents[2]
        for name in ("fleet-kit/fleet/CLAUDE.md", "fleet-kit/fleet/skills/checkin/SKILL.md"):
            text = (root / name).read_text(encoding="utf-8")
            for bad in ("Load `$FLEET_ENV`", "Read those on your first beat",
                        "cat $FLEET_ENV", "cat \"$FLEET_ENV\""):
                self.assertNotIn(bad, text, f"{name} tells the agent to read fleet.env")

    def test_every_unit_logs_under_its_own_name(self):
        """A unit that tags its journal lines with another unit's name.

        cti-agent-appscan.service was generated from the weekly digest's unit
        and kept SyslogIdentifier=cti-agent-weekly. Its log lines - including
        "AUTH FAILED on N scan(s)" - then read as the weekly digest's, and
        `journalctl -t cti-agent-appscan` returned nothing at all. Same origin
        as the stray "weekly" argument its ExecStart arrived with.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        wrong = []
        for unit in sorted((root / "fleet-kit" / "fleet").glob("systemd*/*.service")):
            m = re.search(r"^SyslogIdentifier=(.+)$",
                          unit.read_text(encoding="utf-8"), re.M)
            want = unit.stem.rstrip("@")
            if m and m.group(1).strip() != want:
                wrong.append(f"{unit.parent.name}/{unit.name} logs as "
                             f"{m.group(1).strip()!r}, want {want!r}")
        self.assertEqual(wrong, [], "\n" + "\n".join(wrong))

    def test_every_command_that_reads_credentials_loads_fleet_env(self):
        """A binary run by hand must see the config the timer sees.

        internal/config reads the environment. A command that does not call
        fleetenv.Load() only works when a runner has sourced the file first, so
        `sudo cti-agent <binary>` - the one-off path - fails with "missing
        required environment variables" on a box where every one is set.

        cti-appscan was that command. Fixing its runner made the timer work and
        left the hand-run broken, and the hand-run is exactly what somebody
        reaches for to test a two-week window.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        missing = []
        for main in sorted((root / "cmd").glob("*/main.go")):
            src = main.read_text(encoding="utf-8")
            code = "\n".join(l for l in src.split("\n")
                             if not l.lstrip().startswith("//"))
            if re.search(r"\bconfig\.Load\w*\(", code) and "fleetenv.Load()" not in code:
                missing.append(f"{main.parent.name} calls config.Load* but never "
                               f"fleetenv.Load(), so it only works under a runner")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_an_authentication_failure_reaches_the_operator(self):
        """A broken scanner credential must not be reported only to the people
        who cannot fix it.

        The AppSec report goes to the team that owns application code. They
        cannot repair a Qualys authentication record, and a week where the
        scanner silently stopped logging in is a week where their numbers
        describe a smaller surface than last week's while looking like an
        improvement.

        So the chain has to be intact end to end, and every link of it is
        hand-written: cti-appscan has to be ASKED for the file (--auth-fail-out
        is opt-in), the runner has to test the file, and it has to call
        cti-alert. Any one of those missing leaves a lane that still sends a
        perfectly ordinary-looking report and escalates nothing - which is this
        project's recurring failure, something reporting success while doing
        nothing.
        """
        root = pathlib.Path(__file__).resolve().parents[2]

        # CODE ONLY. Written first with the whole file, and it passed while the
        # flag had been deleted from the invocation - because the comment four
        # lines above still mentioned "--auth-fail-out". A test satisfied by
        # prose about the thing is the same bug as the one it is guarding.
        def code(path):
            return "\n".join(
                line for line in path.read_text(encoding="utf-8").split("\n")
                if not line.lstrip().startswith(("#", "//")))

        runner = code(root / "fleet-kit" / "fleet" / "bin" / "run-appscan")
        main = code(root / "cmd" / "cti-appscan" / "main.go")

        # The INVOCATION, not a mention. Stripping comments was still not
        # enough: the runner has a `log "...predates --auth-fail-out..."` line,
        # which is executable code, so a flag deleted from the command line
        # left the assertion passing on a log message about its absence.
        self.assertRegex(
            runner, r'"\$APPSCAN"[^\n]*(\\\n[^\n]*)*--auth-fail-out',
            "run-appscan does not pass --auth-fail-out to cti-appscan, so "
            "there is nothing to escalate no matter how many logins failed")
        self.assertIn('"auth-fail-out"', main,
                      "cti-appscan does not define --auth-fail-out, so the "
                      "runner is passing a flag that will stop the lane dead")
        self.assertRegex(
            runner, r'"\$ALERT"\s+--unit',
            "run-appscan never runs cti-alert - assigning its path to a "
            "variable is not calling it, and an authentication failure would "
            "be recorded in a 0600 file nobody opens")
        self.assertRegex(
            runner, r'-s\s+"\$AUTHFAIL"',
            "run-appscan does not test whether the failure file has anything "
            "in it; `-f` alone fires on every run, because the file is written "
            "even when nothing failed")
        # Order matters: the report is the deliverable, and an alerting
        # problem must not cost the weekly mail.
        self.assertLess(
            runner.index("--lane was"), runner.index("cti-alert"),
            "run-appscan alerts before it sends - a cti-alert failure would "
            "then take the report down with it")

    def test_the_weekly_neither_clobbers_the_daily_nor_loses_ticket_links(self):
        """On a Monday the daily (06:00) and weekly (07:00) both wrote
        enriched-$DAY.json, so the weekly overwrote the day's findings, and it
        rendered with no ticket links because it never runs cti-jira."""
        root = pathlib.Path(__file__).resolve().parents[2]
        text = (root / "fleet-kit" / "fleet" / "bin" / "run-digest").read_text(encoding="utf-8")
        code = "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))
        self.assertIn('ENRICHED="$FLEET_HOME/state/weekly-enriched-$DAY.json"', code,
                      "the weekly writes the same enriched file as the daily")
        self.assertRegex(code, r'cp "\$LATEST_MAP" "\$\{ENRICHED%\.json\}-tickets\.json"',
                         "the weekly does not borrow the daily ticket map")
        main = (root / "cmd" / "cti-jira" / "main.go").read_text(encoding="utf-8")
        self.assertRegex(main, r"range followUp\(",
                         "cti-jira discards the follow-up's ticket references, so the "
                         "digest links only tickets for CVEs in today's mail")

    # -- man pages -----------------------------------------------------------
    #
    # Every operator command has a page, and every flag or subcommand the code
    # accepts appears in it. The pages are written from the source; this is
    # what stops them drifting from it when a flag is added later.

    MAN_GO_FLAG = re.compile(
        r"\b\w+\.(?:String|Bool|Int|Int64|Uint|Float64|Duration|Var|Func|"
        r"StringVar|BoolVar|IntVar|Int64Var|DurationVar|Float64Var)\("
        r"(?:&[\w.\[\]]+,\s*)?\"([a-z][a-z0-9-]*)\"")

    def _man(self, name):
        root = pathlib.Path(__file__).resolve().parents[2]
        page = root / "man" / "man1" / (name + ".1")
        self.assertTrue(page.exists(), f"no man page for {name}: {page}")
        # roff escapes a hyphen as \-; compare in plain text.
        return page.read_text(encoding="utf-8").replace("\\-", "-")

    def _assert_documented(self, name, words, kind="flag"):
        text = self._man(name)
        missing = []
        for w in sorted(set(words)):
            needle = "--" + w if kind == "flag" else w
            if not re.search(r"(?<![\w-])" + re.escape(needle) + r"(?![\w-])", text):
                missing.append(needle)
        self.assertEqual(missing, [], f"{name}.1 does not document: {missing}")

    def test_every_go_command_flag_is_in_its_man_page(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        for d in sorted((root / "cmd").iterdir()):
            flags = []
            for f in d.glob("*.go"):
                if f.name.endswith("_test.go"):
                    continue
                text = f.read_text(encoding="utf-8")
                flags += self.MAN_GO_FLAG.findall(text)
                if d.name == "fleet-trace":
                    # Subcommands with hand-parsed flags, as the Python had.
                    flags += [x for x in re.findall(r'"--([a-z][a-z0-9-]*)"', text) if x != "help"]
            with self.subTest(cmd=d.name):
                # cti-agent is not installed; the guard reads only stdin.
                self.assertTrue(flags or d.name in ("cti-agent", "checkin-bash-guard"), f"no flags found in {d}")
                self._assert_documented(d.name, flags)

    def test_every_runner_argument_is_in_its_man_page(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        case_label = re.compile(r"^\s*((?:--)?[a-z][a-z0-9-]*(?:\|(?:--)?[a-z][a-z0-9-]*)*)\)", re.M)
        scripts = sorted((root / "fleet-kit" / "fleet" / "bin").glob("run-*"))
        scripts.append(root / "fleet-kit" / "bin" / "dev-run")
        for script in scripts:
            words = []
            for label in case_label.findall(script.read_text(encoding="utf-8")):
                words += [w for w in label.split("|") if w.startswith("--")]
            with self.subTest(runner=script.name):
                self._assert_documented(script.name, [w[2:] for w in words])

    def test_every_fleet_tool_subcommand_is_in_its_man_page(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        db = (root / "fleet-kit" / "fleet" / "bin" / "fleet-db").read_text(encoding="utf-8")
        subs = re.findall(r'^\s*(?:if|elif) cmd == "([a-z-]+)"', db, re.M)
        self.assertGreater(len(subs), 5)
        self._assert_documented("fleet-db", subs, kind="word")
        owners = (root / "fleet-kit" / "fleet" / "bin" / "fleet-owners").read_text(encoding="utf-8")
        subs = re.findall(r'add_parser\("([a-z-]+)"', owners)
        self.assertGreater(len(subs), 10)
        self._assert_documented("fleet-owners", subs, kind="word")
        self._assert_documented("fleet-owners", re.findall(r'add_argument\("--([a-z-]+)"', owners))
        board = (root / "fleet-kit" / "fleet" / "bin" / "fleet-board").read_text(encoding="utf-8")
        self._assert_documented("fleet-board", re.findall(r"^\s{2}([a-z]+)\)", board, re.M), kind="word")

    def test_man_pages_have_the_required_sections(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        pages = sorted((root / "man" / "man1").glob("*.1"))
        self.assertGreaterEqual(len(pages), 20)
        for page in pages:
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                for sec in ("NAME", "SYNOPSIS", "DESCRIPTION", "EXIT STATUS", "EXAMPLES", "SEE ALSO"):
                    self.assertRegex(text, r"(?m)^\.SH \"?" + sec + r"\"?\s*$", f"no {sec}")
                self.assertRegex(text, r"(?m)^\.SH \"?(OPTIONS|COMMANDS)",
                                 "neither OPTIONS nor COMMANDS")

    def test_the_installer_installs_the_man_pages(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/local/share/man/man1", inst)

    def test_the_domains_lane_is_wired_and_read_only(self):
        """The weekly domains check: its own audience, a dry run that does not
        advance the baseline, and a registrar client that never asks for the
        auth codes that would let anyone transfer our domains away."""
        root = pathlib.Path(__file__).resolve().parents[2]

        def code(path):
            return "\n".join(
                line for line in path.read_text(encoding="utf-8").split("\n")
                if not line.lstrip().startswith(("#", "//")))

        runner = code(root / "fleet-kit" / "fleet" / "bin" / "run-domains")
        self.assertRegex(runner, r'"\$MAILER"\s+--lane dom\b',
                         "run-domains does not send through cti-mailer --lane dom")
        self.assertIn('NOSTATE="--no-state-write"', runner,
                      "a dry run would advance last week's baseline, so the real "
                      "run reports no changes in a week that had them")
        self.assertRegex(runner, r'"\$DOMAINS"[^\n]*\$NOSTATE',
                         "--no-state-write is set but never passed to cti-domains")

        client = code(root / "internal" / "domains" / "godaddy" / "client.go")
        self.assertNotRegex(client.lower(), r'q\.set\("includes",\s*"[^"]*authcode',
                            "the GoDaddy client requests authCode")
        self.assertIn('q.Set("includes", "nameServers")', client)
        self.assertNotIn("http.MethodPost", client, "the registrar client must only read")

        unit = (root / "fleet-kit" / "fleet" / "systemd-fedora"
                / "cti-agent-domains.service").read_text(encoding="utf-8")
        self.assertIn("SyslogIdentifier=cti-agent-domains", unit)

        env = (root / "fleet-kit" / "fleet" / "fleet.env.example").read_text(encoding="utf-8")
        for var in ("DOM_TO=", "DOM_ALLOW_TO=", "GODADDY_PAT=", "DOMAINS_FILE="):
            self.assertIn("\n" + var, env, f"{var} is not documented in fleet.env.example")

        # The inventory is an operator file. A domains.txt in the public
        # repository is the list this lane exists to keep private.
        tracked = [p for p in root.rglob("domains.txt") if ".git" not in p.parts]
        self.assertEqual(tracked, [], "a domains.txt is inside the repository tree")
        # Same for the AppSec lane's owners: people's names and emails.
        owners = [p for p in root.rglob("app-owners.txt") if ".git" not in p.parts]
        self.assertEqual(owners, [], "an app-owners.txt is inside the repository tree")

    def test_the_appscan_report_does_not_call_a_public_site_a_coverage_gap(self):
        """An unauthenticated scan is a label, not a defect.

        The first real send named three applications under a heading reading
        COVERAGE GAPS. All three are public sites with no login at all, so
        there is no missing authentication record and nothing for anybody to
        fix. A report whose loudest section is a standing complaint about
        applications being what they are teaches its readers to skip the top
        of the page.

        Asserted here as well as in the Go tests because this one came from
        the operator reading the actual email, and the wording is the thing
        that was wrong.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        for name in ("report.go", "types.go"):
            src = (root / "internal" / "appscan" / name).read_text(encoding="utf-8")
            code = "\n".join(
                line for line in src.split("\n")
                if not line.lstrip().startswith("//"))
            for banned in ("COVERAGE GAP", "coverage gap", "Coverage gap"):
                self.assertNotIn(
                    banned, code,
                    f"internal/appscan/{name} still frames a scan as a "
                    f"coverage gap outside a comment")
            self.assertNotIn(
                "func (a Auth) Blind()", code,
                "Auth.Blind() conflated 'this site has no login' with "
                "'authentication failed' - the two need different handling, "
                "and only the second is a fault")

    def test_the_taskfile_defines_no_task_twice(self):
        """A duplicate YAML key is silently the last one.

        `fmt:check` was defined twice. YAML keeps the later definition and says
        nothing, so the gate that ran was not the gate in the commit - and the
        guidance it was supposed to print ("run task fmt and COMMIT the
        result") never appeared, because that version was dead text in a file
        that parsed cleanly.

        PyYAML will not help here: safe_load accepts duplicates and returns the
        last. So this reads the lines.

        The consequence is the project's recurring one. Two definitions of a
        build gate look like one working gate, and the one being maintained may
        not be the one being run.
        """
        path = pathlib.Path(__file__).resolve().parents[2] / "Taskfile.yml"
        seen = {}
        dupes = []
        for n, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            m = re.match(r"^  ([A-Za-z][\w:.-]*):\s*$", line)
            if not m:
                continue
            name = m.group(1)
            if name in seen:
                dupes.append(f"{name} defined at line {seen[name]} and again at {n}")
            else:
                seen[name] = n
        self.assertEqual(dupes, [], "\n" + "\n".join(dupes))

    def test_no_go_regex_uses_a_backreference_or_lookaround(self):
        """Go's regexp is RE2. Python's is not.

        Twice in one session a parser was prototyped in Python - where the
        pattern was verified against the real input - and then ported to Go
        unchanged, carrying a `\\1` backreference with it. Go panics at package
        init:

            regexp: Compile(`<(style|script|head)[^>]*>.*?</\\1>`):
            invalid escape sequence: `\\1`

        A panic is the good outcome and it still costs a full ship cycle to
        find, because it only appears once the package is built. Prototyping
        elsewhere is what makes these parsers verifiable without a toolchain,
        so the handoff is where the defect enters and the handoff is what needs
        the gate.

        RE2 also has no lookahead or lookbehind, which fail the same way.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        call = re.compile(r'regexp\.(?:Must)?Compile\(\s*`([^`]*)`', re.S)
        banned = (
            (re.compile(r'\\[1-9]'), "backreference"),
            (re.compile(r'\(\?[=!]'), "lookahead"),
            (re.compile(r'\(\?<[=!]'), "lookbehind"),
        )
        found = []
        for f in root.rglob("*.go"):
            if ".git" in f.parts:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for m in call.finditer(text):
                for probe, what in banned:
                    if probe.search(m.group(1)):
                        line = text[:m.start()].count("\n") + 1
                        found.append(
                            f"{f.relative_to(root)}:{line} uses a {what}, which "
                            f"RE2 does not support: {m.group(1)[:60]}")
        self.assertEqual(found, [], "\n" + "\n".join(found))

    def test_no_source_file_contains_an_invisible_character(self):
        """Write \\ufeff, never the character itself.

        Both of these lanes parse text that legitimately contains byte-order
        marks, zero-width spaces and non-breaking spaces, so the characters get
        pasted into source while working on the parsers. The result is a string
        literal that looks correct and is not, and that no amount of reading
        the diff will reveal - the characters render as nothing.

        gofmt rejects a BOM outright, which is how one was caught in
        internal/defender/parse.go. Nothing does that for Python, so a literal
        zero-width space in a fixture here would sit undetected and the test
        built on it would be quietly testing the wrong string.
        """
        # Detected by Unicode CATEGORY, not from a list of characters.
        #
        # The list version knew three: BOM, zero-width space, non-breaking
        # space. It then waved through a SOFT HYPHEN pasted into a Go comment,
        # because a list only ever contains the characters somebody already
        # got caught by.
        #
        # Cf is Unicode's "format" category - the BOM, zero-width joiners, and
        # the bidirectional overrides used by the Trojan Source class of attack
        # to make source read one way to a human and another to a compiler. In
        # a security codebase those have no business in a source file at all.
        # Zs is every space character except the ordinary one.
        root = pathlib.Path(__file__).resolve().parents[2]
        found = []
        # Plus every script with no extension: fleet-kit/fleet/bin is Python
        # and bash named like commands, and a glob on *.py never saw it. That
        # is how a regex in fleet-trace shipped with the bidi overrides
        # themselves in it instead of their escapes, caught only by bandit.
        scripts = [f for f in root.rglob("*") if f.is_file() and not f.suffix
                   and ".git" not in f.parts and f.read_bytes()[:2] == b"#!"]
        for pattern in ("**/*.py", "**/*.go", "**/*.sh", "**/*.yml", scripts):
            for f in (root.glob(pattern) if isinstance(pattern, str) else pattern):
                if ".git" in f.parts or "__pycache__" in f.parts:
                    continue
                try:
                    text = f.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                for i, ch in enumerate(text):
                    if ch in " \t\n\r":
                        continue
                    if unicodedata.category(ch) not in ("Cf", "Zs"):
                        continue
                    found.append(
                        f"{f.relative_to(root)}:{text[:i].count(chr(10)) + 1} "
                        f"contains U+{ord(ch):04X} "
                        f"{unicodedata.name(ch, 'unnamed')} - "
                        f"write the escape instead")
                    break  # one per file is enough to act on
        self.assertEqual(found, [], "\n" + "\n".join(found))



# One stub for every binary a runner calls. Each records its argv; the few
# whose output a runner reads produce just enough of it.
_STUB = r"""#!/usr/bin/env bash
me=$(basename "$0")
echo "$me $*" >> "$STUB_LOG"
next=""
for a in "$@"; do
  case "$next" in
    out|text) echo "<p>x</p>" > "$a" ;;
    subj)     echo "Weekly domains check" > "$a" ;;
    json)     echo "{}" > "$a" ;;
    authfail) printf 'App One\trecord\tFAILED\n' > "$a" ;;
    ref)      echo '{"action":"commented","key":"SEC-50"}' > "$a" ;;
    outdir)   # cti-appreport --deliveries: one email ready, one held
              mkdir -p "$a/app"; echo "Web application scan results: App One" > "$a/app/subject.txt"
              echo "App One" > "$a/app/app.txt"; echo "<p>x</p>" > "$a/app/mail.html"
              printf 'id:1\tref1\t1\t%s\t\n' "$a/app" > "$a/send.tsv"
              printf 'id:2\tref2\theld: the scan did not finish\n' > "$a/held.tsv"
              printf 'App Two: the scan did not finish\n' > "$a/held.txt" ;;
  esac
  next=""
  case "$a" in
    --out|--text-out|--csv-out|--actions-out|--seen-out|--tickets-out|--websites-out|--fixes-out) next=out ;;
    --subject-out) next=subj ;;
    --json) next=json ;;
    --auth-fail-out) next=authfail ;;
    --ref-out) next=ref ;;
    --out-dir) next=outdir ;;
  esac
done
case "$me $*" in
  "cti-mailer --lane owner --armed"*) [ -n "${OWNER_ALLOW_DOMAINS:-}" ] || exit 3 ;;
  "cti-appscan --subject-only"*)      echo "AppSec weekly" ;;
  "cti-brief"*"--subject-only"*)      echo "CTI daily digest" ;;
  "cti-patchtuesday"*"--subject-only"*) echo "Microsoft Patch Tuesday for October 2026" ;;
  "fleet-db was-sent"*)               echo no ;;
  "fleet-db rollup"*)                 echo '{"total": 0, "counts": {}}' ;;
esac
exit 0
"""

class RunnersToDev(unittest.TestCase):
    """--to-dev on a runner: real pipeline, mail to FLEET_DEV_EMAIL only, and
    none of the side effects a real send has."""

    BIN = ("cti-mailer", "cti-alert", "cti-jira", "cti-domains", "cti-appscan", "cti-appreport",
           "cti-patchtuesday", "cti-enrich", "cti-brief", "fleet-db", "fleet-board")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.code, self.home = root / "code", root / "home"
        (self.code / "bin").mkdir(parents=True)
        (self.code / "lanes").mkdir()
        self.home.mkdir()
        for name in self.BIN:
            p = self.code / "bin" / name
            p.write_text(_STUB)
            p.chmod(0o755)
        agent = root / "agent"
        agent.mkdir()
        (agent / "cti-agent").write_text(
            '#!/usr/bin/env bash\necho "| CVE-2026-1 |" > "$REPORT_PATH"\n')
        (agent / "cti-agent").chmod(0o755)
        self.log = root / "calls.log"
        self.log.write_text("")
        self.envfile = root / "fleet.env"
        self.base = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(root),
            "FLEET_HOME": str(self.home),
            "FLEET_CODE": str(self.code),
            "FLEET_ENV": str(self.envfile),
            "STUB_LOG": str(self.log),
            "CTI_AGENT_DIR": str(agent),
            "GRAPH_MAILBOX": "fleet@example.com",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def run_lane(self, runner, *args, dev="dev@example.com", env=""):
        self.envfile.write_text((f"FLEET_DEV_EMAIL={dev}\n" if dev else "") + env)
        r = subprocess.run(["bash", str(KIT / "fleet" / "bin" / runner), *args],
                           env=self.base, capture_output=True, text=True, timeout=60, check=False)
        return r, self.log.read_text().splitlines()

    def test_quarantined_fleet_mail_is_escalated_never_released(self):
        """cti-mailbox names mail the filter quarantined that a lane reads; the
        runner tells the operator (board, and cti-alert on a real run). The
        fleet never releases it: the digest's Release link acts on a bare GET."""
        line = ("QUARANTINE: the mail filter is holding mail the fleet reads: "
                "qualys@qualys.net - Qualys: Scan Results. Release it in the quarantine portal; "
                "the fleet never releases mail itself.")
        clean = self.code / "bin" / "cti-mailbox"
        clean.write_text('#!/usr/bin/env bash\necho "cti-mailbox $*" >> "$STUB_LOG"\n'
                         f"echo '{line}'\n")
        clean.chmod(0o755)
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        alerts = [c for c in calls if c.startswith("cti-alert ")]
        self.assertEqual(len(alerts), 1, calls)
        self.assertIn("--kind ESCALATION", alerts[0])
        self.assertIn("--for-real", alerts[0])
        self.assertIn("Qualys: Scan Results", alerts[0])
        self.assertTrue(any(c.startswith("fleet-board post @mailbox @you WARN QUARANTINE:") for c in calls), calls)

        self.log.write_text("")
        r, calls = self.run_lane("run-mailbox-cleanup", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(any(c.startswith("cti-alert ") for c in calls),
                         "a dry run must not mail the operator")
        self.assertIn("would alert the operator", r.stdout)

    def _fake_audit(self, exit_code=0):
        a = self.code / "bin" / "cti-audit"
        a.write_text('#!/usr/bin/env bash\necho "cti-audit $*" >> "$STUB_LOG"\n'
                     f"exit {exit_code}\n")
        a.chmod(0o755)

    def test_the_cleanup_prunes_the_audit_trail_to_120_days(self):
        """The housekeeping lane enforces the audit trail's retention: 120 days
        by default, AUDIT_RETAIN_DAYS to change it, a dry run only lists."""
        self._fake_audit()
        self._fake_mailbox()
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cti-audit --prune --days 120", calls)
        self.assertNotIn("cti-audit --prune --days 120 --dry-run", calls)
        self.assertLess(calls.index("cti-audit --prune --days 120"),
                        next(i for i, c in enumerate(calls) if c.startswith("cti-mailbox ")),
                        "retention must run before the mailbox work, so a Graph failure cannot skip it")

        self.log.write_text("")
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real", env="AUDIT_RETAIN_DAYS=30\n")
        self.assertIn("cti-audit --prune --days 30", calls)

        self.log.write_text("")
        r, calls = self.run_lane("run-mailbox-cleanup", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cti-audit --prune --days 120 --dry-run", calls)
        self.assertNotIn("cti-audit --prune --days 120", calls, "a dry run must not delete audit files")

    def test_a_nonsense_retention_setting_falls_back_to_120_and_says_so(self):
        self._fake_audit()
        self._fake_mailbox()
        for bad in ("0", "abc", "-5", "12d"):
            self.log.write_text("")
            r, calls = self.run_lane("run-mailbox-cleanup", "--for-real", env=f"AUDIT_RETAIN_DAYS={bad}\n")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("cti-audit --prune --days 120", calls, bad)
            self.assertTrue(any(c.startswith("fleet-board post @mailbox @you WARN AUDIT_RETAIN_DAYS=") for c in calls), (bad, calls))

    def test_a_failed_prune_warns_and_the_mailbox_work_still_runs(self):
        self._fake_audit(exit_code=1)
        self._fake_mailbox()
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, "a retention problem must not fail the unit")
        self.assertTrue(any(c.startswith("cti-mailbox ") for c in calls), calls)
        self.assertTrue(any(c.startswith("fleet-board post @mailbox @you WARN audit trail retention failed") for c in calls), calls)

    def test_without_cti_audit_the_lane_says_so_and_carries_on(self):
        self._fake_mailbox()
        (self.code / "bin" / "cti-audit").unlink(missing_ok=True)
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("not being pruned", r.stdout)
        self.assertTrue(any(c.startswith("cti-mailbox ") for c in calls), calls)

    def _fake_mailbox(self, *lines):
        clean = self.code / "bin" / "cti-mailbox"
        body = "".join(f"echo '{ln}'\n" for ln in lines)
        clean.write_text('#!/usr/bin/env bash\necho "cti-mailbox $*" >> "$STUB_LOG"\n' + body)
        clean.chmod(0o755)

    def test_weekly_summary_counts_the_sweep_and_escalates_never_read_mail(self):
        """Mail swept to Unhandled is counted once a week on the board, and
        mail no lane has read for over a week goes to the operator by mail -
        once a week, not every morning."""
        never = ("NEVER-READ: 2 message(s) no lane has read have been in the inbox over "
                 "168h0m0s (oldest 9d)")
        self._fake_mailbox("  archive 1   delete 0   leave 3 (2 never read, 1 not CTI mail)",
                           "LEFT: never-read=2 (2 over 7d, oldest 9d) not-lane-mail=1",
                           "STALE: moved=4 flagged=1 failed=0 folder=Unhandled", never)
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        week = [c for c in calls if c.startswith("fleet-board post @mailbox @you INFO mailbox week:")]
        self.assertEqual(len(week), 1, calls)
        self.assertIn("4 message(s) swept to the Unhandled folder", week[0])
        self.assertIn("LEFT: never-read=2", week[0])
        alerts = [c for c in calls if c.startswith("cti-alert ")]
        self.assertEqual(len(alerts), 1, calls)
        self.assertIn("--kind ESCALATION", alerts[0])
        self.assertIn("no lane has read", alerts[0])
        self.assertTrue(any(c.startswith("fleet-board post @mailbox @you WARN NEVER-READ:") for c in calls))

        # The next morning: the board still hears about it, the operator's
        # inbox does not, and the week's sweep keeps adding up.
        self.log.write_text("")
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(any(c.startswith("cti-alert ") for c in calls), "escalated twice in one week")
        self.assertFalse(any("mailbox week:" in c for c in calls), "summarised twice in one week")
        self.assertTrue(any(c.startswith("fleet-board post @mailbox @you WARN NEVER-READ:") for c in calls))
        rows = (self.home / "state" / "mailbox-week.tsv").read_text().splitlines()
        self.assertEqual([r.split("\t")[1] for r in rows], ["4", "4"])

        # A week on, it is due again and sums the last seven days.
        stamp = self.home / "state" / "mailbox-week.stamp"
        old = time.time() - 7 * 86400
        os.utime(stamp, (old, old))
        self.log.write_text("")
        r, calls = self.run_lane("run-mailbox-cleanup", "--for-real")
        week = [c for c in calls if c.startswith("fleet-board post @mailbox @you INFO mailbox week:")]
        self.assertEqual(len(week), 1, calls)
        self.assertIn("12 message(s) swept", week[0])

    def test_weekly_summary_dry_run_posts_and_records_nothing(self):
        self._fake_mailbox("STALE: would-move=4 flagged=0 folder=Unhandled",
                           "NEVER-READ: 1 message(s) no lane has read have been in the inbox over 168h0m0s (oldest 8d)")
        r, calls = self.run_lane("run-mailbox-cleanup", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(any(c.startswith("cti-alert ") for c in calls), calls)
        self.assertFalse(any("mailbox week:" in c for c in calls), calls)
        self.assertIn("would post the weekly summary", r.stdout)
        self.assertFalse((self.home / "state" / "mailbox-week.tsv").exists())
        self.assertFalse((self.home / "state" / "mailbox-week.stamp").exists(),
                         "a rehearsal used up this week's summary")

    def assertTestSend(self, runner, *args):
        r, calls = self.run_lane(runner, *args, "--to-dev")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        sends = [c for c in calls if c.startswith("cti-mailer ")]
        self.assertEqual(len(sends), 1, calls)
        self.assertIn("--to-dev", sends[0])
        self.assertNotIn("--lane", sends[0], "a test send reached a lane's audience")
        self.assertNotIn("--dry-run", sends[0], "--to-dev alone must actually send")
        for c in calls:
            self.assertNotIn("--for-real", c, f"a test send made a real change: {c}")
            self.assertNotIn("--mark-sent", c, c)
            self.assertFalse(c.startswith("fleet-db sent"), c)
            self.assertFalse(c.startswith("fleet-board post"), f"a test send posted to the board: {c}")
        return calls

    def test_digest(self):
        self.assertTestSend("run-digest", "daily")

    def test_patchtuesday_including_a_replay_without_for_real(self):
        self.assertTestSend("run-patchtuesday")
        self.log.write_text("")
        self.assertTestSend("run-patchtuesday", "--month", "2026-08")

    def test_domains_leaves_the_baseline_alone(self):
        calls = self.assertTestSend("run-domains")
        probe = [c for c in calls if c.startswith("cti-domains ")]
        self.assertIn("--no-state-write", probe[0])

    def test_appscan_sends_its_alert_to_dev_too(self):
        calls = self.assertTestSend("run-appscan")
        alerts = [c for c in calls if c.startswith("cti-alert ")]
        self.assertEqual(len(alerts), 1, calls)
        self.assertIn("--to-dev", alerts[0])

    def test_appscan_calls_the_scanner_once_per_run(self):
        # The subject used to come from a second `cti-appscan --subject-only`
        # - a full re-run that repeated every Qualys WAS call for one line.
        # One report run per send, with --subject-out; --stamp-tickets and
        # --commit-seen only read files and do not count.
        for args in (["--to-dev"], ["--dry-run"], ["--for-real"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appscan", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                runs = [c for c in calls if c.startswith("cti-appscan ")
                        and "--stamp-tickets" not in c and "--commit-seen" not in c]
                self.assertEqual(len(runs), 1, runs)
                self.assertIn("--subject-out", runs[0])
                self.assertNotIn("--subject-only", runs[0])

    def test_appscan_records_what_it_saw_only_after_a_real_send(self):
        # The mailbox cleanup archives a WAS notice once the AppSec lane has
        # "seen" it. That has to mean the report reached App Dev - a dry run
        # or a test send to the developer must not license archiving.
        for args, want in ((["--to-dev"], False), (["--dry-run"], False), (["--for-real"], True)):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appscan", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                committed = [c for c in calls if "--commit-seen" in c]
                self.assertEqual(bool(committed), want, calls)
                if want:
                    send = [i for i, c in enumerate(calls) if c.startswith("cti-mailer ")]
                    commit = [i for i, c in enumerate(calls) if "--commit-seen" in c]
                    self.assertLess(send[0], commit[0], "recorded before the send")

    def test_domains_names_its_ticket_in_the_email(self):
        # The ticket is filed (or previewed) BEFORE the send and stamped into
        # the report, so the email says which ticket IT is working from.
        for args, real in ((["--for-real"], True), (["--to-dev"], False), (["--dry-run"], False)):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-domains", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                idx = lambda pred, calls=calls: next(i for i, c in enumerate(calls) if pred(c))
                jira = idx(lambda c: c.startswith("cti-jira ") and "--domains-actions" in c)
                stamp = idx(lambda c: "--stamp-ticket" in c)
                send = idx(lambda c: c.startswith("cti-mailer "))
                self.assertLess(jira, stamp, calls)
                self.assertLess(stamp, send, "the email went before the ticket was stamped")
                self.assertIn("--ref-out", calls[jira])
                self.assertIn("--websites-out", calls[idx(lambda c: c.startswith("cti-domains --") and "--out" in c)],
                              "the AppSec coverage check needs the domains lane's website list")
                self.assertEqual("--for-real" in calls[jira], real,
                                 f"{args}: Jira written on a run that must not write: {calls[jira]}")

    def test_appscan_files_no_tickets_unless_asked(self):
        r, calls = self.run_lane("run-appscan", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c for c in calls if c.startswith("cti-jira ")], [], calls)
        self.assertNotIn("--tickets-out", calls[0])

    def test_appscan_files_its_application_tickets_before_the_send(self):
        for args, real in ((["--for-real"], True), (["--to-dev"], False), (["--dry-run"], False)):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appscan", *args, env="WAS_TICKETS=1\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                idx = lambda pred, calls=calls: next(i for i, c in enumerate(calls) if pred(c))
                jira = idx(lambda c: c.startswith("cti-jira ") and "--appscan-tickets" in c)
                stamp = idx(lambda c: "--stamp-tickets" in c)
                send = idx(lambda c: c.startswith("cti-mailer "))
                self.assertLess(jira, stamp, calls)
                self.assertLess(stamp, send, "the email went before its tickets were stamped")
                self.assertEqual("--for-real" in calls[jira], real,
                                 f"{args}: Jira written on a run that must not write: {calls[jira]}")
                self.assertIn("--ticket-slot", calls[idx(lambda c: c.startswith("cti-appscan --out"))])

    def test_appowners_is_off_until_armed(self):
        r, calls = self.run_lane("run-appowners", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, ["cti-mailer --lane owner --armed"],
                         "the owners lane did work with no allowed domains")

    def test_appowners_sends_through_the_owner_lane_then_records(self):
        r, calls = self.run_lane("run-appowners", "--for-real", env="OWNER_ALLOW_DOMAINS=example.com\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        idx = lambda pred, calls=calls: next(i for i, c in enumerate(calls) if pred(c))
        send = idx(lambda c: c.startswith("cti-mailer ") and "--armed" not in c)
        self.assertIn("--lane owner --app-id 1 --app-name App One", calls[send])
        self.assertLess(idx(lambda c: "--armed" in c), idx(lambda c: c.startswith("cti-appscan ")),
                        "the lane did work before asking whether it is armed")
        self.assertNotIn("--to ", calls[send])
        commit = idx(lambda c: "--commit-delivered" in c)
        self.assertLess(send, commit, "recorded as sent before the send")
        self.assertNotIn("--no-fetch", calls[idx(lambda c: c.startswith("cti-appreport "))])
        alerts = [c for c in calls if c.startswith("cti-alert ")]
        self.assertEqual(len(alerts), 1, calls)
        self.assertIn("App Two", alerts[0])

    def test_appowners_test_send_records_nothing(self):
        calls = self.assertTestSend("run-appowners")
        self.assertEqual([c for c in calls if "--commit-delivered" in c], [], calls)

    def test_appowners_dry_run_fetches_and_records_nothing(self):
        r, calls = self.run_lane("run-appowners", "--dry-run", env="OWNER_ALLOW_DOMAINS=example.com\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        report = [c for c in calls if c.startswith("cti-appreport ")]
        self.assertIn("--no-fetch", report[0])
        sends = [c for c in calls if c.startswith("cti-mailer ") and "--armed" not in c]
        self.assertTrue(sends and all("--dry-run" in c for c in sends), calls)
        for c in calls:
            self.assertNotIn("--commit-delivered", c)
            self.assertFalse(c.startswith("cti-alert "), c)

    def test_appowners_records_the_sent_scans_notices_for_the_cleanup(self):
        # The cleanup deletes a sent scan's companion notices (the results
        # notice waits for the weekly) - so after a real send, and only for the
        # scans that were sent (--only-sent), never on a rehearsal or test send.
        for args, want in ((["--to-dev"], False), (["--dry-run"], False), (["--for-real"], True)):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appowners", *args, env="OWNER_ALLOW_DOMAINS=example.com\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                plan = [c for c in calls if "--deliveries-out" in c][0]
                self.assertIn("--seen-out ", plan)
                committed = [c for c in calls if "--commit-seen" in c]
                self.assertEqual(bool(committed), want, calls)
                if want:
                    self.assertIn("--only-sent ", committed[0],
                                  "a held scan's notices must not be archived")
                    send = [i for i, c in enumerate(calls) if c.startswith("cti-mailer ") and "--armed" not in c]
                    self.assertLess(send[-1], calls.index(committed[0]), "recorded before the send")

    def test_no_dev_address_is_refused_before_any_work(self):
        for runner in ("run-digest", "run-patchtuesday", "run-domains", "run-appscan", "run-appowners"):
            with self.subTest(runner=runner):
                self.log.write_text("")
                r, calls = self.run_lane(runner, "--to-dev", dev="")
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual([c for c in calls if c.startswith("cti-mailer")], [],
                                 "a test send with no FLEET_DEV_EMAIL reached the mailer")

    def test_with_dry_run_nothing_is_mailed(self):
        for runner in ("run-digest", "run-patchtuesday", "run-domains", "run-appscan", "run-appowners"):
            with self.subTest(runner=runner):
                self.log.write_text("")
                r, calls = self.run_lane(runner, "--to-dev", "--dry-run")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                sends = [c for c in calls if c.startswith("cti-mailer ")]
                self.assertTrue(sends and all("--dry-run" in c for c in sends), calls)



@contextlib.contextmanager
def hold_lane_lock(home, lane, kind="real"):
    """Hold a lane's lock the way a running runner does (flock on
    $FLEET_HOME/state/locks/<lane>.lock, holder line rewritten) for the length
    of the block."""
    d = pathlib.Path(home) / "state" / "locks"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{lane}.lock", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        f.truncate(0)
        f.write(f"pid 4242, {kind} run, started in a test\n")
        f.flush()
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


class DryRunsLeaveTheRealRunAlone(unittest.TestCase):
    """A dry run or a test send on the day a timer runs must not change what
    the real run reads or reports: no processed-log entries (the mailbox
    cleanup's authority to archive), no memory.db upsert (the next digest's
    "new" flags), and none of the real run's files written or deleted. It
    works in $FLEET_HOME/dryrun/<lane>/, and refuses while a run of the lane
    holds the lane lock."""

    BIN = RunnersToDev.BIN
    tearDown = RunnersToDev.tearDown

    def setUp(self):
        RunnersToDev.setUp(self)
        # The digest's real and dry sends go through cti-mailer, stubbed in BIN.
        p = self.code / "bin" / "cti-vmscan"
        p.write_text(_STUB)
        p.chmod(0o755)

    run_lane = RunnersToDev.run_lane

    def plant(self, rel, text="REAL RUN"):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def assertUntouched(self, *paths):
        for p in paths:
            self.assertTrue(p.exists(), f"a rehearsal deleted {p}")
            self.assertEqual(p.read_text(), "REAL RUN", f"a rehearsal overwrote {p}")

    def agent_logs_its_env(self):
        agent = pathlib.Path(self.base["CTI_AGENT_DIR"]) / "cti-agent"
        agent.write_text('#!/usr/bin/env bash\n'
                         'echo "cti-agent processed=${FLEET_PROCESSED_LOG:-} report=$REPORT_PATH" >> "$STUB_LOG"\n'
                         'echo "| CVE-2026-1 |" > "$REPORT_PATH"\n')

    def test_the_weekly_files_and_comments_on_nothing(self):
        # It borrows the newest daily's ticket map instead (run-digest 1b).
        self.agent_logs_its_env()
        self.plant("state/products.json", "{}")
        r, calls = self.run_lane("run-digest", "weekly", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c for c in calls if c.startswith("cti-jira ")], [])

    def test_digest_daily_rehearsal_writes_no_processed_log_no_db_and_no_real_file(self):
        self.agent_logs_its_env()
        day = datetime.date.today().isoformat()
        real = [self.plant(f"reports/raw-{day}.md"), self.plant(f"state/enriched-{day}.json"),
                self.plant(f"reports/digest-daily-{day}.html"), self.plant(f"reports/digest-daily-{day}.txt")]
        self.plant(f"state/enriched-{day}-tickets.json", '{"tickets": {}}')
        self.plant("state/products.json", "{}")
        out = self.home / "dryrun" / "digest-daily"
        for args in (["daily", "--dry-run"], ["daily", "--to-dev"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-digest", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertUntouched(*real)
                agent = [c for c in calls if c.startswith("cti-agent ")]
                self.assertEqual(agent, [f"cti-agent processed={out}/processed-messages.json "
                                         f"report={out}/raw-{day}.md"],
                                 "the rehearsal's ingest wrote the real processed-message log")
                enrich_ = [c for c in calls if c.startswith("cti-enrich ")]
                self.assertIn("--no-db", enrich_[0], "the rehearsal upserted into memory.db")
                self.assertIn(f"--out {out}/enriched-{day}.json", enrich_[0])
                self.assertIn(f"--enriched {out}/enriched-{day}.json", [c for c in calls if c.startswith("cti-brief ")][0])
                jira = [c for c in calls if c.startswith("cti-jira ")]
                self.assertEqual(jira, [f"cti-jira --from-enriched {out}/enriched-{day}.json --dry-run --follow-up"])
                # What the preview reads beside the enriched file, copied in.
                self.assertTrue((out / f"enriched-{day}-tickets.json").exists())
                self.assertTrue((out / "products.json").exists())
                self.assertEqual(oct(out.stat().st_mode & 0o777), "0o700")

    def test_the_digest_records_what_cti_brief_counted_and_the_request_id(self):
        """The record that stops a second send carries the counts and Graph's
        request-id. run-digest reads them from cti-brief --counts and the
        mailer's --request-id-out, with no Python of its own."""
        self.agent_logs_its_env()
        stubs = {
            "cti-brief": ('if [ "$1" = --counts ]; then echo "3 0 1 2 9 15"; exit 0; fi\n'
                          'while [ $# -gt 0 ]; do case "$1" in --out|--text-out) echo x > "$2";; esac; shift; done\n'
                          'echo "CTI subject"\n'),
            "cti-mailer": ('while [ $# -gt 0 ]; do [ "$1" = --request-id-out ] && echo "0f1e-req-42" > "$2"; shift; done\n'
                           'echo \'{"sent": true}\'\n'),
        }
        for name, body in stubs.items():
            p = self.code / "bin" / name
            p.write_text('#!/usr/bin/env bash\necho "%s $*" >> "$STUB_LOG"\n' % name + body)
            p.chmod(0o755)
        day = datetime.date.today().isoformat()
        r, calls = self.run_lane("run-digest", "daily", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"fleet-db sent {day} 3 0 1 2 9 0f1e-req-42 daily", calls)
        self.assertIn("done - Sev5=3 Sev4=0 Sev3=1 Sev2=2 Sev1=9", r.stdout)

    def test_a_record_with_unreadable_counts_and_no_request_id_still_goes_in(self):
        self.agent_logs_its_env()
        p = self.code / "bin" / "cti-brief"
        p.write_text('#!/usr/bin/env bash\necho "cti-brief $*" >> "$STUB_LOG"\n'
                     'if [ "$1" = --counts ]; then echo "x; rm -rf /" ; exit 0; fi\n'
                     'while [ $# -gt 0 ]; do case "$1" in --out|--text-out) echo x > "$2";; esac; shift; done\n')
        p.chmod(0o755)
        day = datetime.date.today().isoformat()
        r, calls = self.run_lane("run-digest", "daily", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"fleet-db sent {day} 0 0 0 0 0 unknown daily", calls)

    # A runner allowed to run Python, named so the gap is visible. Empty:
    # run-checkin's three heredocs moved to cti-checkin-check.
    PYTHON_STILL_IN = set()

    def test_no_runner_or_shared_library_runs_python(self):
        """The runners call the fleet's commands; Python is for fleet-db,
        fleet-owners and the hand-run tools. Inline python3 (-c or a heredoc)
        in a runner is logic hidden in shell."""
        files = sorted((KIT / "fleet" / "bin").glob("run-*")) + sorted((KIT / "fleet" / "share").glob("*.sh"))
        for f in files:
            if f.name in self.PYTHON_STILL_IN:
                continue
            code = [l for l in f.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#")]
            with self.subTest(file=f.name):
                self.assertEqual([l for l in code if "python" in l], [])

    def test_digest_real_run_keeps_the_real_files_log_and_db(self):
        self.agent_logs_its_env()
        day = datetime.date.today().isoformat()
        r, calls = self.run_lane("run-digest", "daily", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"cti-agent processed= report={self.home}/reports/raw-{day}.md", calls)
        enrich_ = [c for c in calls if c.startswith("cti-enrich ")]
        self.assertNotIn("--no-db", enrich_[0])
        self.assertIn(f"--out {self.home}/state/enriched-{day}.json", enrich_[0])
        self.assertFalse((self.home / "dryrun").exists())

    def triage_stubs(self, triage_exit=0):
        agent = pathlib.Path(self.base["CTI_AGENT_DIR"]) / "cti-agent"
        agent.write_text('#!/usr/bin/env bash\n'
                         'echo "cti-agent $*" >> "$STUB_LOG"\n'
                         'echo "| CVE-2026-1 |" > "$REPORT_PATH"\n'
                         'while [ $# -gt 0 ]; do [ "$1" = --advisories-out ] && echo "{}" > "$2"; shift; done\n')
        t = self.code / "bin" / "cti-triage"
        t.write_text('#!/usr/bin/env bash\necho "cti-triage $*" >> "$STUB_LOG"\n'
                     f'exit {triage_exit}\n')
        t.chmod(0o755)

    def test_digest_triage_is_off_unless_enabled(self):
        self.triage_stubs()
        r, calls = self.run_lane("run-digest", "daily", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse([c for c in calls if c.startswith("cti-triage")], calls)
        self.assertFalse([c for c in calls if "--advisories-out" in c], calls)
        self.assertIn("triage: off", r.stdout)
        r, _ = self.run_lane("run-digest", "daily", "--for-real", env="TRIAGE_ENABLED=yes\n")
        self.assertIn("is not 0 or 1", r.stdout)

    def test_digest_triage_runs_beside_the_enriched_file(self):
        day = datetime.date.today().isoformat()
        for args, where in ((["daily", "--for-real"], self.home / "state"),
                            (["daily", "--dry-run"], self.home / "dryrun" / "digest-daily")):
            with self.subTest(args=args):
                self.triage_stubs()
                self.log.write_text("")
                stale = where / f"enriched-{day}-advisories.json"
                where.mkdir(parents=True, exist_ok=True)
                stale.write_text("yesterday's read")
                r, calls = self.run_lane("run-digest", *args, env="TRIAGE_ENABLED=1\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                adv_in = where / f"enriched-{day}-advisory-input.json"
                self.assertTrue(any(f"--advisories-out {adv_in}" in c for c in calls if c.startswith("cti-agent")), calls)
                tri = [c for c in calls if c.startswith("cti-triage")]
                self.assertEqual(tri, [f"cti-triage --batch {adv_in} --out {stale} --batch-timeout 20m"])
                self.assertFalse(stale.exists(), "a report from an earlier read survived the rerun")
                self.assertFalse(adv_in.exists(), "the input is removed once triaged")
                order = [c.split()[0] for c in calls]
                self.assertLess(order.index("cti-triage"), order.index("cti-brief"))

    def test_digest_survives_a_failed_triage(self):
        self.triage_stubs(triage_exit=1)
        day = datetime.date.today().isoformat()
        r, calls = self.run_lane("run-digest", "daily", "--for-real", env="TRIAGE_ENABLED=1\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cti-triage failed", r.stdout)
        self.assertTrue([c for c in calls if c.startswith("cti-mailer")], "the digest was not sent")
        self.assertTrue((self.home / "state" / f"enriched-{day}-advisory-input.json").exists(),
                        "the input should be kept for a rerun")

    def test_the_weekly_never_triages(self):
        self.triage_stubs()
        r, calls = self.run_lane("run-digest", "weekly", "--dry-run", env="TRIAGE_ENABLED=1\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse([c for c in calls if c.startswith("cti-triage")], calls)

    def test_digest_weekly_rehearsal_leaves_the_weekly_file_alone(self):
        day = datetime.date.today().isoformat()
        real = [self.plant(f"state/weekly-enriched-{day}.json"), self.plant(f"reports/digest-weekly-{day}.html")]
        r, calls = self.run_lane("run-digest", "weekly", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertUntouched(*real)
        self.assertTrue((self.home / "dryrun" / "digest-weekly" / f"weekly-enriched-{day}.json").exists())

    def test_appscan_rehearsal_deletes_and_overwrites_none_of_the_real_files(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        real = [self.plant(f"state/appscan-{n}-{stamp}.json")
                for n in ("seen", "tickets", "tickets-ref", "tickets-plan")]
        real += [self.plant(f"state/appscan-{stamp}.html"), self.plant(f"state/appscan-{stamp}.txt"),
                 self.plant(f"state/appscan-authfail-{stamp}.tsv"), self.plant(f"state/appscan-subject-{stamp}.txt"),
                 self.plant(f"state/appscan-reports-{stamp}/app.zip")]
        out = self.home / "dryrun" / "appscan"
        for args in (["--dry-run"], ["--to-dev"], ["--to-dev", "--dry-run"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appscan", *args, env="WAS_TICKETS=1\nWAS_ATTACH_REPORT=1\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertUntouched(*real)
                scan = [c for c in calls if c.startswith("cti-appscan --out")][0]
                self.assertIn(f"--out {out}/appscan-{stamp}.html", scan)
                self.assertIn(f"--seen-out {out}/appscan-seen-{stamp}.json", scan)
                self.assertIn(f"--tickets-out {out}/appscan-tickets-{stamp}.json", scan)
                for c in calls:
                    self.assertNotIn(f"{self.home}/state/appscan-", c, f"a rehearsal used a real file: {c}")

    def test_domains_rehearsal_leaves_the_website_list_and_real_files_alone(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        real = [self.plant("state/domains-websites.json"), self.plant(f"state/domains-{stamp}.html"),
                self.plant(f"state/domains-{stamp}-actions.json")]
        out = self.home / "dryrun" / "domains"
        for args in (["--dry-run"], ["--to-dev"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-domains", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertUntouched(*real)
                probe = [c for c in calls if c.startswith("cti-domains --no-state-write")][0]
                self.assertIn(f"--websites-out {out}/domains-websites.json", probe,
                              "run-appscan's coverage check would read the rehearsal's website list")
        self.log.write_text("")
        r, calls = self.run_lane("run-domains", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        probe = [c for c in calls if c.startswith("cti-domains --out")][0]
        self.assertIn(f"--websites-out {self.home}/state/domains-websites.json", probe)

    def test_vmscan_rehearsal_leaves_the_seen_list_and_report_alone(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        real = [self.plant(f"state/vmscan-{n}-{stamp}.{e}")
                for n, e in (("seen", "json"), ("subject", "txt"), ("findings", "csv"), ("fixes", "json"))]
        real += [self.plant(f"state/vmscan-{stamp}.html"), self.plant(f"state/vmscan-{stamp}.txt")]
        out = self.home / "dryrun" / "vmscan"
        for args in (["--dry-run"], ["--to-dev"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-vmscan", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertUntouched(*real)
                scan = [c for c in calls if c.startswith("cti-vmscan --out")][0]
                self.assertIn(f"--seen-out {out}/vmscan-seen-{stamp}.json", scan)
                self.assertFalse(any("--commit-seen" in c for c in calls), calls)
                # The spreadsheet ticket is only previewed by a rehearsal.
                jira = [c for c in calls if c.startswith("cti-jira --vmscan-fixes")]
                self.assertEqual(jira, [f"cti-jira --vmscan-fixes {out}/vmscan-fixes-{stamp}.json --dry-run "
                                        f"--ref-out {out}/vmscan-ticket-{stamp}.json"])
                self.assertTicketStampedBeforeTheSend(calls, out, stamp)
        self.log.write_text("")
        r, calls = self.run_lane("run-vmscan", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        scan = [c for c in calls if c.startswith("cti-vmscan --out")][0]
        self.assertIn(f"--seen-out {self.home}/state/vmscan-seen-{stamp}.json", scan)
        jira = [c for c in calls if c.startswith("cti-jira --vmscan-fixes")]
        self.assertEqual(jira, [f"cti-jira --vmscan-fixes {self.home}/state/vmscan-fixes-{stamp}.json --for-real "
                                f"--ref-out {self.home}/state/vmscan-ticket-{stamp}.json"])
        self.assertTicketStampedBeforeTheSend(calls, self.home / "state", stamp)

    def assertTicketStampedBeforeTheSend(self, calls, out, stamp):
        """The report names the spreadsheet ticket: rendered with a slot, the
        ticket step, the stamp, then the mailer - in that order."""
        def idx(pred):
            got = [i for i, c in enumerate(calls) if pred(c)]
            self.assertTrue(got, calls)
            return got[0]
        render = idx(lambda c: c.startswith("cti-vmscan --out"))
        self.assertIn("--ticket-slot", calls[render])
        jira = idx(lambda c: c.startswith("cti-jira --vmscan-fixes"))
        st = idx(lambda c: c.startswith("cti-vmscan --stamp-ticket"))
        self.assertEqual(calls[st], f"cti-vmscan --stamp-ticket {out}/vmscan-ticket-{stamp}.json "
                                    f"--out {out}/vmscan-{stamp}.html --text-out {out}/vmscan-{stamp}.txt")
        send = idx(lambda c: c.startswith("cti-mailer "))
        self.assertLess(render, jira)
        self.assertLess(jira, st)
        self.assertLess(st, send)

    def test_patchtuesday_rehearsal_leaves_the_sent_synopsis_alone(self):
        # The stub's subject is October 2026, so the tag is 2026-October.
        real = [self.plant(f"reports/patchtuesday-2026-October.{e}") for e in ("html", "txt", "json")]
        out = self.home / "dryrun" / "patchtuesday"
        for args in (["--dry-run"], ["--to-dev"], ["--to-dev", "--month", "2026-08"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-patchtuesday", *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertUntouched(*real)
                build = [c for c in calls if c.startswith("cti-patchtuesday ") and "--out" in c][0]
                self.assertIn(f"--out {out}/", build)
                self.assertIn("--no-manifest", build)
        self.log.write_text("")
        r, calls = self.run_lane("run-patchtuesday", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        build = [c for c in calls if c.startswith("cti-patchtuesday ") and "--out" in c][0]
        self.assertIn(f"--out {self.home}/reports/patchtuesday-2026-October.html", build)

    def test_patchtuesday_records_the_present_count_and_request_id(self):
        """run-patchtuesday reads both from files the Go commands write
        (cti-patchtuesday --present-out, cti-mailer --request-id-out), not
        from their JSON with Python."""
        pt = self.code / "bin" / "cti-patchtuesday"
        pt.write_text('#!/usr/bin/env bash\necho "cti-patchtuesday $*" >> "$STUB_LOG"\n'
                      'case "$*" in *--subject-only*) echo "Microsoft Patch Tuesday for October 2026"; exit 0;; esac\n'
                      'while [ $# -gt 0 ]; do case "$1" in\n'
                      '  --out|--text-out|--json) echo x > "$2";;\n'
                      '  --present-out) echo 7 > "$2";;\n'
                      'esac; shift; done\n')
        pt.chmod(0o755)
        mailer = self.code / "bin" / "cti-mailer"
        mailer.write_text('#!/usr/bin/env bash\necho "cti-mailer $*" >> "$STUB_LOG"\n'
                          'while [ $# -gt 0 ]; do [ "$1" = --request-id-out ] && echo "req-77" > "$2"; shift; done\n'
                          'echo \'{"sent": true}\'\n')
        mailer.chmod(0o755)
        r, calls = self.run_lane("run-patchtuesday", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        sent = [c for c in calls if c.startswith("fleet-db sent ")]
        self.assertEqual(len(sent), 1, calls)
        self.assertIn(" 7 0 0 0 0 req-77 ", sent[0] + " ")
        self.assertIn("done - 7 CVE(s) present", r.stdout)

    def test_appowners_rehearsal_works_in_its_own_directory(self):
        old = self.plant("state/appowners-2026-01-01T0000/report.html")
        os.utime(old.parent, (0, 0))
        out = self.home / "dryrun" / "appowners"
        for args in (["--dry-run"], ["--to-dev"]):
            with self.subTest(args=args):
                self.log.write_text("")
                r, calls = self.run_lane("run-appowners", *args, env="OWNER_ALLOW_DOMAINS=example.com\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                plan = [c for c in calls if c.startswith("cti-appscan ") and "--deliveries-out" in c][0]
                self.assertIn(f"--deliveries-out {out}/appowners-plan-", plan)
                self.assertIn(f"--delivered-log {self.home}/state/appowners-sent.json", plan,
                              "the rehearsal must plan from the real delivered log")
                self.assertIn(f"--out-dir {out}/appowners-",
                              [c for c in calls if c.startswith("cti-appreport ")][0])
                self.assertFalse(any("--commit-delivered" in c for c in calls), calls)
                self.assertUntouched(old)
                self.assertEqual(list(out.iterdir()), [], "the rehearsal's reports were not deleted")
        self.log.write_text("")
        r, calls = self.run_lane("run-appowners", "--for-real", env="OWNER_ALLOW_DOMAINS=example.com\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(old.exists(), "a real run still clears a killed run's leftovers")

    def test_a_rehearsal_refuses_while_the_lane_is_running(self):
        cases = (("run-digest", ["daily"], "digest-daily"), ("run-digest", ["weekly"], "digest-weekly"),
                 ("run-appscan", [], "appscan"), ("run-domains", [], "domains"),
                 ("run-appowners", [], "appowners"), ("run-vmscan", [], "vmscan"),
                 ("run-patchtuesday", [], "patchtuesday"))
        for runner, pre, lane in cases:
            for mode in ("--dry-run", "--to-dev"):
                with self.subTest(runner=runner, lane=lane, mode=mode), hold_lane_lock(self.home, lane):
                    self.log.write_text("")
                    r, calls = self.run_lane(runner, *pre, mode, env="OWNER_ALLOW_DOMAINS=example.com\n")
                    self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
                    self.assertIn("pid 4242", r.stderr, "the refusal must say which run holds the lane")
                    self.assertEqual(calls, [], "a refused rehearsal did work")
                    self.assertFalse((self.home / "dryrun").exists())

    def test_a_real_run_goes_ahead_past_a_rehearsal_that_outlasts_the_wait(self):
        # A long operator dry run must not cost the timer's run: rehearsals
        # write only their own files, so the real run waits, then goes on.
        cases = (("run-digest", ["daily"], "digest-daily"), ("run-appscan", [], "appscan"),
                 ("run-domains", [], "domains"), ("run-appowners", [], "appowners"),
                 ("run-vmscan", [], "vmscan"), ("run-patchtuesday", [], "patchtuesday"))
        for runner, pre, lane in cases:
            with self.subTest(runner=runner), hold_lane_lock(self.home, lane, kind="dry"):
                self.log.write_text("")
                r, calls = self.run_lane(runner, *pre, "--for-real",
                                         env="FLEET_LOCK_WAIT_SECONDS=1\nOWNER_ALLOW_DOMAINS=example.com\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("going ahead without it", r.stderr)
                sends = [c for c in calls if c.startswith(("cti-mailer ",))]
                if runner not in ("run-digest", "run-patchtuesday"):
                    self.assertTrue(sends and "--for-real" in sends[-1], calls)

    def test_a_failed_dry_digest_says_dry_run_on_the_board(self):
        (self.code / "bin" / "cti-enrich").write_text("#!/usr/bin/env bash\nexit 1\n")
        r, calls = self.run_lane("run-digest", "daily", "--dry-run")
        self.assertEqual(r.returncode, 1)
        board = [c for c in calls if c.startswith("fleet-board post")]
        self.assertTrue(board and all("DRY RUN run-digest daily failed" in c for c in board), calls)

    def test_a_rehearsal_that_cannot_empty_its_directory_stops(self):
        # Carrying on would present the last rehearsal's files as this one's.
        stale = self.home / "dryrun" / "domains" / "stuck"
        stale.mkdir(parents=True)
        (stale / "domains-old.html").write_text("LAST TIME")
        stale.chmod(0o500)          # rm -rf cannot empty it
        try:
            r, calls = self.run_lane("run-domains", "--dry-run")
        finally:
            stale.chmod(0o700)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c for c in calls if c.startswith("cti-domains ")], [], calls)

    def test_a_real_run_waits_for_the_lane_then_fails_loudly(self):
        cases = (("run-digest", ["daily"], "digest-daily"), ("run-appscan", [], "appscan"),
                 ("run-domains", [], "domains"), ("run-appowners", [], "appowners"),
                 ("run-vmscan", [], "vmscan"), ("run-patchtuesday", [], "patchtuesday"))
        for runner, pre, lane in cases:
            with self.subTest(runner=runner), hold_lane_lock(self.home, lane):
                self.log.write_text("")
                t0 = time.monotonic()
                r, calls = self.run_lane(runner, *pre, "--for-real",
                                         env="FLEET_LOCK_WAIT_SECONDS=1\nOWNER_ALLOW_DOMAINS=example.com\n")
                self.assertGreaterEqual(time.monotonic() - t0, 1.0, "the real run did not wait")
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("still going", r.stdout + r.stderr)
                self.assertEqual([c for c in calls if not c.startswith("fleet-board post")], [],
                                 "a real run ran beside another run of its lane")
        # Free again: the next run goes ahead.
        r, _ = self.run_lane("run-domains", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_lock_is_released_when_the_runner_is_killed(self):
        # flock on an open descriptor: the kernel drops it with the process,
        # so a killed run never leaves a stale lock behind to clear by hand.
        code = self.code / "bin" / "cti-domains"
        code.write_text('#!/usr/bin/env bash\necho "cti-domains $*" >> "$STUB_LOG"\nsleep 30\n')
        self.envfile.write_text("FLEET_DEV_EMAIL=dev@example.com\n")
        p = subprocess.Popen(["bash", str(KIT / "fleet" / "bin" / "run-domains"), "--for-real"],
                             env=self.base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while "cti-domains" not in self.log.read_text() and time.monotonic() < deadline:
                time.sleep(0.1)
            r, _ = self.run_lane("run-domains", "--dry-run")
            self.assertEqual(r.returncode, 75, "the running real run did not hold the lane")
        finally:
            os.killpg(p.pid, 9)
            p.wait()
        code.write_text(_STUB)
        r, _ = self.run_lane("run-domains", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class ModelLaneLibrary(unittest.TestCase):
    """share/model-lane.sh, the rules every model lane shares (HARNESS H4),
    called directly - each runner's tests cover how it uses them."""

    LIB = KIT / "fleet" / "share" / "model-lane.sh"

    def bash(self, script, env=None, linux=False):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = "/usr/bin:/bin"
        if linux:
            (tmp / "uname").write_text("#!/bin/sh\necho Linux\n")
            (tmp / "uname").chmod(0o755)
            path = f"{tmp}:{path}"
        e = {"PATH": path, "HOME": str(tmp), **(env or {})}
        return subprocess.run(["bash", "-c", f'. "{self.LIB}"; {script}'], env=e,
                              capture_output=True, text=True, check=False), tmp

    def test_model_names(self):
        for name, ok in [("", True), ("sonnet", True), ("haiku", True), ("claude-sonnet-5-5", True),
                         ("claude-", False), ("Sonnet", False), ("gpt-4", False),
                         ("sonnet --dangerously-skip-permissions", False), ("claude-x;rm", False)]:
            with self.subTest(name=name):
                r, _ = self.bash(f"ml_model_ok {shlex.quote(name)}")
                self.assertEqual(r.returncode == 0, ok, name)

    def test_one_credential_is_named_never_its_value(self):
        r, _ = self.bash('ml_auth_check t; echo "rc=$? via=$ML_AUTH_VIA"',
                         env={"ANTHROPIC_AUTH_TOKEN": "secret-value"}, linux=True)
        self.assertIn("rc=0 via=ANTHROPIC_AUTH_TOKEN", r.stdout)
        self.assertNotIn("secret-value", r.stdout + r.stderr)
        r, _ = self.bash('ml_auth_check t; echo "rc=$?"',
                         env={"ANTHROPIC_API_KEY": "a", "CLAUDE_CODE_OAUTH_TOKEN": "b"}, linux=True)
        self.assertIn("rc=1", r.stdout)
        self.assertIn("MORE THAN ONE", r.stderr)

    def test_a_stored_login_does_not_count_for_a_scrubbed_lane(self):
        script = ('mkdir -p "$HOME/.claude"; echo "{}" > "$HOME/.claude/.credentials.json"; '
                  'ml_auth_check t; echo "rc=$?"; ml_auth_check t env-only; echo "rc=$?"')
        r, _ = self.bash(script, linux=True)
        self.assertEqual(re.findall(r"rc=\d", r.stdout), ["rc=0", "rc=2"], r.stdout + r.stderr)
        self.assertIn("empty HOME", r.stderr)

    def test_the_scrub_keeps_only_what_the_cli_needs(self):
        r, tmp = self.bash('( ml_scrub_env "$HOME/empty"; env | sort )',
                           env={"ANTHROPIC_AUTH_TOKEN": "t", "FALCON_CLIENT_SECRET": "s",
                                "CLIENT_SECRET": "graph", "LANG": "C"})
        self.assertIn("ANTHROPIC_AUTH_TOKEN=t", r.stdout)
        self.assertIn("LANG=C", r.stdout)
        self.assertIn(f"HOME={tmp}/empty", r.stdout)
        for gone in ("FALCON_CLIENT_SECRET", "CLIENT_SECRET"):
            self.assertNotIn(gone, r.stdout)

    def test_on_linux_only_system_locations_are_searched(self):
        # A claude in the service account's own HOME or PATH is not used.
        r, tmp = self.bash('mkdir -p "$HOME/.local/bin"; printf "#!/bin/sh\\n" > "$HOME/.local/bin/claude"; '
                           'chmod +x "$HOME/.local/bin/claude"; PATH="$HOME/.local/bin:$PATH"; '
                           'ml_find_claude t; echo "rc=$?"', linux=True)
        self.assertNotIn(".local/bin/claude", r.stdout)


class SupplierRunner(unittest.TestCase):
    """run-supplier with the three programs it calls replaced by stubs that
    record their arguments, so the test says exactly what the runner asked of
    each: which mode cti-supplier got, whether the model was shown a request
    with no tools, what the mailer was told, and when the record was updated."""

    RUNNER = KIT / "fleet" / "bin" / "run-supplier"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.code = self.tmp / "code"
        (self.code / "bin").mkdir(parents=True)
        (self.code / "share").mkdir()
        (self.code / "agents" / "supplier").mkdir(parents=True)
        shutil.copy(KIT / "fleet" / "share" / "fleet-mode.sh", self.code / "share")
        shutil.copy(KIT / "fleet" / "share" / "model-lane.sh", self.code / "share")
        shutil.copy(CTI_LOCK, self.code / "bin")
        (self.code / "agents" / "supplier" / "CLAUDE.md").write_text("STANDING INSTRUCTIONS")
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.log = self.tmp / "calls.log"
        self.stub("cti-mailer", 'echo "mailer $*" >> "$CALLS"\n')
        # The model's environment is scrubbed (CALLS included), so this stub
        # logs to a literal path, and records what environment it got.
        self.stub("claude",
                  'echo "claude $*" >> %s\n'
                  'echo "stdin: $(head -c 20)" >> %s\n'
                  'env | sort > %s\n'
                  'echo \'{"schema":"cti-supplier/1"}\'\n' % (shlex.quote(str(self.log)), shlex.quote(str(self.log)),
                                                          shlex.quote(str(self.tmp / "claude.env"))))
        self.problems = ""
        self.requests = 2
        self.held_only = False  # collect finds items, but all are held from the model
        self.write_supplier()

    def stub(self, name, body):
        f = self.code / "bin" / name
        f.write_text("#!/usr/bin/env bash\n" + body)
        f.chmod(0o755)

    def write_supplier(self, digest=True):
        # --collect makes N inputs; --finish writes a digest, seen.json and problems.
        digest_cmds = ("echo 'Supplier requests: 2' > $DIR/digest.subject; "
                       "echo hi > $DIR/digest.html; echo hi > $DIR/digest.txt;") if digest else ""
        self.stub("cti-supplier", """
echo "supplier $*" >> "$CALLS"
while [ $# -gt 0 ]; do
  case "$1" in
    --collect) DIR="$2"; MODE=collect; shift;;
    --finish) DIR="$2"; MODE=finish; shift;;
  esac
  shift
done
if [ "$MODE" = collect ]; then
  for (( i = 0; i < %d; i++ )); do printf 'REQUEST %%s' "$i" > "$DIR/00$i.input.txt"; done
  if [ "%s" = yes ]; then : > "$DIR/has-items"; fi
  echo '{"entries":[{"id":"settled-earlier"}]}' > "$DIR/owned.json"
fi
if [ "$MODE" = finish ]; then
  %s
  echo '["fleet-supplier-x"]' > "$DIR/seen.json"
  echo '{"entries":[{"id":"settled-earlier"},{"id":"settled-now"}]}' > "$DIR/owned.json"
  printf '%%s' "%s" > "$DIR/problems.txt"
fi
""" % (self.requests, "yes" if self.held_only else "no", digest_cmds, self.problems))

    def run_it(self, *args, env=None):
        e = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "FLEET_HOME": str(self.home),
             "FLEET_CODE": str(self.code), "FLEET_ENV": str(self.tmp / "none.env"),
             "CALLS": str(self.log), "FLEET_DEV_EMAIL": "dev@example.test",
             "CLAUDE_BIN": str(self.code / "bin" / "claude"),
             # One credential, as the model-lane rules require (HARNESS H4).
             "ANTHROPIC_API_KEY": "test-placeholder"}
        e.update(env or {})
        e = {k: v for k, v in e.items() if v is not None}  # None removes a default
        return subprocess.run(["bash", str(self.RUNNER), *args], check=False,
                              capture_output=True, text=True, env=e)

    # ─── the model-lane rules it now shares with the heartbeat (H4) ──────────

    def model_calls(self):
        return [c for c in self.calls() if c.startswith("claude ")]

    def test_a_run_of_only_held_threads_is_still_finished_and_never_shown_to_the_model(self):
        # A credit application is held from the model: collect writes no input
        # file for it. The run must not be taken for empty (it would never be
        # filed or digested), and the model must not be called.
        self.requests, self.held_only = 0, True
        self.write_supplier()
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.model_calls(), [])
        self.assertTrue(any(" --finish " in c for c in self.calls()), self.calls())
        self.assertIn("held from it", r.stderr)

    def test_two_credentials_mean_no_judgement(self):
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet",
                                          "CLAUDE_CODE_OAUTH_TOKEN": "seat-token"})
        self.assertIn("MORE THAN ONE credential", r.stderr)
        self.assertIn("every request is Unsure", r.stderr)
        self.assertEqual(self.model_calls(), [])

    def test_an_auth_token_reaches_the_model_through_the_scrub(self):
        # It used to be dropped by the keep list, so every call failed.
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet", "ANTHROPIC_API_KEY": None,
                                           "ANTHROPIC_AUTH_TOKEN": "gateway-token"})
        self.assertNotEqual(self.model_calls(), [], r.stderr)
        self.assertIn("ANTHROPIC_AUTH_TOKEN=gateway-token", (self.tmp / "claude.env").read_text())
        self.assertIn("auth: ANTHROPIC_AUTH_TOKEN", r.stderr)

    def test_a_model_name_that_is_not_one_means_no_judgement(self):
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet --dangerously-skip-permissions"})
        self.assertIn("is not a model", r.stderr)
        self.assertEqual(self.model_calls(), [])

    def test_on_linux_a_claude_the_service_could_replace_is_not_run(self):
        fake = self.tmp / "fakebin"
        fake.mkdir()
        (fake / "uname").write_text("#!/bin/sh\necho Linux\n")
        # stat -L -c %u / %a: owned by uid 1000, the service account.
        (fake / "stat").write_text('#!/bin/sh\ncase "$3" in %u) echo 1000;; %a) echo 755;; esac\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet", "PATH": f"{fake}:/usr/bin:/bin"})
        self.assertIn("REFUSING", r.stderr)
        self.assertIn("not root-owned", r.stderr)
        self.assertEqual(self.model_calls(), [])

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_scrubbed(self):
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet",
                                           "FALCON_CLIENT_SECRET": "falcon-secret",
                                           "GRAPH_CLIENT_SECRET": "graph-secret",
                                           "JIRA_API_TOKEN": "jira-secret",
                                           "ANTHROPIC_API_KEY": "model-key"})
        self.assertEqual(r.returncode, 0, r.stderr)
        env = (self.tmp / "claude.env").read_text()
        for secret in ("falcon-secret", "graph-secret", "jira-secret", "FLEET_ENV=", "FLEET_HOME="):
            self.assertNotIn(secret, env)
        self.assertIn("ANTHROPIC_API_KEY=model-key", env)
        for var in ("HOME", "TMPDIR"):
            got = [l for l in env.splitlines() if l.startswith(var + "=")]
            self.assertEqual(len(got), 1, env)
            self.assertTrue(got[0].endswith("/.claude-home"), got)
        # The key never rides on the command line, where ps would show it.
        self.assertFalse(any("model-key" in c for c in self.calls()))

    def test_the_model_gets_no_fleet_secrets_and_an_empty_home(self):
        self.assert_scrubbed()

    def test_the_model_gets_no_fleet_secrets_with_cost_tracing_on(self):
        # The JSON branch is the one the box runs: fleet-trace ships with it.
        self.with_trace()
        self.assert_scrubbed()

    def test_for_real_files_sends_to_the_lane_and_records(self):
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.calls()
        self.assertIn(f"supplier --for-real --collect {self.home}/state/supplier-work-", " ".join(c))
        self.assertTrue(any(x.startswith("supplier --for-real --finish ") for x in c), c)
        self.assertTrue(any(x.startswith("mailer --lane supplier ") and x.endswith("--for-real") for x in c), c)
        self.assertTrue(any(x.startswith("supplier --for-real --commit-seen ") for x in c), c)
        self.assertTrue(any(x.startswith("supplier --for-real --commit-owned ") for x in c),
                        "the settled mail must be handed to the mailbox cleanup")
        self.assertEqual(list((self.home / "state").glob("supplier-work-*")), [],
                         "the work directory holds request text and must not be left behind")

    def test_settled_mail_is_handed_over_on_a_day_with_nothing_new(self):
        # Mail dealt with earlier must still reach the cleanup when there is no
        # new request to judge, or the first backlog would never be filed away.
        self.requests = 0
        self.write_supplier()
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.calls()
        self.assertTrue(any(x.startswith("supplier --for-real --commit-owned ") for x in c), c)
        self.assertFalse(any("--finish" in x for x in c), c)
        self.assertFalse(any("--commit-seen" in x for x in c), c)

    def test_a_day_with_no_digest_still_records_what_cti_supplier_wrote(self):
        # What belongs in seen.json on such a day is cti-supplier's call (see
        # SeenRecordsFor); the runner must not skip the commit, or a reply that
        # changed nothing is judged again every day.
        self.write_supplier(digest=False)
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.calls()
        self.assertTrue(any("--commit-owned" in x for x in c), c)
        # cti-supplier decides what seen.json holds on a day with no digest; the
        # runner always hands it over on a real run.
        self.assertTrue(any("--commit-seen" in x for x in c), c)
        self.assertFalse(any(x.startswith("mailer") for x in c), c)

    def test_a_dry_run_files_nothing_sends_nothing_and_records_nothing(self):
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.calls()
        self.assertFalse(any(x.startswith("supplier") and "--for-real" in x for x in c), c)
        self.assertFalse(any("--commit-seen" in x or "--commit-owned" in x for x in c), c)
        self.assertTrue(any(x.startswith("supplier --dry-run --finish") for x in c), c)
        self.assertTrue(any(x.startswith("mailer --lane supplier") and x.endswith("--dry-run") for x in c), c)

    def test_a_test_send_goes_to_dev_only_and_files_nothing(self):
        r = self.run_it("--to-dev", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.calls()
        self.assertTrue(any(x.startswith("mailer --to-dev ") for x in c), c)
        self.assertFalse(any("--lane" in x for x in c), c)
        self.assertFalse(any(x.startswith("supplier") and "--for-real" in x for x in c), c)
        self.assertFalse(any("--commit-seen" in x or "--commit-owned" in x for x in c), c)

    def test_the_model_is_given_no_tools_and_the_request_on_stdin(self):
        self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        claude = [x for x in self.calls() if x.startswith("claude ")]
        self.assertEqual(len(claude), 2, "one model call per request")
        for line in claude:
            for want in ("--tools ", "--strict-mcp-config", "--no-session-persistence",
                         "--setting-sources project", "--model sonnet",
                         "--system-prompt STANDING INSTRUCTIONS"):
                self.assertIn(want, line)
            self.assertNotIn("--allowedTools", line)
            self.assertNotIn("--dangerously", line)
        self.assertTrue(any(x.startswith("stdin: REQUEST") for x in self.calls()))

    def test_with_no_model_set_the_model_is_never_called(self):
        r = self.run_it("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(x.startswith("claude ") for x in self.calls()))
        self.assertIn("every request is Unsure", r.stderr)

    def test_a_missing_claude_binary_or_instructions_falls_back_to_unsure(self):
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet", "CLAUDE_BIN": str(self.tmp / "nope")})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("claude binary was not found", r.stderr)
        (self.code / "agents" / "supplier" / "CLAUDE.md").unlink()
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("instructions are not at", r.stderr)

    def test_a_model_that_fails_leaves_that_request_unjudged_and_the_run_going(self):
        self.stub("claude", 'echo "boom" >&2\nexit 1\n')
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no usable judgement", r.stderr)
        self.assertTrue(any(x.startswith("supplier --dry-run --finish") for x in self.calls()))

    def test_no_new_requests_sends_nothing(self):
        self.requests = 0
        self.write_supplier()
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(x.startswith("mailer") or "--finish" in x for x in self.calls()), self.calls())
        self.assertIn("no new supplier requests", r.stderr)

    def test_a_ticket_that_could_not_be_filed_fails_the_run_after_the_digest_goes_out(self):
        self.problems = "Example Co: creating the item: jira said no"
        self.write_supplier()
        r = self.run_it("--for-real", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("jira said no", r.stderr)
        c = self.calls()
        self.assertTrue(any(x.startswith("mailer --lane supplier") for x in c), "the digest must still go out")
        self.assertTrue(any("--commit-seen" in x for x in c), "and what was filed be recorded as reported")

    def test_a_rehearsal_leaves_the_real_work_alone_and_keeps_no_request_text(self):
        # A same-day timer run's work directory must survive a rehearsal, and
        # the rehearsal must not leave mail text behind: only the digest.
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        real = self.home / "state" / f"supplier-work-{stamp}"
        real.mkdir(parents=True)
        (real / "000.input.txt").write_text("THE REAL RUN'S REQUEST")
        for args in (["--dry-run"], ["--to-dev"], ["--to-dev", "--dry-run"]):
            with self.subTest(args=args):
                r = self.run_it(*args, env={"SUPPLIER_MODEL": "sonnet"})
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual((real / "000.input.txt").read_text(), "THE REAL RUN'S REQUEST",
                                 "a rehearsal touched the real run's work")
                preview = self.home / "dryrun" / "supplier"
                self.assertFalse((preview / "work").exists(), "request text kept after a rehearsal")
                self.assertEqual(list(preview.rglob("*.input.txt")), [])
                self.assertEqual((preview / "digest.html").read_text().strip(), "hi")
                self.assertEqual(oct((preview / "digest.html").stat().st_mode & 0o777), "0o600")
                self.assertTrue(any(f"--collect {preview}/work" in x for x in self.calls()), self.calls())

    def test_a_rehearsal_that_fails_still_removes_the_request_text(self):
        # --collect writes one request, then fails: "$3" is the work directory.
        self.stub("cti-supplier", 'echo x > "$3/000.input.txt"; exit 1\n')
        r = self.run_it("--dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(list(self.home.rglob("*.input.txt")), [],
                         "a failed rehearsal left request text behind")

    def test_a_rehearsal_refuses_while_a_run_of_the_lane_holds_the_lock(self):
        with hold_lane_lock(self.home, "supplier"):
            r = self.run_it("--dry-run")
            self.assertEqual(r.returncode, 75, r.stderr)
            self.assertIn("in progress", r.stderr)
            self.assertEqual(self.calls(), [], "a refused rehearsal did work")
            r = self.run_it("--for-real", env={"FLEET_LOCK_WAIT_SECONDS": "1"})
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(self.calls(), [], "a real run ran beside another run")
        r = self.run_it("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)


    # -- what the model calls cost ------------------------------------------

    REPLY = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1,
             "duration_ms": 2100, "total_cost_usd": 0.0125,
             "result": '{"schema":"cti-supplier/1","SECRET":"supplier mail text"}',
             "usage": {"input_tokens": 900, "output_tokens": 120, "cache_read_input_tokens": 0},
             "modelUsage": {"claude-sonnet-5-5": {"costUSD": 0.0125}}}

    def with_trace(self, reply=None):
        """The real fleet-trace on the box, and a model that answers in JSON."""
        shutil.copy(FLEET_TRACE_BIN, self.code / "bin" / "fleet-trace")
        (self.code / "bin" / "fleet-trace").chmod(0o755)
        reply_file = self.tmp / "reply.json"
        reply_file.write_text(json.dumps(reply or self.REPLY))
        self.stub("claude", 'echo "claude $*" >> %s\ncat >/dev/null\nenv | sort > %s\ncat "%s"\n'
                  % (shlex.quote(str(self.log)), shlex.quote(str(self.tmp / "claude.env")), reply_file))
        # --finish copies what the runner handed it, so the test can read it.
        body = (self.code / "bin" / "cti-supplier").read_text().replace(
            'if [ "$MODE" = finish ]; then',
            'if [ "$MODE" = finish ]; then\n  cat "$DIR"/*.result.json > "%s" 2>/dev/null || true'
            % (self.tmp / "results.seen"))
        (self.code / "bin" / "cti-supplier").write_text(body)

    def traces(self):
        return sorted((self.home / "state" / "traces").glob("supplier-*.jsonl"))

    def fleet_trace(self, *args):
        return subprocess.run([str(self.code / "bin" / "fleet-trace"), *args],
                              capture_output=True, text=True, check=False,
                              env={"PATH": "/usr/bin:/bin", "FLEET_HOME": str(self.home)})

    def test_each_call_asks_for_json_and_the_lane_gets_the_answer_text(self):
        self.with_trace()
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        claude = [x for x in self.calls() if x.startswith("claude ")]
        self.assertTrue(claude and all("--output-format json" in x for x in claude), claude)
        self.assertEqual((self.tmp / "results.seen").read_text(), self.REPLY["result"] * 2,
                         "cti-supplier must get the model's answer, not the JSON envelope")
        self.assertIn("judged 2 request(s); 0 without", r.stderr)

    def test_the_cost_is_recorded_without_the_answer_and_listed_with_a_total(self):
        self.with_trace()
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        [trace] = self.traces()
        self.assertEqual(oct(trace.stat().st_mode & 0o777), "0o600")
        text = trace.read_text()
        self.assertNotIn("SECRET", text, "the trace kept the model's answer")
        self.assertNotIn("supplier mail", text)
        lines = [json.loads(l) for l in text.splitlines()]
        self.assertEqual(lines[0]["unit"], "supplier")
        self.assertEqual([l["total_cost_usd"] for l in lines[1:]], [0.0125, 0.0125])
        self.assertEqual(lines[1]["models"], ["claude-sonnet-5-5"])
        out = self.fleet_trace("list").stdout
        self.assertIn(trace.name, out)
        self.assertIn("$0.0250", out, "a run's cost is the sum of its calls")
        self.assertIn("total for the 1 listed: $0.0250 (supplier $0.0250)", out)

    def test_a_failed_call_is_unsure_but_its_cost_is_still_recorded(self):
        self.with_trace(dict(self.REPLY, is_error=True, subtype="error_max_turns", result=""))
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no usable judgement", r.stderr)
        self.assertIn("error_max_turns", r.stderr)
        self.assertEqual((self.tmp / "results.seen").read_text(), "")
        [trace] = self.traces()
        self.assertEqual(sum(json.loads(l).get("total_cost_usd", 0) for l in trace.read_text().splitlines()),
                         0.025, "a failed call is still billed")

    def test_a_call_that_exits_non_zero_is_still_costed(self):
        self.with_trace(dict(self.REPLY, is_error=True, subtype="error_during_execution", result=""))
        body = (self.code / "bin" / "claude").read_text() + "exit 1\n"
        (self.code / "bin" / "claude").write_text(body)
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 without a judgement", r.stderr)
        [trace] = self.traces()
        self.assertEqual(len(trace.read_text().splitlines()), 3, "header and both calls")

    def test_list_survives_malformed_result_lines(self):
        self.with_trace()
        d = self.home / "state" / "traces"
        d.mkdir(parents=True)
        (d / "checkin-20261111T080000.jsonl").write_text(
            '{"type":"result","total_cost_usd":%s,"permission_denials":5}\n' % ("1" + "0" * 400)
            + '{"type":"result","total_cost_usd":true,"permission_denials":"abc"}\n')
        r = self.fleet_trace("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("checkin-20261111T080000.jsonl", r.stdout)

    def test_a_reply_that_is_not_json_is_unsure(self):
        self.with_trace()
        self.stub("claude", 'cat >/dev/null\necho "not json"\n')
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not a claude JSON result", r.stderr)
        self.assertIn("2 without a judgement", r.stderr)

    def test_an_unwritable_trace_directory_costs_the_record_not_the_judgement(self):
        self.with_trace()
        (self.home / "state").mkdir(exist_ok=True)
        (self.home / "state" / "traces").write_text("a file, not a directory")
        r = self.run_it("--dry-run", env={"SUPPLIER_MODEL": "sonnet"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("what they cost is not recorded", r.stderr)
        self.assertIn("judged 2 request(s); 0 without", r.stderr)

    def test_list_interleaves_lanes_by_time_and_show_last_stays_a_heartbeat(self):
        self.with_trace()
        d = self.home / "state" / "traces"
        d.mkdir(parents=True)
        beat = {"type": "result", "num_turns": 7, "total_cost_usd": 0.5, "is_error": False}
        (d / "checkin-20261111T080000.jsonl").write_text(json.dumps(beat) + "\n")
        (d / "supplier-20261111T070000.jsonl").write_text(json.dumps(dict(beat, total_cost_usd=0.01)) + "\n")
        (d / "checkin-20261111T060000.jsonl").write_text(json.dumps(beat) + "\n")
        out = self.fleet_trace("list").stdout.splitlines()
        names = [l.split()[0] for l in out[1:-1]]
        self.assertEqual(names, ["checkin-20261111T080000.jsonl", "supplier-20261111T070000.jsonl",
                                 "checkin-20261111T060000.jsonl"], "newest first, whatever the lane")
        self.assertEqual(out[-1], "total for the 3 listed: $1.0100 (checkin $1.0000, supplier $0.0100)")
        self.assertIn("checkin-20261111T080000", self.fleet_trace("show", "--last").stdout)

    def test_unwrap_refuses_a_heartbeat_trace_name_and_a_planted_link(self):
        self.with_trace()
        d = self.home / "state" / "traces"
        d.mkdir(parents=True)
        reply = json.dumps(self.REPLY)
        r = subprocess.run([str(self.code / "bin" / "fleet-trace"), "unwrap",
                            "--result", str(self.tmp / "r1"), "--trace", str(d / "checkin-20261111T080000.jsonl")],
                           input=reply, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 2)
        target = self.tmp / "elsewhere"
        target.write_text("")
        (d / "supplier-20261111T080000.jsonl").symlink_to(target)
        r = subprocess.run([str(self.code / "bin" / "fleet-trace"), "unwrap",
                            "--result", str(self.tmp / "r2"), "--trace", str(d / "supplier-20261111T080000.jsonl")],
                           input=reply, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, "the judgement is kept")
        self.assertIn("cost not recorded", r.stderr)
        self.assertEqual(target.read_text(), "", "wrote through a planted link")

    def test_unknown_arguments_are_refused(self):
        r = self.run_it("--for-real", "--file-jira")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown argument", r.stderr)


class TestHeartbeatCredentialChecks(unittest.TestCase):
    """The beat may run five credential checks, and nothing else of those
    commands. They are why it is not granted the lanes' --dry-run, which prints
    recipients and inbound subjects, spends the Qualys budget and writes state
    the real runs read. cti-mailer is the recipient gate every send goes
    through: one extra argument after --check (--to, --lane) would make the
    grant a way to address mail."""

    CHECKS = ("cti-mailer", "cti-jira", "cti-appreport", "cti-domains", "cti-vmscan")
    BIN = "/opt/cti-agent/bin/"

    def guard(self, cmd):
        guard = GUARD_BIN
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
        return subprocess.run([str(guard)], input=payload,
                              capture_output=True, text=True, check=False, env=env)

    def test_each_check_is_allowed_exactly(self):
        for c in self.CHECKS:
            with self.subTest(cmd=c):
                r = self.guard(self.BIN + c + " --check")
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_nothing_rides_along_with_a_check(self):
        for cmd in ("cti-mailer --check --to someone@example.com", "cti-mailer --lane was --for-real",
                    "cti-mailer", "cti-jira --check --for-real", "cti-jira --test-ticket --for-real",
                    "cti-appreport --app-id 1", "cti-domains --check --out /tmp/x",
                    "cti-domains", "cti-vmscan --commit-seen x.json", "cti-vmscan --check --since 1h"):
            with self.subTest(cmd=cmd):
                r = self.guard(self.BIN + cmd)
                self.assertEqual(r.returncode, 2, f"{cmd} was let through")

    def test_the_grant_is_the_exact_command(self):
        src = (KIT / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        for c in self.CHECKS:
            with self.subTest(cmd=c):
                self.assertIn(f"Bash($FLEET_CODE/bin/{c} --check)", src)
                self.assertNotIn(f"Bash($FLEET_CODE/bin/{c}:*)", src)
                self.assertNotIn(f"Bash($FLEET_CODE/bin/{c} --check:*)", src)

    def test_the_owner_lane_handle_can_be_addressed(self):
        r = self.guard(self.BIN + 'fleet-board say @appowners INFO "held scan tracked"')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_no_instruction_uses_command_substitution(self):
        # The guard refuses a dollar sign outside single quotes, so an
        # instruction showing $(date +%F) costs the beat a refused call.
        for name in ("CLAUDE.md", "skills/checkin/SKILL.md"):
            text = (KIT / "fleet" / name).read_text(encoding="utf-8")
            spans = re.findall(r"`([^`\n]+)`", text)
            bad = [s for s in spans if "$(" in s]
            with self.subTest(file=name):
                self.assertEqual(bad, [], f"{name} shows a command the guard refuses")

    def test_operator_messages_open_with_the_plain_english_asks(self):
        # The operator reads these on a phone: what is asked, and what
        # happens if nothing is done, come before any detail.
        for name in ("CLAUDE.md", "skills/checkin/SKILL.md"):
            text = (KIT / "fleet" / name).read_text(encoding="utf-8")
            with self.subTest(file=name):
                self.assertIn("What I am asking:", text)
                self.assertIn("If you do nothing:", text)
                self.assertIn("fleet-board say @operator", text)

    def test_the_worked_operator_examples_pass_the_guard(self):
        # The examples are what the beat copies. A semicolon or question mark
        # inside them is refused by checkin-bash-guard even in quotes, which
        # costs the beat a turn (found in review, 2026-11-11).
        text = (KIT / "fleet" / "CLAUDE.md").read_text(encoding="utf-8")
        examples = re.findall(r"```\n(What I am asking:[^\n]+)\n```", text)
        self.assertEqual(len(examples), 2, "expected the alert and the board example")
        wraps = ('cti-alert --unit cti-agent-checkin.service --for-real --kind ESCALATION --reason "%s"',
                 'fleet-board say @operator INFO "%s"')
        for ex, wrap in zip(examples, wraps):
            cmd = "/opt/cti-agent/bin/" + (wrap % ex)
            event = {"tool_name": "Bash", "tool_input": {"command": cmd}}
            env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
            with self.subTest(example=ex[:40]):
                r = subprocess.run([str(GUARD_BIN)], input=json.dumps(event), capture_output=True,
                                   text=True, check=False, env=env)
                self.assertEqual(r.returncode, 0, r.stderr)


class FleetDbWritesAreChecked(unittest.TestCase):
    """Every fleet-db command that writes checks its arguments first, and
    refuses with exit 2 before touching the database. checkin-bash-guard
    already restricts what the heartbeat may send; this is what protects the
    database from every other caller, and the limits are the guard's."""

    DB = KIT / "fleet" / "bin" / "fleet-db"
    GUARD = KIT.parent / "cmd" / "checkin-bash-guard" / "policy.go"

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        self.env = {"PATH": "/usr/bin:/bin", "FLEET_HOME": self.home}
        self.assertEqual(self.run_db("init").returncode, 0)

    def run_db(self, *args, stdin=""):
        return subprocess.run([sys.executable, "-sE", str(self.DB), *args], input=stdin,
                              capture_output=True, text=True, env=self.env, check=False)

    def count(self, table):
        import sqlite3
        c = sqlite3.connect(os.path.join(self.home, "state", "memory.db"))
        try:
            return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608
        finally:
            c.close()

    def refused(self, table, *args, why):
        before = self.count(table)
        r = self.run_db(*args)
        self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))
        self.assertIn("fleet-db:", r.stderr)
        self.assertIn(why, r.stderr, args)
        self.assertNotIn("Traceback", r.stderr, args)
        self.assertEqual(self.count(table), before, f"{args} wrote a row it refused")

    def test_what_every_caller_sends_today_still_works(self):
        for args, table in ((("remember", "checkin", "beat_1", "quiet beat, 0 findings"), "memories"),
                            (("task", "add", "look at the Qualys scan"), "tasks"),
                            (("mail", "send", "digest", "note", "check the daily"), "mailbox"),
                            (("sent", "2026-11-19", "1", "2", "3", "4", "5", "AAMkAD-request-id", "daily"), "digests")):
            before = self.count(table)
            r = self.run_db(*args)
            self.assertEqual(r.returncode, 0, (args, r.stderr))
            self.assertEqual(self.count(table), before + 1)
        self.assertEqual(self.run_db("task", "done", "1").returncode, 0)
        self.assertEqual(self.run_db("ack", "1").returncode, 0)
        self.assertEqual(self.run_db("mail", "ack", "1").returncode, 0)

    def test_remember_refuses_what_is_not_a_memory(self):
        long_text = "x" * 1501
        self.refused("memories", "remember", "Bad Cat", "topic", "text", why="category")
        self.refused("memories", "remember", "cat", "bad topic", "text", why="topic")
        self.refused("memories", "remember", "cat", "topic", long_text, why="too long")
        self.refused("memories", "remember", "cat", "topic", "has \x1b[2J escape", why="control characters")
        self.refused("memories", "remember", "cat", "topic", "   ", why="empty")
        self.refused("memories", "remember", "cat", why="takes a category")

    def test_task_and_ack_refuse_what_is_not_a_row_number(self):
        for bad in ("abc", "0", "-3", "1e3", "99999999999", ""):
            self.refused("tasks", "task", "done", bad, why="row number")
            self.refused("mailbox", "ack", bad, why="row number")
            self.refused("mailbox", "mail", "ack", bad, why="row number")
        self.refused("tasks", "task", "add", "t" * 201, why="too long")
        self.refused("tasks", "task", "add", why="empty")
        self.refused("tasks", "task", "done", why="one row number")

    def test_mail_send_refuses_a_bad_agent_kind_or_body(self):
        self.refused("mailbox", "mail", "send", "bad agent", "k", "body", why="agent")
        self.refused("mailbox", "mail", "send", "agent", "k;drop", "body", why="kind")
        self.refused("mailbox", "mail", "send", "agent", "kind", "b" * 401, why="too long")
        self.refused("mailbox", "mail", "send", "agent", why="takes an agent")

    def test_sent_refuses_a_bad_date_count_or_kind(self):
        ok = ["1", "2", "3", "4", "5", "mid"]
        self.refused("digests", "sent", "2026-13-40", *ok, why="real date")
        self.refused("digests", "sent", "yesterday", *ok, why="date")
        self.refused("digests", "sent", "2026-11-19", "x", "2", "3", "4", "5", "mid", why="whole number")
        self.refused("digests", "sent", "2026-11-19", "-1", "2", "3", "4", "5", "mid", why="outside")
        self.refused("digests", "sent", "2026-11-19", *ok, "Daily!", why="digest kind")
        self.refused("digests", "sent", "2026-11-19", "1", why="takes a date")
        # an empty message id is recorded as "unknown" (the mailer's own default)
        r = self.run_db("sent", "2026-11-20", "1", "2", "3", "4", "5", "")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_note_refuses_a_bad_cve_or_a_huge_note_but_clears_on_empty(self):
        self.assertEqual(self.run_db("finding", "upsert", stdin=json.dumps(
            [{"cve": "CVE-2026-1234", "status": "PRESENT", "priority": "Sev5"}])).returncode, 0)
        r = self.run_db("note", "CVE-2026-1234", "CR-100 filed")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_db("note", "CVE-2026-1234")  # empty clears
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(cleared)", r.stdout)
        self.assertEqual(self.run_db("note", "not-a-cve", "x").returncode, 2)
        self.assertEqual(self.run_db("note", "CVE-2026-1234", "n" * 1001).returncode, 2)
        self.assertEqual(self.run_db("note").returncode, 2)

    def test_a_finding_batch_skips_bad_rows_and_writes_the_rest(self):
        rows = [
            {"cve": "CVE-2026-1111", "status": "PRESENT", "host_count": 3, "cvss": 9.8, "epss": 0.5,
             "kev": 1, "priority": "Sev5", "description": "d" * 5000},
            {"cve": "nope"},
            {"cve": "CVE-2026-2222", "cvss": 99},
            {"cve": "CVE-2026-3333", "priority": "Critical"},
            {"cve": "CVE-2026-4444", "host_count": "many"},
            {"cve": "CVE-2026-5555", "description": "bad \x00 byte"},
            "not an object",
            {"cve": "CVE-2026-6666", "status": "NOT_PRESENT", "epss_pct": 0.0, "qids": "", "kev": False},
        ]
        r = self.run_db("finding", "upsert", stdin=json.dumps(rows))
        # exit 3: every valid row is written, and the caller can tell rows were skipped
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("upserted 3 findings (5 skipped", r.stdout)
        self.assertEqual(r.stderr.count("skipped:"), 5, r.stderr)
        self.assertEqual(self.count("findings"), 3)
        # the row with a stray control character was REPAIRED, not lost
        import sqlite3
        c = sqlite3.connect(os.path.join(self.home, "state", "memory.db"))
        try:
            desc = c.execute("SELECT description FROM findings WHERE cve='CVE-2026-5555'").fetchone()[0]
        finally:
            c.close()
        self.assertNotIn("\x00", desc)
        self.assertIn("bad", desc)
        # a clean batch still exits 0
        ok = self.run_db("finding", "upsert", stdin=json.dumps([{"cve": "CVE-2026-7777", "priority": "Sev3"}]))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertNotEqual(self.run_db("finding", "upsert", stdin="{not json").returncode, 0)

    def test_the_limits_are_the_heartbeat_guards(self):
        """The guard restricts the heartbeat's calls; the database refuses the
        same things from every caller. They must not drift apart."""
        import importlib.machinery
        import importlib.util

        def load_file(name, path):
            loader = importlib.machinery.SourceFileLoader(name, str(path))
            spec = importlib.util.spec_from_loader(name, loader)
            mod = importlib.util.module_from_spec(spec)
            loader.exec_module(mod)
            return mod

        db = load_file("fleet_db_for_guard", self.DB)
        src = self.GUARD.read_text(encoding="utf-8")

        def const(name):
            m = re.search(r"\b" + name + r"\s*=\s*(\d+)", src)
            self.assertIsNotNone(m, name)
            return int(m.group(1))

        def go_rx(rx):
            # Python r"X\Z" with re.match is Go `^X\z`.
            return "`^" + rx.pattern[:-2] + "\\z`"
        self.assertEqual(db.MAX_MEMORY_CONTENT, const("maxMemory"))
        self.assertIn(f"text({db.MAX_TASK_TITLE})", src, "the task title limit drifted from the guard's")
        self.assertEqual(db.MAX_MAIL_BODY, const("maxBoardMessage"))
        for rx in (db.ID_RX, db.NUM_ID_RX, db.CATEGORY_RX, db.TOPIC_RX):
            self.assertIn(go_rx(rx), src, rx.pattern)


class AuditTrailUnits(unittest.TestCase):
    """Every unit whose lane changes something gets /var/log/cti-agent from
    systemd (LogsDirectory=), so the audit trail is writable under
    ProtectSystem=strict. The orchestrator's unit is the exception on purpose:
    the heartbeat must not be able to write, alter or delete the trail it is
    itself accountable to, so its events fall back to the journal."""

    UNITS = KIT / "fleet" / "systemd-fedora"
    WITH = ("alert@", "appowners", "appscan", "digest", "domains", "mailbox",
            "patchtuesday", "supplier", "vmscan", "weekly")
    WITHOUT = ("checkin", "scout")

    def test_the_units_that_change_things_get_the_log_directory(self):
        for name in self.WITH:
            text = (self.UNITS / f"cti-agent-{name}.service").read_text()
            self.assertIn("\nLogsDirectory=cti-agent\n", text, name)
            if "StateDirectory=" in text:
                self.assertIn("\nLogsDirectoryMode=0750\n", text, name)

    def test_the_orchestrator_cannot_write_the_trail(self):
        for name in self.WITHOUT:
            text = (self.UNITS / f"cti-agent-{name}.service").read_text()
            self.assertNotIn("LogsDirectory", text, name)

    def test_every_service_unit_is_classified(self):
        """A new unit has to be put in WITH or WITHOUT, so nobody forgets to
        decide whether it should write the trail."""
        have = {p.name[len("cti-agent-"):-len(".service")] for p in self.UNITS.glob("cti-agent-*.service")}
        self.assertEqual(have, set(self.WITH) | set(self.WITHOUT),
                         "a unit was added or removed: decide whether it writes the audit trail")


class NoPythonLane(unittest.TestCase):
    """Python is for SQLite (fleet-db, fleet-owners) and the root tools, not
    for the lanes. scout.py was the last one; it is cti-scout. A lane that
    came back as Python would bring its own HTTP, TLS and file-mode code,
    outside the Go gates and internal/httpx's floor."""

    def test_no_unit_runs_an_interpreter(self):
        for unit in sorted((KIT / "fleet" / "systemd-fedora").glob("*.service")):
            for line in unit.read_text(encoding="utf-8").splitlines():
                if line.startswith(("ExecStart=", "ExecStartPre=", "ExecStop=")):
                    with self.subTest(unit=unit.name):
                        self.assertNotRegex(line, r"python|\.py\b", line)

    def test_there_is_no_lane_code(self):
        self.assertEqual(sorted(p.name for p in LANES.iterdir() if p.is_file()), ["feeds.txt"],
                         "fleet-kit/fleet/lanes holds the feed list and no code")

class FleetConfig(unittest.TestCase):
    """fleet-config check reads fleet.env, which holds secrets, so the one
    promise that matters is that it never prints a value. The rest: what it
    flags, and that settings.manifest stays in step with the code."""

    TOOL = KIT / "fleet" / "bin" / "fleet-config"
    REPO = KIT.parent

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.manifest = self.tmp / "settings.manifest"
        self.manifest.write_text(
            "key: CLIENT_SECRET\nreaders: cti-mailer cti-agent\nsecret: yes\nrequired: always\n\n"
            "key: SUPPLIER_MODEL\nreaders: run-supplier\n\n"
            "key: GRAPH_FOLDER\nreaders: cti-agent\ncode-default: Inbox\n\n"
            "key: LOOKUP_PROVIDER\nreaders: cti-agent\ncode-default: qualys\n\n"
            "key: QUALYS_PASSWORD\nreaders: cti-vmscan\nsecret: yes\nrequired: if LOOKUP_PROVIDER=qualys\n\n"
            "key: DOM_TO\nreaders: run-domains\n\n"
            "key: TENANT_ID\nreaders: cti-mailer\ncredential: yes\n\n")

    def run_tool(self, *args, env_text=None):
        env = {"PATH": os.environ["PATH"], "FLEET_CODE": str(self.tmp),
               "CTI_CREDSTORE_LIST": str(self.tmp / "credentials.stored")}
        if env_text is not None:
            f = self.tmp / "fleet.env"
            f.write_text(env_text)
            args = (*args, "--env", str(f))
        return subprocess.run([sys.executable, str(self.TOOL), *args], env=env,
                              capture_output=True, text=True, check=False)

    def test_it_never_prints_a_value(self):
        r = self.run_tool("check", env_text=(
            "CLIENT_SECRET=hunter2-secret-value\nSUPLIER_MODEL=typo-value-x\n"
            "GRAPH_FOLDER=Inbox\nDOM_TO=\nCLIENT_SECRET=second-secret-value\nnot a setting line\n"))
        for v in ("hunter2", "second-secret", "typo-value-x", "not a setting"):
            self.assertNotIn(v, r.stdout + r.stderr)
        r = self.run_tool("check", "--json", env_text="CLIENT_SECRET=hunter2-secret-value\n")
        self.assertNotIn("hunter2", r.stdout + r.stderr)

    def test_it_flags_typos_duplicates_missing_and_removable(self):
        r = self.run_tool("check", "--json", env_text=(
            "CLIENT_SECRET=x\nSUPLIER_MODEL=sonnet\nGRAPH_FOLDER=Inbox\nDOM_TO=\n"
            "CLIENT_SECRET=y\nexport LOOKUP_PROVIDER=qualys\nbad line\n"))
        self.assertEqual(r.returncode, 1, r.stderr)
        j = json.loads(r.stdout)
        self.assertEqual(j["unknown"], [{"key": "SUPLIER_MODEL", "did_you_mean": "SUPPLIER_MODEL"}])
        self.assertEqual(j["duplicates"], {"CLIENT_SECRET": [1, 5]})
        self.assertEqual(j["unparsed_lines"], [7])
        self.assertEqual([m["key"] for m in j["missing"]], ["QUALYS_PASSWORD"])
        self.assertIn("LOOKUP_PROVIDER=qualys", j["missing"][0]["why"])
        self.assertEqual(j["at_default"], ["GRAPH_FOLDER", "LOOKUP_PROVIDER"])
        self.assertEqual(j["empty"], ["DOM_TO"])
        self.assertEqual(j["secrets_set"], [{"key": "CLIENT_SECRET", "readers": ["cti-mailer", "cti-agent"]}])

    def test_a_requirement_follows_its_condition(self):
        r = self.run_tool("check", "--json", env_text="CLIENT_SECRET=x\nLOOKUP_PROVIDER=none\n")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(json.loads(r.stdout)["missing"], [])

    def test_an_empty_required_setting_is_missing(self):
        r = self.run_tool("check", "--json", env_text="CLIENT_SECRET=\nLOOKUP_PROVIDER=none\n")
        j = json.loads(r.stdout)
        self.assertEqual([m["key"] for m in j["missing"]], ["CLIENT_SECRET"])
        self.assertNotIn("CLIENT_SECRET", j["empty"])

    def test_list_shows_readers_and_secrets(self):
        r = self.run_tool("list", "--secrets", "--json")
        self.assertEqual([x["key"] for x in json.loads(r.stdout)], ["CLIENT_SECRET", "QUALYS_PASSWORD"])
        r = self.run_tool("list", "--by-reader")
        self.assertIn("cti-vmscan: 1 setting(s), 1 secret(s)", r.stdout)

    def test_a_value_over_several_lines_is_never_read_as_a_key(self):
        r = self.run_tool("check", "--json", env_text=(
            'CLIENT_SECRET="first part\nQ7XK9PSECRETPART=tail"\n'
            "SUPPLIER_MODEL=a\\\nZZSECRETCONT=more\n"
            "LOOKUP_PROVIDER=none\n"))
        self.assertNotIn("Q7XK9P", r.stdout + r.stderr)
        self.assertNotIn("ZZSECRET", r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["unknown"], [])

    def test_bad_utf8_is_not_a_traceback(self):
        f = self.tmp / "fleet.env"
        f.write_bytes(b"CLIENT_SECRET=abc\xff\xfedef\nLOOKUP_PROVIDER=none\n")
        r = subprocess.run([sys.executable, str(self.TOOL), "check", "--env", str(f)],
                           env={"PATH": os.environ["PATH"], "FLEET_CODE": str(self.tmp)},
                           capture_output=True, text=True, check=False)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("0xff", r.stdout + r.stderr)

    def test_an_empty_value_that_means_something_is_not_removable(self):
        with self.manifest.open("a") as f:
            f.write("key: SUPPLIER_TECH_TERMS\nreaders: cti-supplier\nempty-differs: yes\n\n")
        r = self.run_tool("check", "--json", env_text="CLIENT_SECRET=x\nLOOKUP_PROVIDER=none\nSUPPLIER_TECH_TERMS=\n")
        self.assertNotIn("SUPPLIER_TECH_TERMS", json.loads(r.stdout)["empty"])

    def test_the_lookupenv_keys_are_marked_in_the_real_manifest(self):
        text = (KIT / "fleet" / "settings.manifest").read_text()
        for k in ("SUPPLIER_HOLD_PHRASES", "SUPPLIER_TECH_TERMS", "SUPPLIER_JIRA_STATUS", "DIGEST_SKIP_SUBJECTS"):
            block = text.split("key: " + k + "\n", 1)[1].split("\n\n", 1)[0]
            self.assertIn("empty-differs: yes", block, k)

    def test_a_helper_other_settings_use_is_not_a_typo(self):
        r = self.run_tool("check", "--json", env_text=(
            "CLIENT_SECRET=x\nLOOKUP_PROVIDER=none\nTEAM_LIST=a@example.test,b@example.test\n"
            "DOM_TO=ops@example.test,$TEAM_LIST\nSUPPLIER_MODEL=${TEAM_LIST}\n"))
        j = json.loads(r.stdout)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(j["unknown"], [])
        self.assertEqual(j["helpers"], [{"key": "TEAM_LIST", "used_by": 2}])
        self.assertNotIn("example.test", r.stdout)

    def test_a_reference_above_its_setting_expands_to_nothing(self):
        r = self.run_tool("check", "--json", env_text=(
            "CLIENT_SECRET=x\nLOOKUP_PROVIDER=none\nDOM_TO=ops@example.test,$TEAM_LIST\n"
            "TEAM_LIST=a@example.test\nSUPPLIER_MODEL=$NOWHERE\nGRAPH_FOLDER=$HOME/x\nDIGEST='$LITERAL'\n"))
        self.assertEqual(r.returncode, 1)
        late = {x["refers_to"]: x for x in json.loads(r.stdout)["late_references"]}
        self.assertEqual(set(late), {"TEAM_LIST", "NOWHERE"})
        self.assertEqual(late["TEAM_LIST"]["line"], 3)
        self.assertIn("below", late["TEAM_LIST"]["why"])
        self.assertIn("not set", late["NOWHERE"]["why"])

    def test_a_secret_moved_to_a_credential_is_not_missing(self):
        (self.tmp / "credentials.stored").write_text("# names only\nCLIENT_SECRET\nTENANT_ID\n")
        r = self.run_tool("check", "--json", env_text="LOOKUP_PROVIDER=none\n")
        j = json.loads(r.stdout)
        self.assertEqual(j["missing"], [])
        self.assertEqual(j["stored"], ["CLIENT_SECRET", "TENANT_ID"])
        r = self.run_tool("check", "--json", env_text="LOOKUP_PROVIDER=none\nCLIENT_SECRET=still-here\n")
        self.assertEqual(json.loads(r.stdout)["stored_and_in_env"], ["CLIENT_SECRET"])

    def test_a_login_not_moved_yet_is_listed(self):
        (self.tmp / "credentials.stored").write_text("CLIENT_SECRET\n")
        r = self.run_tool("check", "--json", env_text="LOOKUP_PROVIDER=none\nTENANT_ID=tenant-guid-x\n")
        j = json.loads(r.stdout)
        self.assertEqual(j["logins_in_env"], ["TENANT_ID"])
        self.assertNotIn("tenant-guid-x", r.stdout)
        self.assertNotIn("still-here", r.stdout)

    def test_an_unreadable_file_is_an_error_not_a_pass(self):
        r = self.run_tool("check", "--env", str(self.tmp / "missing.env"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot read", r.stderr)

    def test_the_settings_manifest_is_in_step_with_the_code(self):
        """A key added to the code or fleet.env.example without a manifest
        entry, or a manifest key nothing reads, fails here. Fix: run
        scripts/settings-manifest --write and review the diff."""
        r = subprocess.run([sys.executable, str(self.REPO / "scripts" / "settings-manifest"), "--check"],
                           cwd=self.REPO, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_real_manifest_marks_the_known_secrets(self):
        r = subprocess.run([sys.executable, str(self.TOOL), "list", "--secrets", "--json"],
                           env={"PATH": os.environ["PATH"], "FLEET_CODE": str(KIT / "fleet")},
                           capture_output=True, text=True, check=False)
        rows = {x["key"]: x for x in json.loads(r.stdout)}
        for k in ("CLIENT_SECRET", "QUALYS_PASSWORD", "JIRA_API_TOKEN", "FALCON_CLIENT_SECRET", "CLAUDE_CODE_OAUTH_TOKEN"):
            self.assertIn(k, rows)
        for k, row in rows.items():
            self.assertNotIn("checkin-bash-guard", row["readers"],
                             f"{k}: the guard names secrets to refuse them; it must not count as reading one")



class SecretsAsCredentials(unittest.TestCase):
    """cti-agent-secrets moves secrets out of fleet.env into systemd
    credentials; the shell helpers read them. The promises: no value is ever
    printed or put on a command line, only known secrets are stored, and a
    runner drops the environment copy of a secret it has as a file."""

    TOOL = KIT / "bin" / "cti-agent-secrets"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "code").mkdir()
        (self.tmp / "code" / "settings.manifest").write_text(
            "key: CLIENT_SECRET\nsecret: yes\n\nkey: JIRA_API_TOKEN\nsecret: yes\n\n"
            "key: NVD_API_KEY\nsecret: yes\n\nkey: GRAPH_FOLDER\n\nkey: CLIENT_ID\ncredential: yes\n\n")
        self.store = self.tmp / "store"
        self.argv_log = self.tmp / "argv.log"
        fake = self.tmp / "systemd-creds"
        fake.write_text("#!/bin/sh\n" f'echo "$@" >> {shlex.quote(str(self.argv_log))}\n'
                        'out="$4"; { printf "ENC:"; cat; } > "$out"\n')
        fake.chmod(0o755)
        self.env = {"PATH": os.environ["PATH"], "CTI_CREDSTORE": str(self.store),
                    "CTI_CREDSTORE_LIST": str(self.tmp / "credentials.stored"),
                    "FLEET_CODE": str(self.tmp / "code"), "FLEET_ENV": str(self.tmp / "fleet.env"),
                    "SYSTEMD_CREDS": str(fake)}

    def run_tool(self, *args, stdin=""):
        return subprocess.run([sys.executable, str(self.TOOL), *args], env=self.env, input=stdin,
                              capture_output=True, text=True, check=False)

    def test_import_stores_known_secrets_and_never_shows_a_value(self):
        (self.tmp / "fleet.env").write_text(
            "CLIENT_SECRET=client-value-1  # a note bash ignores\nJIRA_API_TOKEN='jira-value-2'\nCLIENT_ID=app-id-3\n"
            "HELPER=nvd-part\nNVD_API_KEY=$HELPER-x\nGRAPH_FOLDER=Inbox\nUNKNOWN_SECRET=x\n")
        r = self.run_tool("import", "--dry-run")
        self.assertIn("would store CLIENT_SECRET", r.stdout)
        self.assertFalse(self.store.exists() and any(self.store.iterdir()), "a dry run stored something")
        r = self.run_tool("import")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(p.name for p in self.store.iterdir()),
                         ["CLIENT_ID", "CLIENT_SECRET", "JIRA_API_TOKEN", "NVD_API_KEY"],
                         "a login half (credential: yes) moves with its secret")
        self.assertEqual((self.store / "JIRA_API_TOKEN").read_text(), "ENC:jira-value-2")
        self.assertEqual((self.store / "CLIENT_SECRET").read_text(), "ENC:client-value-1", "bash drops the comment")
        self.assertEqual((self.store / "NVD_API_KEY").read_text(), "ENC:nvd-part-x", "bash expands the helper")
        self.assertEqual(oct((self.store / "CLIENT_SECRET").stat().st_mode & 0o777), "0o600")
        listed = (self.tmp / "credentials.stored").read_text()
        self.assertIn("CLIENT_SECRET\n", listed)
        everything = r.stdout + r.stderr + self.argv_log.read_text() + listed
        for v in ("client-value-1", "jira-value-2", "nvd-part", "app-id-3"):
            self.assertNotIn(v, everything, "a value was printed or put on a command line")
        self.assertIn("--name=CLIENT_SECRET", self.argv_log.read_text())
        r = self.run_tool("status")
        self.assertIn("4 of 4 secrets and logins stored", r.stdout)
        self.assertNotIn("client-value-1", r.stdout)
        r = self.run_tool("import")
        self.assertIn("nothing to import", r.stdout)

    def test_set_reads_stdin_and_refuses_unknown_names(self):
        r = self.run_tool("set", "NVD_API_KEY", stdin="nvd-value\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.store / "NVD_API_KEY").read_text(), "ENC:nvd-value")
        for bad in ("GRAPH_FOLDER", "../etc/x", "lower"):
            r = self.run_tool("set", bad, stdin="x")
            self.assertEqual(r.returncode, 2, bad)
        r = self.run_tool("remove", "NVD_API_KEY")
        self.assertFalse((self.store / "NVD_API_KEY").exists())

    def test_a_runner_drops_the_environment_copy_of_a_credential_secret(self):
        creds = self.tmp / "creds"
        creds.mkdir()
        (creds / "CLIENT_SECRET").write_text("from-file\n")
        script = (f". {shlex.quote(str(KIT / 'fleet' / 'share' / 'fleet-mode.sh'))}\n"
                  "fleet_secrets_from_credentials\n"
                  'echo "env=${CLIENT_SECRET:-unset} jira=${JIRA_API_TOKEN:-unset}"\n'
                  'echo "read=$(fleet_secret CLIENT_SECRET) jira=$(fleet_secret JIRA_API_TOKEN)"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False,
                           env={"PATH": os.environ["PATH"], "CREDENTIALS_DIRECTORY": str(creds),
                                "CLIENT_SECRET": "from-env", "JIRA_API_TOKEN": "jira-env"})
        self.assertIn("env=unset jira=jira-env", r.stdout, r.stderr)
        self.assertIn("read=from-file jira=jira-env", r.stdout)

    def test_every_runner_drops_credential_secrets_once_both_files_are_loaded(self):
        """The call must come after fleet.env is sourced (or the copy comes
        back) and after fleet-mode.sh defines it (or, under set -e, the lane
        dies with "command not found" - which it did, in three runners, until
        a test ran them)."""
        for f in sorted((KIT / "fleet" / "bin").glob("run-*")):
            with self.subTest(runner=f.name):
                lines = f.read_text().splitlines()
                call = lines.index("fleet_secrets_from_credentials")
                env = lines.index("set +a")
                mode = next(i for i, l in enumerate(lines) if re.match(r'^\. ".*share/fleet-mode\.sh"$', l))
                self.assertGreater(call, env)
                self.assertGreater(call, mode)

    def test_no_unit_or_command_gets_a_secret_without_its_login(self):
        """Once the login halves leave fleet.env, a grant with the secret but
        not its client ID or username would fail - on the box, at night."""
        pairs = {"CLIENT_SECRET": ["TENANT_ID", "CLIENT_ID"],
                 "QUALYS_PASSWORD": ["QUALYS_USERNAME", "QUALYS_BASE_URL"],
                 "JIRA_API_TOKEN": ["JIRA_EMAIL", "JIRA_BASE_URL"],
                 "FALCON_CLIENT_SECRET": ["FALCON_CLIENT_ID", "FALCON_BASE_URL"],
                 "POD_API_TOKEN": ["POD_CLUSTER_ID"]}
        grants = [(p.name, set(re.findall(r"(?m)^ImportCredential=(\S+)", p.read_text())))
                  for p in (KIT / "fleet" / "systemd-fedora").glob("*.service")]
        for line in (KIT / "fleet" / "credentials.map").read_text().splitlines():
            if line and not line.startswith("#"):
                name, *keys = line.split()
                grants.append((name, set(keys)))
        for name, keys in grants:
            for secret, logins in pairs.items():
                if secret in keys:
                    with self.subTest(grant=name, secret=secret):
                        self.assertEqual([l for l in logins if l not in keys], [])

    def test_the_model_token_reaches_only_the_claude_subshell(self):
        creds = self.tmp / "creds"
        creds.mkdir()
        (creds / "CLAUDE_CODE_OAUTH_TOKEN").write_text("tok\n")
        script = (f"ML_OS=linux; . {shlex.quote(str(KIT / 'fleet' / 'share' / 'model-lane.sh'))}\n"
                  "ml_auth_check t >/dev/null && echo auth-ok\n"
                  'ml_with_model_token sh -c \'echo "child=$CLAUDE_CODE_OAUTH_TOKEN"\'\n'
                  'echo "runner=${CLAUDE_CODE_OAUTH_TOKEN:-unset}"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False,
                           env={"PATH": os.environ["PATH"], "CREDENTIALS_DIRECTORY": str(creds)})
        self.assertIn("auth-ok", r.stdout, r.stderr)
        self.assertIn("child=tok", r.stdout)
        self.assertIn("runner=unset", r.stdout)



class SettingsPerLane(unittest.TestCase):
    """Step 3 of splitting fleet.env: core plus one plain file per lane, each
    unit loading core and its own. The promises: no value printed, nothing
    lost, no secret split into a file, no setting left expanding to nothing,
    and every unit and hand run loading the right files."""

    TOOL = KIT / "bin" / "cti-agent-settings"
    CONFIG = KIT / "fleet" / "bin" / "fleet-config"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.conf = self.tmp / "conf"
        self.conf.mkdir()
        self.code = self.tmp / "code"
        self.code.mkdir()
        (self.code / "settings.manifest").write_text(
            "key: GRAPH_MAILBOX\nreaders: cti-agent\nfile: core\n\n"
            "key: DOM_TO\nreaders: run-domains\nfile: domains\n\n"
            "key: DOM_ALLOW_TO\nreaders: run-domains\nfile: domains\n\n"
            "key: SUPPLIER_TO\nreaders: run-supplier\nfile: supplier\n\n"
            "key: CLIENT_SECRET\nreaders: cti-agent\nsecret: yes\n\n"
            "key: CLIENT_ID\nreaders: cti-agent\ncredential: yes\n\n")
        self.env = {"PATH": os.environ["PATH"], "CTI_CONF_DIR": str(self.conf), "FLEET_CODE": str(self.code),
                    "CTI_CREDSTORE_LIST": str(self.tmp / "none")}

    def tool(self, *args):
        return subprocess.run([sys.executable, str(self.TOOL), *args], env=self.env,
                              capture_output=True, text=True, check=False)

    def config(self, *args):
        return subprocess.run([sys.executable, str(self.CONFIG), *args], env=self.env,
                              capture_output=True, text=True, check=False)

    def test_a_split_keeps_every_line_and_prints_no_value(self):
        (self.conf / "fleet.env").write_text(
            "# The mailbox the fleet reads.\nGRAPH_MAILBOX=mailbox-value-1\n\n"
            "TEAM=team-value-2\n# Domains recipients.\nDOM_TO=dom-value-3,$TEAM\n"
            "SUPPLIER_TO=$TEAM\nDOM_ALLOW_TO=$DOM_TO\nODD_LEFTOVER=x\n")
        r = self.tool("split", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.conf / "fleet.d").exists(), "a dry run wrote something")
        r = self.tool("split", "--for-real")
        self.assertEqual(r.returncode, 0, r.stderr)
        for v in ("mailbox-value-1", "team-value-2", "dom-value-3"):
            self.assertNotIn(v, r.stdout + r.stderr)
        d = self.conf / "fleet.d"
        core, dom, sup = ((d / n).read_text() for n in ("00-core.env", "domains.env", "supplier.env"))
        self.assertIn("# The mailbox the fleet reads.\nGRAPH_MAILBOX=mailbox-value-1", core, "comment kept")
        self.assertIn("TEAM=team-value-2", core, "a helper two lane files use goes to core")
        self.assertIn("ODD_LEFTOVER=x", core, "a setting no code reads is kept in core, not lost")
        self.assertIn("# Domains recipients.\nDOM_TO=dom-value-3,$TEAM", dom)
        self.assertIn("DOM_ALLOW_TO=$DOM_TO", dom, "a reference within one lane file is fine")
        self.assertIn("SUPPLIER_TO=$TEAM", sup)
        self.assertFalse((self.conf / "fleet.env").exists())
        aside = list(self.conf.glob("fleet.env.pre-split-*"))
        self.assertEqual(len(aside), 1)
        self.assertEqual(oct(aside[0].stat().st_mode & 0o777), "0o600")
        self.assertIn("already split", self.tool("split", "--for-real").stderr)
        r = self.config("check", "--json")
        j = json.loads(r.stdout)
        self.assertEqual(j["misplaced"], [])
        self.assertEqual(j["late_references"], [])

    def test_secrets_and_logins_are_never_split_into_a_file(self):
        (self.conf / "fleet.env").write_text("GRAPH_MAILBOX=m\nCLIENT_SECRET=s3cr3t-value\nCLIENT_ID=app\n")
        r = self.tool("split", "--for-real")
        self.assertEqual(r.returncode, 1)
        self.assertIn("CLIENT_ID CLIENT_SECRET", r.stderr)
        self.assertNotIn("s3cr3t-value", r.stdout + r.stderr)
        self.assertFalse((self.conf / "fleet.d").exists())

    def test_a_reference_across_lane_files_is_refused(self):
        (self.conf / "fleet.env").write_text("DOM_TO=a@example.test\nSUPPLIER_TO=$DOM_TO\n")
        r = self.tool("split", "--for-real")
        self.assertEqual(r.returncode, 1)
        self.assertIn("SUPPLIER_TO (supplier.env) uses $DOM_TO (domains.env)", r.stderr)

    def test_split_needs_a_mode(self):
        (self.conf / "fleet.env").write_text("GRAPH_MAILBOX=m\n")
        self.assertEqual(self.tool("split").returncode, 2)

    def test_fleet_config_finds_misplaced_and_cross_lane_settings(self):
        d = self.conf / "fleet.d"
        d.mkdir()
        (d / "00-core.env").write_text("GRAPH_MAILBOX=m\nDOM_TO=wrong-file\n")
        (d / "domains.env").write_text("DOM_ALLOW_TO=x\n")
        (d / "supplier.env").write_text("SUPPLIER_TO=$DOM_ALLOW_TO\nGRAPH_MAILBOX=again\n")
        r = self.config("check", "--json")
        self.assertEqual(r.returncode, 1)
        j = json.loads(r.stdout)
        self.assertIn({"key": "DOM_TO", "in": "00-core.env", "belongs_in": "domains.env"}, j["misplaced"])
        self.assertTrue(any(x["refers_to"] == "DOM_ALLOW_TO" and "does not load" in x["why"]
                            for x in j["late_references"]), j["late_references"])
        self.assertEqual(j["duplicates"]["GRAPH_MAILBOX"], ["00-core.env:1", "supplier.env:2"])

    def test_every_unit_loads_core_and_its_own_file_and_the_checkin_all(self):
        units = KIT / "fleet" / "systemd-fedora"
        for u in sorted(units.glob("*.service")):
            text = u.read_text()
            with self.subTest(unit=u.name):
                m = re.search(r'(?m)^Environment="FLEET_ENV_FILES=(.*)"$', text)
                self.assertIsNotNone(m)
                files = m.group(1).split()
                self.assertEqual(files[0], "/etc/cti-agent/fleet.d/00-core.env")
                for f in files:
                    self.assertIn(f"EnvironmentFile=-{f}", text)
                self.assertIn("EnvironmentFile=-/etc/cti-agent/fleet.env", text)
                self.assertNotIn("EnvironmentFile=/etc/cti-agent/fleet.env\n", text)
        checkin = (units / "cti-agent-checkin.service").read_text()
        for lane in ("supplier", "vmscan", "domains", "digest"):
            self.assertIn(f"fleet.d/{lane}.env", checkin)
        vmscan = (units / "cti-agent-vmscan.service").read_text()
        self.assertNotIn("fleet.d/supplier.env", vmscan)

    def test_the_mailers_default_path_settings_are_in_core(self):
        """cti-mailer reads these whenever a runner sends without --lane -
        the digest and Patch Tuesday both - so they cannot sit in one lane's
        file."""
        text = (KIT / "fleet" / "settings.manifest").read_text()
        for k in ("DIGEST_TO", "DIGEST_CC", "DIGEST_CC_FROM_ALLOW_TO", "VM_ALLOW_TO", "FLEET_ALLOW_TO"):
            block = text.split("key: " + k + "\n", 1)[1].split("\n\n", 1)[0]
            self.assertIn("file: core", block, k)

    def test_a_lane_files_recipients_are_sent_with_that_lanes_flag(self):
        """A lane's own recipient settings are read by cti-mailer only for its
        --lane, so the runner that sends must pass it."""
        text = (KIT / "fleet" / "settings.manifest").read_text()
        flags = {"DOM_": ("domains", "run-domains", "dom"), "VMSCAN_": ("vmscan", "run-vmscan", "vmscan"),
                 "SUPPLIER_": ("supplier", "run-supplier", "supplier"),
                 "WAS_OWNER_CC": ("appowners", "run-appowners", "owner")}
        for prefix, (lane, runner, flag) in flags.items():
            keys = re.findall(r"(?m)^key: (" + re.escape(prefix) + r"\S*)\n(?:[^\n]+\n)*?file: " + lane + r"$", text)
            if keys:
                with self.subTest(lane=lane):
                    r = (KIT / "fleet" / "bin" / runner).read_text()
                    self.assertRegex(r, r"--lane[ =]" + flag + r"\b")

    def test_an_unmatched_quote_is_refused_not_guessed(self):
        (self.conf / "fleet.env").write_text('GRAPH_MAILBOX="he said \\"hi\\" ok"\nDOM_TO="open\nSUPPLIER_TO=x\n')
        r = self.tool("split", "--for-real")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot tell where DOM_TO", r.stderr)
        self.assertTrue((self.conf / "fleet.env").exists())
        self.assertFalse((self.conf / "fleet.d").exists())

    def test_an_escaped_quote_and_a_comment_do_not_swallow_the_next_line(self):
        (self.conf / "fleet.env").write_text(
            'GRAPH_MAILBOX="he said \\"hi\\""\nDOM_TO=a@x.test # a "quoted" note\nSUPPLIER_TO=y\n')
        r = self.tool("split", "--for-real")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUPPLIER_TO=y", (self.conf / "fleet.d" / "supplier.env").read_text())

    def test_every_runner_sources_its_lane_files_after_fleet_env(self):
        for f in sorted((KIT / "fleet" / "bin").glob("run-*")):
            with self.subTest(runner=f.name):
                t = f.read_text()
                i, j = t.index('. "$FLEET_ENV"'), t.index("for _f in ${FLEET_ENV_FILES:-}; do")
                self.assertLess(i, j)
                self.assertLess(j, t.index("\nset +a\n"))



class SbinTools(unittest.TestCase):
    """A root tool in /usr/local/sbin is a command the operator types, so it
    gets what cti-agent-update has: a man page, bash and zsh completion that
    the installer installs, relabels and removes, a line in the README's file
    tree and in the cheat sheet - and completions that offer exactly the
    tool's own subcommands and flags. cti-agent-secrets shipped without its
    completion; this keeps the next one from doing the same."""

    REPO = KIT.parent
    TOOLS = ("cti-agent-secrets", "cti-agent-settings")

    def test_each_tool_has_its_man_page_completion_and_docs(self):
        inst = (KIT / "install-fedora.sh").read_text()
        readme = (KIT / "README.md").read_text()
        cheat = (self.REPO / "CHEATSHEET.md").read_text()
        for t in self.TOOLS:
            with self.subTest(tool=t):
                self.assertTrue((self.REPO / "man" / "man1" / f"{t}.1").is_file(), "man page")
                for f in (f"{t}.bash", f"_{t}"):
                    self.assertTrue((KIT / "fleet" / "share" / f).is_file(), f)
                self.assertIn(f"/usr/local/sbin/{t}", inst, "installed")
                self.assertIn("for t in cti-agent-secrets cti-agent-settings; do", inst, "completion installed")
                self.assertIn(f"/usr/share/bash-completion/completions/{t}", inst, "relabelled and removed")
                self.assertIn(f"/usr/share/zsh/site-functions/_{t}", inst)
                self.assertIn(f"bin/{t}", readme, "README file tree")
                self.assertIn(f"sudo {t} ", cheat, "cheat sheet")

    def test_each_man_page_documents_every_subcommand_and_flag(self):
        for t in self.TOOLS:
            src = (KIT / "bin" / t).read_text()
            page = (self.REPO / "man" / "man1" / f"{t}.1").read_text().replace("\\-", "-")
            for w in set(re.findall(r'add_parser\("([a-z-]+)"', src)) | set(re.findall(r'add_argument\("(--[a-z-]+)"', src)):
                with self.subTest(tool=t, word=w):
                    self.assertIn(w, page)

    STANDARD_PATHS = ("/opt/cti-agent", "/etc/cti-agent", "/var/lib/cti-agent", "/var/log/cti-agent",
                      "/etc/credstore.encrypted", "/etc/systemd/system", "/usr/local/bin/cti-agent",
                      "/usr/local/sbin", "/usr/local/share/man/man1", "/usr/share/bash-completion/completions",
                      "/usr/share/zsh/site-functions", "journal")

    def test_every_standard_location_is_listed_in_all_three_places(self):
        """The installer's Layout output, the RUNBOOK's "Where it lives" table
        and the kit README's path table each list every standard location the
        install uses - so a new one cannot be added without saying so."""
        inst = (KIT / "install-fedora.sh").read_text()
        layout = inst[inst.index('bold "Layout"'):inst.index('bold "Installing code"')]
        consts = dict(re.findall(r"(?m)^([A-Z_]+)=(\S+)", inst))
        for k, v in consts.items():
            layout = layout.replace("$" + k, v)
        runbook = (self.REPO / "RUNBOOK.md").read_text()
        table = runbook[runbook.index("## Where it lives"):runbook.index("## Before you start")]
        kit = (KIT / "README.md").read_text()
        kit_table = kit[kit.index("| Path | Holds | Ownership |"):kit.index("All standard *IX locations")]
        preflight = inst[inst.index('bold "Preflight"'):inst.index('bold "Service account')]
        for p in self.STANDARD_PATHS:
            for name, text in (("installer Layout", layout), ("RUNBOOK table", table), ("kit README", kit_table)):
                with self.subTest(path=p, where=name):
                    self.assertIn(p, text)
        for p in ("/opt", "/etc", "/var/lib", "/var/log", "journal"):
            self.assertIn(p, preflight, "Preflight names it")
        self.assertIn("standard *IX naming, locations and configuration", runbook[:3000])

    def test_completions_offer_exactly_the_tools_subcommands_and_flags(self):
        for t in self.TOOLS:
            src = (KIT / "bin" / t).read_text()
            subs = set(re.findall(r'add_parser\("([a-z-]+)"', src))
            flags = set(re.findall(r'add_argument\("(--[a-z-]+)"', src))
            for f in (f"{t}.bash", f"_{t}"):
                comp = (KIT / "fleet" / "share" / f).read_text()
                with self.subTest(tool=t, completion=f):
                    for w in subs | flags:
                        self.assertIn(w, comp, f"{w} is the tool's but the completion does not offer it")
                    offered = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", comp))
                    self.assertEqual(offered - flags, set(), "the completion offers a flag the tool does not take")


if __name__ == "__main__":
    unittest.main(verbosity=2)
