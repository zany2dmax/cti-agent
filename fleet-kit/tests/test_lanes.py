#!/usr/bin/env python3
"""Tests for the fleet lanes. Stdlib unittest only - no pip install.

    python3 -m unittest discover -s fleet-kit/tests -v
    task test:lanes

Network is never touched: the enrichment fetchers are stubbed, so these run
offline and deterministically. What they cover is the logic that decides what a
human sees - priority assignment, report parsing, digest rendering, and the
mailer's autonomy gate.
"""
import base64
import contextlib
import datetime
import fcntl
import importlib.util
import io
import json
import os
import pathlib
import re
import sys
import shutil
import subprocess
import tempfile
import time
import unicodedata
import unittest

KIT = pathlib.Path(__file__).resolve().parents[1]
LANES = KIT / "fleet" / "lanes"


@contextlib.contextmanager
def quiet():
    """Lanes log to stdout/stderr by design. Swallow it during tests so a real
    failure is not buried in progress output."""
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        yield


def load(name):
    """Import a lane by path - they are scripts, not an installed package."""
    spec = importlib.util.spec_from_file_location(name, LANES / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enrich = load("enrich")
brief = load("brief")
mailer = load("mailer")


REPORT = """# CTI / CVE Daily Report

- Mailbox: `security@example.com`
- Lookback since: `2026-09-01T19:10:47-04:00`
- Emails inspected: `312`
- Lookup provider: `qualys`
- Generated: `2026-09-02T19:14:44-04:00`

| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts / Reason |
|---|---|---|---|---:|---:|---|---|
| CVE-2021-44228 | PRESENT | qualys | 376160 | 12 | 100 | 2026-09-01T22:00:00Z | h1, h2 |
| CVE-2020-1472 | PRESENT | qualys | 91668,91680 | 4 | 100 | 2026-06-03T19:10:28Z | h3 |
| CVE-2025-33073 | PRESENT | qualys | 92272 | 40 | 95 | 2026-06-03T22:53:25Z | h4 |
| CVE-2026-9110 | PRESENT | qualys | 288802 | 379 | 65 | 2026-06-03T23:12:38Z | h5 |
| CVE-2026-45659 | PRESENT | qualys | 110525 | 186 | 65 | 2026-06-03T23:10:22Z | h6, h6 |
| CVE-2023-35636 | PRESENT | qualys | 92089 | 4 | 37 | 2026-06-03T22:08:29Z | h7 |
| CVE-2008-4250 | NOT_PRESENT | qualys | 1225 | 0 | 0 |  |  |
| CVE-2022-0492 | NOT_PRESENT | qualys | 159639 | 0 | 0 |  |  |
| CVE-2026-49975 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
| CVE-2026-0826 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
| CVE-2026-8206 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
"""

# cve -> (cvss, epss, on_kev)
FIXTURES = {
    "CVE-2021-44228": (10.0, 0.99999, True),
    "CVE-2020-1472": (10.0, 0.994, True),
    "CVE-2025-33073": (8.8, 0.21, False),
    "CVE-2026-9110": (7.8, 0.04, False),
    "CVE-2026-45659": (5.5, 0.0009, False),
    "CVE-2023-35636": (6.5, 0.003, False),
    "CVE-2008-4250": (9.3, 0.944, False),
    "CVE-2022-0492": (8.8, 0.002, True),
    "CVE-2026-49975": (9.9, 0.78, True),
    "CVE-2026-0826": (9.8, 0.006, False),
    "CVE-2026-8206": (4.3, 0.0002, False),
}


def stub_enrichment():
    """Replace the three network fetchers with fixtures."""
    enrich.fetch_nvd = lambda cves: {
        c: {"cvss": FIXTURES[c][0], "cvss_severity": "HIGH",
            "description": f"Stub for {c}.", "kev_nvd": FIXTURES[c][2],
            "vuln_status": "Analyzed", "published": "2026-01-01T00:00:00"}
        for c in cves if c in FIXTURES}
    enrich.fetch_epss = lambda cves: {
        c: {"epss": FIXTURES[c][1], "epss_pct": 0.9, "epss_date": "2026-09-01"}
        for c in cves if c in FIXTURES}
    enrich.fetch_kev = lambda: {
        c: {"kev_added": "2021-12-10", "kev_due": "2021-12-24",
            "ransomware": "Known", "kev_name": c, "kev_action": "Patch."}
        for c, v in FIXTURES.items() if v[2]}


class ReportParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "raw.md")
        with open(self.path, "w") as f:
            f.write(REPORT)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parses_every_row(self):
        f = enrich.parse_report(self.path)
        self.assertEqual(len(f), 11)

    def test_header_and_separator_rows_are_skipped(self):
        for cve in enrich.parse_report(self.path):
            self.assertRegex(cve, r"^CVE-\d{4}-\d{4,}$")

    def test_fields_are_typed(self):
        row = enrich.parse_report(self.path)["CVE-2026-9110"]
        self.assertEqual(row["status"], "PRESENT")
        self.assertEqual(row["host_count"], 379)
        self.assertEqual(row["qualys_score"], 65)
        self.assertIsInstance(row["host_count"], int)

    def test_blank_numeric_cells_become_zero(self):
        row = enrich.parse_report(self.path)["CVE-2026-49975"]
        self.assertEqual(row["host_count"], 0)
        self.assertEqual(row["qualys_score"], 0)

    def test_metadata_is_extracted(self):
        meta = enrich.parse_meta(self.path)
        self.assertEqual(meta["mailbox"], "security@example.com")
        self.assertEqual(meta["emails"], "312")
        self.assertEqual(meta["provider"], "qualys")

    def test_missing_file_does_not_raise_for_metadata(self):
        self.assertEqual(enrich.parse_meta("/nonexistent/x.md"), {})


class Prioritize(unittest.TestCase):
    """The truth table. These are the calls a human acts on, so they are
    asserted individually rather than by counting buckets."""

    def score(self, cve):
        row = {"cve": cve, "status": "UNKNOWN", "host_count": 0, "qualys_score": 0}
        return row

    def build(self):
        stub_enrichment()
        tmp = tempfile.TemporaryDirectory()
        raw = os.path.join(tmp.name, "raw.md")
        out = os.path.join(tmp.name, "enriched.json")
        with open(raw, "w") as f:
            f.write(REPORT)
        sys.argv = ["enrich.py", "--report", raw, "--out", out, "--no-db"]
        with quiet():
            enrich.main()
        with open(out) as fh:
            data = json.load(fh)
        tmp.cleanup()
        return {f["cve"]: f["priority"] for f in data["findings"]}, data

    def test_truth_table(self):
        pri, _ = self.build()
        expected = {
            # Sev5: present AND actively exploited -> today
            "CVE-2021-44228": ("Sev5", "present, KEV, EPSS 100%"),
            "CVE-2020-1472":  ("Sev5", "present, KEV, EPSS 99%"),
            "CVE-2025-33073": ("Sev5", "present, EPSS 21% (over the 10% bar)"),
            # Sev4: present, nobody exploiting it -> this patch cycle,
            # regardless of CVSS
            "CVE-2026-9110":  ("Sev4", "present on 379 hosts"),
            "CVE-2026-45659": ("Sev4", "present on 186 hosts, CVSS only 5.5"),
            "CVE-2023-35636": ("Sev4", "present on 4 hosts, CVSS 6.5"),
            # Sev3: exploited AND we cannot say whether we are exposed. Above
            # Sev4 deliberately - unbounded risk plus a blind spot beats
            # bounded scheduled work.
            "CVE-2026-49975": ("Sev3", "UNKNOWN + KEV + EPSS 78%"),
            # Sev2: exploited but the scanner checked and found nothing, or a
            # critical it could not check -> verify coverage
            "CVE-2008-4250":  ("Sev2", "EPSS 94% but NOT_PRESENT"),
            "CVE-2022-0492":  ("Sev2", "KEV but NOT_PRESENT"),
            "CVE-2026-0826":  ("Sev2", "UNKNOWN + CVSS 9.8 = coverage gap"),
            # Sev1: nothing to act on
            "CVE-2026-8206":  ("Sev1", "UNKNOWN, CVSS 4.3, no exploitation"),
        }
        for cve, (want, why) in expected.items():
            with self.subTest(cve=cve, rationale=why):
                self.assertEqual(pri[cve], want, f"{cve}: {why}")

    def test_present_never_ranks_below_not_present(self):
        """The regression that motivated the current thresholds."""
        pri, _ = self.build()
        order = {"Sev5": 0, "Sev4": 1, "Sev3": 2, "Sev2": 3, "Sev1": 4}
        present_worst = max(order[pri[c]] for c in
                            ("CVE-2026-45659", "CVE-2023-35636", "CVE-2026-9110"))
        absent_best = min(order[pri[c]] for c in ("CVE-2008-4250", "CVE-2022-0492"))
        self.assertLess(present_worst, absent_best,
                        "a PRESENT finding ranked at or below a NOT_PRESENT one")

    def test_unknown_with_critical_cvss_is_not_sev1(self):
        pri, _ = self.build()
        self.assertNotEqual(pri["CVE-2026-0826"], "Sev1",
                            "UNKNOWN means we did not look, not that we are clean")

    def test_sorted_by_priority_then_host_count(self):
        _, data = self.build()
        order = {"Sev5": 0, "Sev4": 1, "Sev3": 2, "Sev2": 3, "Sev1": 4}
        keys = [(order[f["priority"]], -(f["host_count"] or 0))
                for f in data["findings"]]
        self.assertEqual(keys, sorted(keys), "findings are not ordered for triage")

    def test_counts_match_findings(self):
        _, data = self.build()
        for p in ("Sev5", "Sev4", "Sev3", "Sev1"):
            self.assertEqual(
                data["counts"][p],
                sum(1 for f in data["findings"] if f["priority"] == p))
        self.assertEqual(data["total"], len(data["findings"]))

    def test_rationale_is_always_populated(self):
        _, data = self.build()
        for f in data["findings"]:
            self.assertTrue(f["rationale"], f"{f['cve']} has no rationale")


class Degradation(unittest.TestCase):
    """A digest that hides its own gaps is worse than no digest."""

    def test_all_sources_down_is_reported_not_hidden(self):
        enrich.fetch_nvd = lambda cves: {}
        enrich.fetch_epss = lambda cves: {}
        enrich.fetch_kev = lambda: {}
        with tempfile.TemporaryDirectory() as tmp:
            raw, out = os.path.join(tmp, "r.md"), os.path.join(tmp, "e.json")
            with open(raw, "w") as f:
                f.write(REPORT)
            sys.argv = ["enrich.py", "--report", raw, "--out", out, "--no-db"]
            with quiet():
                enrich.main()
            with open(out) as fh:
                data = json.load(fh)
        self.assertIn("EPSS", data["degraded"])
        self.assertIn("KEV catalog", data["degraded"])
        # Presence still comes from the scanner, so PRESENT rows stay actionable.
        self.assertGreater(data["counts"]["Sev4"], 0)

    def test_degraded_banner_reaches_the_digest(self):
        data = {"generated": "2026-09-02T00:00:00+00:00", "source_meta": {},
                "counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 0}, "total": 0,
                "degraded": ["NVD", "EPSS"], "findings": []}
        html = brief.render(data, "daily")
        self.assertIn("DEGRADED", html)
        self.assertIn("NVD", html)


class BriefRendering(unittest.TestCase):
    def enriched(self):
        stub_enrichment()
        with tempfile.TemporaryDirectory() as tmp:
            raw, out = os.path.join(tmp, "r.md"), os.path.join(tmp, "e.json")
            with open(raw, "w") as f:
                f.write(REPORT)
            sys.argv = ["enrich.py", "--report", raw, "--out", out, "--no-db"]
            with quiet():
                enrich.main()
            with open(out) as fh:
                return json.load(fh)

    def test_subject_leads_with_sev5(self):
        d = self.enriched()
        self.assertTrue(brief.subject(d, "daily").startswith("[Sev5]"))

    def test_subject_without_sev5_does_not_cry_wolf(self):
        d = self.enriched()
        d["findings"] = [f for f in d["findings"] if f["priority"] != "Sev5"]
        d["counts"]["Sev5"] = 0
        self.assertFalse(brief.subject(d, "daily").startswith("[Sev5]"))

    def test_empty_run_still_says_something_useful(self):
        d = {"generated": "x", "source_meta": {}, "total": 0, "degraded": [],
             "counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 0}, "findings": []}
        self.assertIn("no new CVEs", brief.subject(d, "daily"))
        self.assertIn("Nothing to action", brief.render(d, "daily"))

    def test_html_tags_balance(self):
        html = brief.render(self.enriched(), "daily")
        self.assertEqual(html.count("<table"), html.count("</table>"))
        self.assertEqual(html.count("<tr"), html.count("</tr>"))

    def test_sev1_is_a_count_not_a_list_in_either_digest(self):
        """Awareness items get a number and no prose.

        They used to fill 25 rows of the weekly. A large weekly earns a mail
        rule pointing at Trash, and that rule cannot tell a Sev5 from a Sev1 -
        so padding the weekly with things nobody acts on costs the Sev5s their
        audience.

        The count is not lost: it is in the tiles at the top of the HTML and
        the header line of the text version, both of which iterate every band
        regardless of how many rows it lists.
        """
        d = self.enriched()
        for kind in ("daily", "weekly"):
            html = brief.render(d, kind)
            self.assertNotIn("Awareness only", html,
                             f"{kind}: Sev1 should have no section")
            # ...but its number is still on the email.
            self.assertIn(">Sev1<", html, f"{kind}: the Sev1 count tile is missing")
            text = brief.render_text(d, kind)
            # Find the counts strip rather than assuming its line number -
            # blank lines and the degraded/novelty blocks move it around.
            strip = [l for l in text.split("\n")
                     if "Sev5" in l and "Sev1" in l and "total" in l]
            self.assertEqual(len(strip), 1,
                             f"{kind}: expected exactly one counts strip, got {strip}")
            self.assertRegex(strip[0], r"Sev1 \d+",
                             f"{kind}: the strip should carry a Sev1 number")
            self.assertNotIn("Sev1 - Awareness only", text,
                             f"{kind}: Sev1 should have no text section")

    def test_both_renderers_cap_the_same_way(self):
        """render_text used to have its own hardcoded caps.

        It printed up to 99 Sev4 rows where the HTML printed 12, so the
        plain-text alternative - which is what some clients display - was the
        wordier of the two. One table, read by both.
        """
        d = self.enriched()
        for kind in ("daily", "weekly"):
            limits = brief.ROW_LIMITS[kind]
            text = brief.render_text(d, kind)
            for band, cap in limits.items():
                group = [f for f in d["findings"] if f["priority"] == band]
                shown = sum(1 for line in text.split("\n")
                            if line.startswith("  CVE-")
                            and any(f["cve"] in line for f in group))
                self.assertLessEqual(shown, cap,
                                     f"{kind}/{band}: {shown} rows exceeds the cap of {cap}")

    def test_truncation_is_stated_in_the_text_version_too(self):
        d = self.enriched()
        # Force a truncation: more Sev4 rows than the daily cap allows.
        cap = brief.ROW_LIMITS["daily"]["Sev4"]
        d["findings"] = [dict(d["findings"][0], cve=f"CVE-2026-{9000+i}",
                              priority="Sev4", status="PRESENT", host_count=5)
                         for i in range(cap + 3)]
        d["counts"] = {"Sev5": 0, "Sev4": cap + 3, "Sev3": 0, "Sev2": 0, "Sev1": 0}
        text = brief.render_text(d, "daily")
        self.assertIn("+3 more Sev4 in the full report", text,
                      "a list that silently stops is one the reader believes is complete")

    def test_sample_hosts_are_deduped(self):
        d = self.enriched()
        html = brief.render(d, "daily")
        # CVE-2026-45659's sample hosts are "h6, h6" in the fixture.
        self.assertEqual(html.count(">h6<") + html.count(" h6,"), 0,
                         "duplicate hostnames should collapse")

    def test_no_hardcoded_address_when_metadata_missing(self):
        d = self.enriched()
        d["source_meta"] = {}
        self.assertNotIn("@", brief.render(d, "daily").split("Generated by")[0]
                         .split("Presence is determined")[-1])

    def test_text_version_renders(self):
        text = brief.render_text(self.enriched(), "daily")
        self.assertIn("Sev5", text)
        self.assertIn("Presence determined solely", text)


class GrantedRoles(unittest.TestCase):
    """What the token can actually do, checked without touching Entra.

    These run in `task test`, so they are inside `task ship`. The LIVE check -
    `mailer.py --check`, which fetches a real token - stays in
    `task dev:doctor` on purpose: coupling a pre-push gate to tenant state and
    network would mean a consent problem in Entra blocks a code push, and the
    gate would fail on any machine without credentials.
    """

    def token(self, roles):
        """A JWT-shaped string carrying the roles claim; only the payload is read."""
        payload = base64.urlsafe_b64encode(
            json.dumps({"tid": "t", "appid": "a", "roles": roles}).encode()
        ).decode().rstrip("=")
        return f"header.{payload}.signature"

    def check(self, roles):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            rc = mailer.check(self.token(roles), "cti@example.com")
        return rc, buf.getvalue()

    def test_the_two_required_capabilities_pass(self):
        rc, out = self.check(["Mail.Read", "Mail.Send"])
        self.assertEqual(rc, 0, out)
        self.assertIn("read the CTI mailbox", out)
        self.assertIn("send the digest", out)

    def test_readwrite_satisfies_the_read_requirement(self):
        """Mail.ReadWrite supersedes Mail.Read.

        The previous check required the literal string "Mail.Read", so a tenant
        that pruned it after granting Mail.ReadWrite - which is what least
        privilege tells you to do - would have been reported as broken.
        """
        rc, out = self.check(["Mail.ReadWrite", "Mail.Send"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("MISSING", out)

    def test_a_missing_send_role_fails(self):
        rc, out = self.check(["Mail.Read"])
        self.assertEqual(rc, 1)
        self.assertIn("MISSING", out)
        self.assertIn("Mail.Send", out)

    def test_readwrite_is_reported_but_never_fatal(self):
        """The cleanup lane is opt-in, so its permission cannot fail the check."""
        rc, out = self.check(["Mail.Read", "Mail.Send"])
        self.assertEqual(rc, 0)
        self.assertIn("absent", out)
        self.assertIn("cti-mailbox", out)
        rc, out = self.check(["Mail.ReadWrite", "Mail.Send"])
        self.assertEqual(rc, 0)
        self.assertIn("cti-mailbox cleanup", out)
        self.assertNotIn("absent", out)

    def test_unused_permissions_are_named(self):
        """The finding from the real app registration.

        It had Directory.Read.All, User.Read.All and AuditLog.Read.All
        consented and called by nothing - a far wider grant than the mail
        access the code uses. Reported, not fatal: it is a judgement for the
        operator, and a check that fails on it would be one people switch off.
        """
        rc, out = self.check(["Mail.Read", "Mail.Send", "Mail.ReadWrite",
                              "Directory.Read.All", "User.Read.All",
                              "AuditLog.Read.All"])
        self.assertEqual(rc, 0, "unused roles must not fail the check")
        self.assertIn("UNUSED", out)
        for r in ("Directory.Read.All", "User.Read.All", "AuditLog.Read.All"):
            self.assertIn(r, out)
        # The three it does use must not be listed as unused.
        unused_line = [l for l in out.split("\n") if "UNUSED" in l][0]
        for r in ("Mail.Read", "Mail.Send", "Mail.ReadWrite"):
            self.assertNotIn(r, unused_line)

    def test_a_minimal_grant_reports_nothing_unused(self):
        _, out = self.check(["Mail.ReadWrite", "Mail.Send"])
        self.assertNotIn("UNUSED", out)

    def test_no_roles_at_all_is_reported_not_crashed(self):
        rc, out = self.check([])
        self.assertEqual(rc, 1)
        self.assertIn("(none)", out)

    def test_the_used_set_matches_the_endpoints_the_code_calls(self):
        """USED_ROLES is a claim about the codebase; verify it against the code.

        If someone adds a Graph call needing a fourth permission, the unused
        report would start naming a role that is genuinely required.
        """
        root = pathlib.Path(__file__).resolve().parents[2]
        graph = (root / "internal" / "graph" / "client.go").read_text()
        # The three endpoints, and nothing else that would need another role.
        self.assertIn("/mailFolders/%s/messages", graph)
        self.assertIn("/sendMail", graph)
        self.assertIn("/messages/%s/move", graph)
        for forbidden in ("/auditLogs", "/directoryObjects", "/servicePrincipals"):
            self.assertNotIn(forbidden, graph,
                             f"{forbidden} needs a permission USED_ROLES omits")
        self.assertEqual(mailer.USED_ROLES,
                         frozenset({"Mail.Read", "Mail.ReadWrite", "Mail.Send"}))


class Attribution(unittest.TestCase):
    """The footer credit is configuration, not code.

    This kit was deliberately genericised - no organisation name, no
    addresses, no internal identifiers. An attribution line baked into the
    renderer would undo that, so unset renders the wording the digest has
    always had and advertises nobody.
    """

    def setUp(self):
        # Isolate from the developer's shell. These tests are about what the
        # environment does to the output, so ambient values would make them
        # pass or fail for reasons that have nothing to do with the code -
        # and sourcing .env before running them is a normal thing to do.
        self._saved = {k: os.environ.pop(k, None)
                       for k in ("FLEET_ATTRIBUTION", "FLEET_REPO_URL", "FLEET_ORG")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def data(self):
        return {"generated": "2026-09-21T06:00:00Z", "total": 1,
                "counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 1},
                "findings": [{"cve": "CVE-2026-1", "priority": "Sev1",
                              "status": "UNKNOWN", "host_count": 0,
                              "cvss": 0, "epss": 0, "kev": 0, "qids": "",
                              "sample_hosts": "", "rationale": "awareness"}],
                "source_meta": {}}

    def test_unset_keeps_the_footer_it_always_had(self):
        self.assertEqual(brief.attribution(), ("", ""))
        html = brief.render(self.data(), "daily")
        self.assertIn("Generated by the ", html)
        self.assertNotIn("CTI agent fleet", html)
        self.assertNotIn("Claude Code Agent Fleet", html)

    def test_a_url_alone_is_enough_and_names_the_org(self):
        os.environ["FLEET_ORG"] = "Example Org"
        os.environ["FLEET_REPO_URL"] = "https://github.com/example/cti-agent"
        text, url = brief.attribution()
        self.assertIn("Example Org Claude Code Agent Fleet", text)
        self.assertEqual(url, "https://github.com/example/cti-agent")

    def test_explicit_text_wins_and_reaches_both_renderings(self):
        os.environ["FLEET_ATTRIBUTION"] = \
            "Correlated and published by the CR Claude Code Agent Fleet"
        os.environ["FLEET_REPO_URL"] = "https://github.com/example/cti-agent"
        html = brief.render(self.data(), "daily")
        self.assertIn('href="https://github.com/example/cti-agent"', html)
        self.assertIn("CR Claude Code Agent Fleet", html)
        text = brief.render_text(self.data(), "daily")
        self.assertIn("Correlated and published by the CR Claude Code Agent Fleet", text)
        # URL on its own line: a text-only reader cannot follow an anchor.
        self.assertIn("\nhttps://github.com/example/cti-agent", text)

    def test_only_http_links_reach_the_email(self):
        for bad in ("javascript:alert(1)",
                    "data:text/html;base64,PHNjcmlwdD4=",
                    "file:///etc/passwd",
                    "github.com/example/cti-agent",
                    "https://",
                    "   "):
            self.assertEqual(brief.safe_link_url(bad), "",
                             f"{bad!r} should be refused")
        for good in ("https://github.com/example/cti-agent",
                     "http://intranet.example.com/cti",
                     "HTTPS://GitHub.com/Example/cti-agent"):
            self.assertNotEqual(brief.safe_link_url(good), "",
                                f"{good!r} is a usable link")

    def test_a_refused_url_does_not_take_the_text_with_it(self):
        os.environ["FLEET_ATTRIBUTION"] = "Published by the CR fleet"
        os.environ["FLEET_REPO_URL"] = "javascript:alert(1)"
        text, url = brief.attribution()
        self.assertEqual(url, "")
        self.assertEqual(text, "Published by the CR fleet")
        html = brief.render(self.data(), "daily")
        self.assertNotIn("javascript", html)
        self.assertIn("Published by the CR fleet", html)

    def test_the_credit_is_escaped(self):
        os.environ["FLEET_ATTRIBUTION"] = "CR <script>alert(1)</script> & co"
        os.environ["FLEET_REPO_URL"] = 'https://example.com/?a=1&b="2"'
        html = brief.render(self.data(), "daily")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&amp;", html)
        self.assertNotIn('b="2"', html)

    def test_go_and_python_agree_on_what_a_link_is(self):
        """Both emails must apply the same rule.

        The daily digest is rendered in Python and the monthly synopsis in Go.
        Two implementations of "is this a safe href" that disagree is a bug
        waiting for whichever email gets the odd URL.
        """
        go = (pathlib.Path(__file__).resolve().parents[2]
              / "internal" / "patchtuesday" / "render.go").read_text()
        self.assertIn("safeLinkURL", go)
        # The Go side must accept exactly http and https, like safe_link_url.
        self.assertIn('case "http", "https":', go)


class MailerGate(unittest.TestCase):
    """The autonomy gate is a control, not advice. It must exit non-zero."""

    def setUp(self):
        self.env = dict(os.environ)
        os.environ.update({
            "GRAPH_MAILBOX": "security@example.com",
            "DIGEST_TO": "soc@example.com",
            "VM_ALLOW_TO": "soc@example.com",
            "FLEET_OPERATOR_EMAIL": "operator@example.com",
            "FLEET_HOME": tempfile.mkdtemp(),
        })

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)

    def run_mailer(self, *args):
        sys.argv = ["mailer.py", *args, "--dry-run"]
        try:
            with quiet():
                return mailer.main() or 0
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 1

    def test_scheduled_digest_to_the_dl_is_allowed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
            f.write("<html><body>d</body></html>")
        self.assertEqual(self.run_mailer("--html", f.name, "--subject", "s"), 0)

    def test_every_email_carries_the_attribution_even_when_a_lane_forgot(self):
        os.environ["FLEET_ATTRIBUTION"] = "Sent by the Example <fleet>"
        out = mailer.with_attribution("<html><body><p>report</p></body></html>")
        self.assertIn("Sent by the Example &lt;fleet&gt;", out)
        self.assertTrue(out.endswith("</div></body></html>"))
        # A body that already has it, escaped or not, is left alone.
        once = out
        self.assertEqual(mailer.with_attribution(once), once)
        plain = "<body>Sent by the Example <fleet></body>"
        os.environ["FLEET_ATTRIBUTION"] = "Sent by the Example <fleet>"
        self.assertEqual(mailer.with_attribution(plain), plain)
        # Unset adds nothing, and a body with no closing tag still gets it.
        del os.environ["FLEET_ATTRIBUTION"]
        self.assertEqual(mailer.with_attribution("<p>x</p>"), "<p>x</p>")
        os.environ["FLEET_ATTRIBUTION"] = "Credit"
        self.assertIn("Credit", mailer.with_attribution("<p>x</p>"))

    def test_the_self_header_matches_the_go_signature(self):
        # Golden value from internal/graph/selfsign.go selfMAC with the same
        # inputs. If either side changes, cti-mailbox stops archiving our reports.
        v = mailer.sign_self_header("s3cret", "Cyber@Example.com",
                                    nonce="0123456789abcdef01234567")
        self.assertEqual(
            v, "Cyber@Example.com; n=0123456789abcdef01234567; sig="
               "eaebc36cad57f3d0088c739280c34581fd20ca911b3ed4de4e170490c45cf4e8")
        self.assertEqual(mailer.sign_self_header("", "a@b.c"), "a@b.c")

    def test_operator_escalation_needs_no_approval(self):
        self.assertEqual(
            self.run_mailer("--to-operator", "--subject", "s", "--message", "m"), 0)

    def test_third_party_is_refused(self):
        self.assertNotEqual(
            self.run_mailer("--to", "outsider@elsewhere.com",
                            "--subject", "s", "--message", "m"), 0)

    def test_third_party_with_approve_is_allowed(self):
        self.assertEqual(
            self.run_mailer("--to", "outsider@elsewhere.com", "--approve",
                            "--subject", "s", "--message", "m"), 0)

    def test_require_approval_without_approve_is_refused(self):
        self.assertNotEqual(
            self.run_mailer("--to-operator", "--require-approval",
                            "--subject", "s", "--message", "m"), 0)

    def test_old_allowlist_name_is_still_read(self):
        del os.environ["VM_ALLOW_TO"]
        os.environ["FLEET_ALLOW_TO"] = "soc@example.com,ok@example.com"
        self.assertEqual(
            self.run_mailer("--to", "ok@example.com", "--subject", "s", "--message", "m"), 0)

    def test_both_allowlist_names_disagreeing_is_refused(self):
        os.environ["FLEET_ALLOW_TO"] = "soc@example.com,other@example.com"
        self.assertNotEqual(
            self.run_mailer("--html", __file__, "--subject", "s"), 0,
            "two names for one control, with two values, must not send")

    def test_both_names_agreeing_still_sends(self):
        os.environ["FLEET_ALLOW_TO"] = " SOC@example.com "
        self.assertEqual(
            self.run_mailer("--to", "soc@example.com", "--subject", "s", "--message", "m"), 0)

    def test_allowlist_conflict_does_not_close_the_alert_path(self):
        os.environ["FLEET_ALLOW_TO"] = "other@example.com"
        self.assertEqual(
            self.run_mailer("--to-operator", "--subject", "s", "--message", "m"), 0)

    def test_no_recipient_is_refused_rather_than_guessed(self):
        del os.environ["DIGEST_TO"]
        del os.environ["VM_ALLOW_TO"]
        self.assertNotEqual(self.run_mailer("--subject", "s", "--message", "m"), 0)

    def test_missing_sending_mailbox_is_refused(self):
        del os.environ["GRAPH_MAILBOX"]
        self.assertNotEqual(
            self.run_mailer("--to-operator", "--subject", "s", "--message", "m"), 0)

    def test_invalid_address_is_refused(self):
        self.assertNotEqual(
            self.run_mailer("--to", "not-an-email", "--approve",
                            "--subject", "s", "--message", "m"), 0)

    def test_html_and_message_together_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
            f.write("<html></html>")
        self.assertNotEqual(
            self.run_mailer("--to-operator", "--html", f.name,
                            "--message", "m", "--subject", "s"), 0)

    def test_escalation_body_carries_reply_instructions(self):
        body = mailer.escalation_html("Need a decision.", "q17")
        self.assertIn("[FLEET q17]", body)
        self.assertIn("reply", body.lower())

    def test_escalation_body_escapes_html(self):
        body = mailer.escalation_html("<script>alert(1)</script>", None)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)


class BandLabelsDoNotOverclaim(unittest.TestCase):
    """A band heading must not assert presence the scanner never confirmed.

    The digest once printed "Present in the environment" directly above rows
    whose own status read UNKNOWN, because one band held both. The five-band
    split fixes that structurally: these tests check the structure, not just
    the wording, since wording drifts and structure does not."""

    def data(self, findings, **counts):
        c = {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 0}
        c.update(counts)
        return {"counts": c, "total": len(findings), "degraded": [],
                "source_meta": {}, "generated": "g", "kev_deadlines": {},
                "findings": findings}

    def unknown(self, cve, pri="Sev4"):
        return {"cve": cve, "priority": pri, "status": "UNKNOWN", "host_count": 0,
                "rationale": "No Qualys KnowledgeBase CVE-to-QID mapping found",
                "sample_hosts": "", "qids": ""}

    def present(self, cve, hosts=3, pri="Sev4"):
        return {"cve": cve, "priority": pri, "status": "PRESENT",
                "host_count": hosts, "rationale": f"PRESENT on {hosts} host(s)",
                "sample_hosts": "h1", "qids": "1"}

    def test_sev4_claims_presence_because_only_presence_lands_there(self):
        # With five bands the label can finally be plain. Sev4 is confirmed
        # present and nothing else, so saying so is honest rather than the
        # overclaim it was when the band also held UNKNOWN rows.
        self.assertIn("Confirmed present", brief.PRI["Sev4"][2])
        self.assertNotIn("unverified", brief.PRI["Sev4"][2].lower())

    def test_no_band_label_claims_presence_for_unverified_rows(self):
        # The structural fix for the reported bug. Sev3 and Sev2 are where
        # UNKNOWN rows live, and neither may assert presence.
        for band in ("Sev3", "Sev2"):
            label = brief.PRI[band][2].lower()
            self.assertNotIn("confirmed present", label, band)

    def test_scoring_cannot_put_an_unknown_row_in_sev4(self):
        # Stronger than checking the wording: if the scoring itself can never
        # place an unverified finding in the confirmed-present band, the
        # heading cannot lie no matter how it is worded later.
        for kev, epss, cvss in [(1, 0.9, 9.9), (0, 0.6, 9.9), (0, 0.0, 9.5),
                                (0, 0.0, 2.0), (1, 0.0, 0.0)]:
            f = {"status": "UNKNOWN", "host_count": 0, "kev": kev,
                 "epss": epss, "cvss": cvss}
            band, _ = enrich.prioritize(f)
            self.assertNotEqual(band, "Sev4",
                                f"UNKNOWN reached Sev4 with kev={kev} epss={epss}")
            self.assertNotEqual(band, "Sev5",
                                f"UNKNOWN reached Sev5 with kev={kev} epss={epss}")

    def test_the_scale_is_monotonic(self):
        # A severity number has to mean what it says: Sev4 outranks Sev3, and
        # no amount of reasoning in a comment changes that. An earlier draft
        # claimed Sev3 outranked Sev4 and this test caught it.
        self.assertEqual(list(brief.SEV_ORDER),
                         ["Sev5", "Sev4", "Sev3", "Sev2", "Sev1"])
        order = {p: i for i, p in enumerate(brief.SEV_ORDER)}
        for higher, lower in zip(brief.SEV_ORDER, brief.SEV_ORDER[1:]):
            self.assertLess(order[higher], order[lower])

    def test_unverified_sits_mid_scale_not_at_the_floor(self):
        # Below confirmed presence, because a coverage gap may turn out to be
        # nothing. Well above awareness, because it may turn out to be
        # everything - that is the reason the old P2 band was split at all.
        unverified, _ = enrich.prioritize(
            {"status": "UNKNOWN", "host_count": 0, "kev": 1, "epss": 0.9})
        present_quiet, _ = enrich.prioritize(
            {"status": "PRESENT", "host_count": 300, "kev": 0, "epss": 0.001,
             "cvss": 7.0})
        noise, _ = enrich.prioritize(
            {"status": "UNKNOWN", "host_count": 0, "kev": 0, "epss": 0.0001,
             "cvss": 4.0})
        order = {p: i for i, p in enumerate(brief.SEV_ORDER)}
        self.assertEqual(unverified, "Sev3")
        self.assertGreater(order[unverified], order[present_quiet])
        self.assertLess(order[unverified], order[noise])

    def test_sev3_explains_why_it_exists(self):
        d = self.data([self.unknown("CVE-1", pri="Sev3")], Sev3=1)
        html = brief.render(d, "daily")
        self.assertIn("it means nobody looked", html)
        self.assertNotIn("Confirmed present", html.split("Sev3")[1][:400])

    def test_all_present_band_carries_no_caveat(self):
        # A caveat on a band that does not need one is noise, and noise is how
        # a caveat stops being read when it matters.
        d = self.data([self.present("CVE-1"), self.present("CVE-2")], Sev4=2)
        html = brief.render(d, "daily")
        self.assertNotIn("nobody looked", html)

    def test_subject_counts_confirmed_presence_not_band_size(self):
        # "3 confirmed present" was printed from a band count that could be
        # entirely UNKNOWN. It now counts rows.
        d = self.data([self.unknown("CVE-1", pri="Sev3"),
                       self.unknown("CVE-2", pri="Sev3")], Sev3=2)
        s = brief.subject(d, "daily")
        self.assertIn("0 confirmed present", s)
        self.assertIn("could not check", s)

        d = self.data([self.present("CVE-1"),
                       self.unknown("CVE-2", pri="Sev3")], Sev4=1, Sev3=1)
        s = brief.subject(d, "daily")
        self.assertIn("1 confirmed present", s)
        self.assertIn("1 unverified", s)

    def test_text_digest_carries_the_same_caveat(self):
        d = self.data([self.present("CVE-1"),
                       self.unknown("CVE-2", pri="Sev3")], Sev4=1, Sev3=1)
        txt = brief.render_text(d, "daily")
        self.assertIn("unverified coverage", txt)
        self.assertIn("not that we are clean", txt)

    def test_label_never_says_p1_through_p4(self):
        # The point of the rename: no collision with the incident scale.
        for band, (_, _, label) in brief.PRI.items():
            for p in ("P1", "P2", "P3", "P4"):
                self.assertNotIn(p, label, f"{band} label mentions {p}")


class MailerCc(unittest.TestCase):
    """CC exists so individuals can receive the digest without appearing on a
    distribution list's To line. It is still a delivery, so the allowlist
    covers it."""

    def env(self, **extra):
        e = {"TENANT_ID": "t", "CLIENT_ID": "c", "CLIENT_SECRET": "s",
             "GRAPH_MAILBOX": "cti@example.com",
             "FLEET_OPERATOR_EMAIL": "op@example.com",
             "DIGEST_TO": "dl@example.com"}
        e.update(extra)
        return e

    def run_mailer(self, env, *argv):
        tmp = tempfile.TemporaryDirectory()
        html = os.path.join(tmp.name, "d.html")
        with open(html, "w") as f:
            f.write("<html>x</html>")
        old = dict(os.environ)
        os.environ.clear()
        os.environ.update(env, FLEET_HOME=tmp.name,
                          FLEET_ENV=os.path.join(tmp.name, "absent.env"))
        sys.argv = ["mailer.py", "--html", html, "--subject", "S",
                    "--dry-run", *argv]
        out = io.StringIO()
        code = 0
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                mailer.main()
        except SystemExit as e:
            code = e.code or 0
        finally:
            os.environ.clear()
            os.environ.update(old)
            tmp.cleanup()
        return code, out.getvalue()

    def test_cc_outside_the_allowlist_is_refused(self):
        code, _ = self.run_mailer(self.env(), "--cc", "outsider@example.com")
        self.assertNotEqual(code, 0,
                            "an unapproved CC must be refused, not delivered")

    def test_cc_on_the_allowlist_is_sent(self):
        code, out = self.run_mailer(
            self.env(VM_ALLOW_TO="dl@example.com,ok@example.com"),
            "--cc", "ok@example.com")
        self.assertEqual(code, 0)
        self.assertIn("ok@example.com", json.loads(out)["cc"])

    def test_cc_duplicating_a_to_recipient_is_dropped(self):
        code, out = self.run_mailer(self.env(), "--cc", "dl@example.com")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cc"], [],
                         "a CC that is already a To recipient would deliver twice")

    def test_digest_cc_env_var_is_honoured(self):
        code, out = self.run_mailer(self.env(
            DIGEST_CC="ok@example.com",
            VM_ALLOW_TO="dl@example.com,ok@example.com"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cc"], ["ok@example.com"])

    def test_allowlist_can_supply_the_cc(self):
        # One edit instead of two: add a standing recipient to VM_ALLOW_TO
        # and they receive the digest.
        code, out = self.run_mailer(self.env(
            VM_ALLOW_TO="dl@example.com,alice@example.com,bob@example.com",
            DIGEST_CC_FROM_ALLOW_TO="true"))
        self.assertEqual(code, 0)
        self.assertEqual(sorted(json.loads(out)["cc"]),
                         ["alice@example.com", "bob@example.com"])

    def test_allowlist_cc_excludes_the_to_recipients(self):
        # DIGEST_TO is in the allowlist by definition, so without this every
        # digest would CC its own To line.
        code, out = self.run_mailer(self.env(
            VM_ALLOW_TO="dl@example.com", DIGEST_CC_FROM_ALLOW_TO="1"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cc"], [])

    def test_allowlist_cc_does_not_include_the_operator(self):
        # The operator is added to the allow SET in code so escalations always
        # work. Deriving the CC from the raw variable keeps them off the
        # digest unless they are listed deliberately.
        code, out = self.run_mailer(self.env(
            VM_ALLOW_TO="dl@example.com,alice@example.com",
            DIGEST_CC_FROM_ALLOW_TO="yes"))
        self.assertEqual(code, 0)
        self.assertNotIn("op@example.com", json.loads(out)["cc"])

    def test_allowlist_cc_merges_with_an_explicit_digest_cc(self):
        code, out = self.run_mailer(self.env(
            VM_ALLOW_TO="dl@example.com,alice@example.com,carol@example.com",
            DIGEST_CC="alice@example.com",
            DIGEST_CC_FROM_ALLOW_TO="on"))
        self.assertEqual(code, 0)
        cc = json.loads(out)["cc"]
        self.assertEqual(sorted(cc), ["alice@example.com", "carol@example.com"])
        self.assertEqual(len(cc), len(set(cc)), "merged CC contains a duplicate")

    def test_allowlist_cc_is_off_unless_explicitly_enabled(self):
        for value in ("", "ture", "maybe", "0", "false", "no"):
            code, out = self.run_mailer(self.env(
                VM_ALLOW_TO="dl@example.com,alice@example.com",
                DIGEST_CC_FROM_ALLOW_TO=value))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["cc"], [],
                             f"{value!r} should not enable allowlist CC")

    def test_allowlist_cc_never_applies_to_an_escalation(self):
        tmp = tempfile.TemporaryDirectory()
        old = dict(os.environ)
        os.environ.clear()
        os.environ.update(self.env(VM_ALLOW_TO="dl@example.com,alice@example.com",
                                   DIGEST_CC_FROM_ALLOW_TO="true"),
                          FLEET_HOME=tmp.name,
                          FLEET_ENV=os.path.join(tmp.name, "absent.env"))
        sys.argv = ["mailer.py", "--to-operator", "--subject", "S",
                    "--message", "M", "--dry-run"]
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                mailer.main()
        except SystemExit:
            pass
        finally:
            os.environ.clear()
            os.environ.update(old)
            tmp.cleanup()
        d = json.loads(out.getvalue())
        self.assertEqual(d["to"], ["op@example.com"])
        self.assertEqual(d["cc"], [], "a question to one person is not a thread")

    def test_invalid_cc_address_is_refused(self):
        code, _ = self.run_mailer(
            self.env(VM_ALLOW_TO="dl@example.com,notanemail"), "--cc", "notanemail")
        self.assertNotEqual(code, 0)


class KevDeadlines(unittest.TestCase):
    """CISA publishes a due date with every KEV entry. It is the only date in
    this system that somebody outside the company set, which makes it the most
    useful one in a patching argument - and the easiest to misuse."""

    TODAY = datetime.date(2026, 9, 15)

    def days(self, due):
        return enrich.kev_days_left({"kev_due": due}, self.TODAY)

    def test_sign_convention(self):
        self.assertEqual(self.days("2026-09-01"), -14, "past dates are negative")
        self.assertEqual(self.days("2026-09-15"), 0, "today is zero")
        self.assertEqual(self.days("2026-09-20"), 5, "future dates are positive")

    def test_absent_is_not_zero(self):
        # "No deadline" and "due today" are opposite facts. Collapsing them
        # into 0 would report every non-KEV finding as due today.
        for due in ("", "   ", None, "not-a-date", "2026-13-45"):
            self.assertIsNone(self.days(due), f"{due!r} should have no deadline")

    def test_rationale_states_the_deadline_only_when_present(self):
        overdue = {"status": "PRESENT", "host_count": 3, "kev": 1,
                   "kev_due": "2026-09-01"}
        _, why = enrich.prioritize(overdue, self.TODAY)
        self.assertIn("PASSED 14d ago", why)

        # The same deadline on something not in the estate is not an
        # obligation, and saying "OVERDUE" about it teaches people to
        # discount the word.
        elsewhere = {"status": "NOT_PRESENT", "host_count": 0, "kev": 1,
                     "kev_due": "2026-09-01"}
        _, why = enrich.prioritize(elsewhere, self.TODAY)
        self.assertNotIn("PASSED", why)
        self.assertIn("not detected here", why)

    def test_due_today_is_not_reported_as_overdue(self):
        f = {"status": "PRESENT", "host_count": 1, "kev": 1, "kev_due": "2026-09-15"}
        _, why = enrich.prioritize(f, self.TODAY)
        self.assertIn("TODAY", why)
        self.assertNotIn("PASSED", why)

    def test_deadline_does_not_change_the_priority(self):
        # A deadline is an obligation about a risk, not a change to it. If it
        # moved findings between bands, the same CVE would be P1 one week and
        # P2 the next with nothing about the environment having changed.
        base = {"status": "PRESENT", "host_count": 1, "kev": 1}
        for due in (None, "2026-09-01", "2026-09-15", "2027-01-01"):
            f = dict(base)
            if due:
                f["kev_due"] = due
            p, _ = enrich.prioritize(f, self.TODAY)
            self.assertEqual(p, "Sev5", f"due={due} changed the band")

    def test_host_count_still_outranks_lateness(self):
        # The regression guard. An earlier cut sorted by lateness first, which
        # pushed a 40-host P1 below a 4-host P1 - the same inversion as the
        # CVSS-gated P2 bug this scoring exists to prevent.
        stub_enrichment()
        tmp = tempfile.TemporaryDirectory()
        raw = os.path.join(tmp.name, "raw.md")
        out = os.path.join(tmp.name, "enriched.json")
        with open(raw, "w") as f:
            f.write(REPORT)
        sys.argv = ["enrich.py", "--report", raw, "--out", out, "--no-db"]
        with quiet():
            enrich.main()
        with open(out) as fh:
            data = json.load(fh)
        tmp.cleanup()

        order = {"Sev5": 0, "Sev4": 1, "Sev3": 2, "Sev2": 3, "Sev1": 4}
        keys = [(order[f["priority"]], -(f.get("host_count") or 0))
                for f in data["findings"]]
        self.assertEqual(keys, sorted(keys),
                         "lateness must not reorder ahead of blast radius")

    def test_summary_counts_only_what_is_present(self):
        rows = [
            {"cve": "A", "status": "PRESENT", "host_count": 2,
             "kev_days_left": -5, "ransomware": "Known"},
            {"cve": "B", "status": "PRESENT", "host_count": 1, "kev_days_left": 3},
            {"cve": "C", "status": "PRESENT", "host_count": 1, "kev_days_left": 90},
            {"cve": "D", "status": "NOT_PRESENT", "host_count": 0,
             "kev_days_left": -100, "ransomware": "Known"},
            {"cve": "E", "status": "UNKNOWN", "host_count": 0, "kev_days_left": -7},
            {"cve": "F", "status": "PRESENT", "host_count": 5, "kev_days_left": None},
        ]
        s = enrich.kev_summary(rows)
        self.assertEqual(s["overdue"], 1, "only A is overdue and present")
        self.assertEqual(s["overdue_cves"], ["A"])
        self.assertEqual(s["due_within_14d"], 1)
        self.assertEqual(s["worst_overdue_days"], 5)
        self.assertEqual(s["ransomware_present"], 1, "D is not in the estate")

    def test_empty_summary_is_all_zeroes_not_an_error(self):
        s = enrich.kev_summary([])
        self.assertEqual(s["overdue"], 0)
        self.assertEqual(s["worst_overdue_days"], 0)
        self.assertEqual(s["overdue_cves"], [])


class KevInTheDigest(unittest.TestCase):
    def data(self, kev, sev5=1):
        return {"counts": {"Sev5": sev5, "Sev4": 2, "Sev3": 0, "Sev2": 0,
                           "Sev1": 0}, "total": 3,
                "degraded": [], "source_meta": {}, "generated": "2026-09-15T06:00:00Z",
                "kev_deadlines": kev,
                "findings": [{"cve": "CVE-2026-1", "priority": "Sev5",
                              "status": "PRESENT", "host_count": 12,
                              "rationale": "present", "sample_hosts": "a",
                              "qids": "1"}]}

    def test_sev5_still_leads_the_subject(self):
        # An overdue deadline on a Sev4 is less urgent than a Sev5. A subject that
        # led with OVERDUE would bury the more urgent fact.
        s = brief.subject(self.data({"overdue": 2, "worst_overdue_days": 26,
                                     "overdue_cves": ["X", "Y"]}), "daily")
        self.assertTrue(s.startswith("[Sev5]"), s)
        self.assertIn("OVERDUE", s, "the deadline should still ride along")

    def test_overdue_leads_when_there_is_no_sev5(self):
        s = brief.subject(self.data({"overdue": 2, "worst_overdue_days": 26,
                                     "overdue_cves": ["X", "Y"]}, sev5=0), "daily")
        self.assertTrue(s.startswith("[OVERDUE]"), s)

    def test_no_banner_when_nothing_is_due(self):
        # A banner that says "nothing overdue" every morning is a banner
        # nobody reads by Thursday.
        html = brief.render(self.data({"overdue": 0, "due_within_14d": 0}), "daily")
        self.assertNotIn("remediation deadline", html)
        self.assertNotIn("fall due within", html)

    def test_banners_coexist_with_the_degraded_notice(self):
        d = self.data({"overdue": 1, "worst_overdue_days": 4, "overdue_cves": ["X"]})
        d["degraded"] = ["KEV catalog"]
        html = brief.render(d, "daily")
        self.assertIn("DEGRADED", html)
        self.assertIn("remediation deadline", html)
        self.assertEqual(html.count("<div"), html.count("</div>"))

    def test_missing_summary_key_does_not_break_rendering(self):
        # Older enriched files predate kev_deadlines. The digest must still
        # render rather than failing the whole 6am run over a new field.
        d = self.data({})
        del d["kev_deadlines"]
        self.assertTrue(brief.render(d, "daily"))
        self.assertTrue(brief.render_text(d, "daily"))
        self.assertTrue(brief.subject(d, "daily"))

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


class DigestTicketLinks(unittest.TestCase):
    """The digest must quote the ticket, and must render without one.

    Every ticket description promises "the CTI daily digest will keep listing
    this CVE, with this ticket's key, until the scanner stops finding it".
    Until now nothing kept that promise.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.enriched = os.path.join(self.dir, "enriched-2026-10-02.json")
        self.tickets = os.path.join(self.dir, "enriched-2026-10-02-tickets.json")
        with open(self.enriched, "w") as fh:
            json.dump({"findings": [], "counts": {}}, fh)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_map(self, obj):
        with open(self.tickets, "w") as fh:
            json.dump(obj, fh)

    def test_the_map_is_found_beside_the_enriched_file(self):
        self.write_map({"tickets": {"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9"}}})
        got = brief.load_tickets(self.enriched)
        self.assertEqual(got["CVE-1"]["key"], "CR-9")

    def test_a_missing_map_is_silent_not_an_error(self):
        # Ticketing is optional and runs before the renderer. A digest that
        # refused to render because Jira was down would turn an optional
        # feature into an outage of the security email.
        self.assertEqual(brief.load_tickets(self.enriched), {})

    def test_a_corrupt_map_is_silent_too(self):
        with open(self.tickets, "w") as fh:
            fh.write("{not json")
        self.assertEqual(brief.load_tickets(self.enriched), {})

    def test_the_key_and_link_reach_the_html(self):
        tickets = {"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9",
                             "status": "In Progress"}}
        html = brief.ticket_cell_html({"cve": "CVE-1"}, tickets)
        self.assertIn("CR-9", html)
        self.assertIn("https://x/browse/CR-9", html)
        self.assertIn("In Progress", html)

    def test_a_finding_with_no_ticket_renders_nothing(self):
        self.assertEqual(brief.ticket_cell_html({"cve": "CVE-2"}, {}), "")
        self.assertIsNone(brief.ticket_cell_text({"cve": "CVE-2"}, {}))

    def test_only_http_urls_become_links(self):
        # Same rule the attribution line follows. The map is generated
        # locally, but this lands in an email.
        tickets = {"CVE-1": {"key": "CR-9", "url": "javascript:alert(1)"}}
        html = brief.ticket_cell_html({"cve": "CVE-1"}, tickets)
        self.assertNotIn("javascript:", html)
        self.assertIn("CR-9", html)

    def test_the_ticket_key_is_escaped(self):
        tickets = {"CVE-1": {"key": "<script>", "url": ""}}
        html = brief.ticket_cell_html({"cve": "CVE-1"}, tickets)
        self.assertNotIn("<script>", html)

    def test_the_text_digest_carries_it_too(self):
        # Some readers get the text part. A ticket quoted only in HTML is a
        # ticket half the recipients never see.
        tickets = {"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9"}}
        line = brief.ticket_cell_text({"cve": "CVE-1"}, tickets)
        self.assertIn("CR-9", line)
        self.assertIn("https://x/browse/CR-9", line)


class DigestFleetTickets(unittest.TestCase):
    """Every fleet ticket appears in the digest, not only today's CVEs'.

    A ticket used to show only on a day its CVE was back in the mail. The
    follow-up re-checked all of them and commented in Jira, and the reader of
    the digest heard nothing - "today's daily still didn't include ticket
    status".
    """

    TICKETS = {
        "CVE-2026-1": {"key": "CR-10", "url": "https://x/browse/CR-10", "status": "In Progress",
                       "cve": "CVE-2026-1", "checked": True, "hosts": 0,
                       "outcome": "commented: no detections remain (was 12) - this ticket can be closed"},
        "CVE-2026-2": {"key": "CR-9", "url": "https://x/browse/CR-9", "status": "Open",
                       "cve": "CVE-2026-2", "checked": True, "hosts": 227,
                       "outcome": "no change since the last report (227 host(s)) - no comment"},
        "CVE-2026-3": {"key": "CR-11", "url": "https://x/browse/CR-11", "status": "Done",
                       "done": True, "cve": "CVE-2026-3", "checked": True, "hosts": 0},
        "CVE-2026-4": {"key": "CR-12", "url": "javascript:alert(1)", "status": "<b>New</b>",
                       "outcome": "not re-checked: the scanner lookup failed"},
    }

    def data(self, tickets=None):
        return {"findings": [], "counts": {}, "total": 0, "generated": "now",
                "_tickets": self.TICKETS if tickets is None else tickets}

    def test_every_ticket_is_listed_open_first_in_key_order(self):
        open_, closed = brief._fleet_tickets(self.data())
        self.assertEqual([t["key"] for t in open_], ["CR-9", "CR-10", "CR-12"])
        self.assertEqual([t["key"] for t in closed], ["CR-11"])

    def test_the_html_says_what_the_recheck_found(self):
        html = brief.fleet_tickets_section(self.data())
        self.assertIn("FLEET TICKETS &mdash; 3 open", html)
        self.assertIn("no detections remain", html)
        self.assertIn("227 hosts", html)
        self.assertIn("not re-checked", html)
        self.assertIn("Closed in the last 30 days", html)
        self.assertNotIn("javascript:", html)
        self.assertNotIn("<b>New</b>", html)

    def test_it_reaches_the_rendered_daily_even_with_no_findings(self):
        html = brief.render(self.data(), "daily")
        self.assertIn("FLEET TICKETS", html)
        txt = brief.render_text(self.data(), "daily")
        self.assertIn("FLEET TICKETS - 3 open", txt)
        self.assertIn("CR-9", txt)
        self.assertIn("227 hosts", txt)

    def test_the_domains_lock_down_ticket_is_shown_as_such(self):
        t = {"DNS lock-down": {"key": "CR-50", "url": "https://x/browse/CR-50", "status": "Open",
                               "kind": "domains-lockdown",
                               "outcome": "the weekly domains lock-down ticket"}}
        html = brief.fleet_tickets_section(self.data(t))
        self.assertIn("DNS lock-down", html)
        self.assertIn("DNS changes for IT", html)
        self.assertNotIn("not re-checked", html)

    def test_no_tickets_no_section(self):
        self.assertEqual(brief.fleet_tickets_section(self.data({})), "")
        self.assertNotIn("FLEET TICKETS", brief.render_text(self.data({}), "daily"))

    def test_an_old_map_without_the_new_fields_still_renders(self):
        old = {"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9", "status": "Open"}}
        html = brief.fleet_tickets_section(self.data(old))
        self.assertIn("CR-9", html)
        self.assertIn("CVE-1", html)
        self.assertIn("not re-checked", html)


class HeldForApproval(unittest.TestCase):
    """A Sev5 held for approval is named in the digest, with the command.

    CVE-2026-111497 was held and the only trace was a journal line, so the
    reader could not tell "no ticket wanted" from "no ticket filed".
    """
    HELD = [{"cve": "CVE-2026-111497", "hosts": 14, "title": "Some <b>exploit</b>"}]

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.enriched = os.path.join(self.dir, "enriched-2026-10-02.json")
        self.tickets = os.path.join(self.dir, "enriched-2026-10-02-tickets.json")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_map(self, obj):
        with open(self.tickets, "w") as fh:
            json.dump(obj, fh)

    def held_data(self, held=None):
        d = {"findings": [], "counts": {}, "total": 0, "generated": "now", "_tickets": {}}
        d["_held"] = self.HELD if held is None else held
        d["_enriched"] = self.enriched
        return d

    def test_the_held_cve_the_hosts_and_the_command_reach_the_html(self):
        html = brief.held_section(self.held_data())
        self.assertIn("HELD FOR APPROVAL", html)
        self.assertIn("CVE-2026-111497", html)
        self.assertIn("14 hosts", html)
        self.assertIn("--for-real --approve", html)
        self.assertIn(self.enriched, html)

    def test_titles_are_escaped(self):
        html = brief.held_section(self.held_data())
        self.assertNotIn("<b>exploit</b>", html)

    def test_the_text_digest_names_it_too(self):
        text = brief.render_text(self.held_data(), "daily")
        self.assertIn("HELD FOR APPROVAL", text)
        self.assertIn("CVE-2026-111497", text)
        self.assertIn("--approve", text)

    def test_nothing_held_means_no_section(self):
        self.assertEqual(brief.held_section(self.held_data([])), "")
        self.assertNotIn("HELD FOR APPROVAL",
                         brief.render_text(self.held_data([]), "daily"))

    def test_load_held_reads_the_map_and_survives_a_bad_one(self):
        self.write_map({"tickets": {}, "held": self.HELD + ["junk", {"hosts": 2}]})
        self.assertEqual(brief.load_held(self.enriched), self.HELD)
        self.write_map({"tickets": {}, "held": "nope"})
        self.assertEqual(brief.load_held(self.enriched), [])
        self.write_map(["not", "a", "dict"])
        self.assertEqual(brief.load_held(self.enriched), [])
        self.assertEqual(brief.load_tickets(self.enriched), {})
        os.remove(self.tickets)
        self.assertEqual(brief.load_held(self.enriched), [])


class ProductName(unittest.TestCase):
    """Every finding and fleet ticket says which product it is about.

    Asked for 2026-11-09: "the targeted configuration item ... highlighted,
    i.e. Chrome, Safari, PHP". From the CISA KEV catalog first, NVD's CPE
    data second, and never guessed.
    """

    NVD = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:nodejs:node\\.js:*:*:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "not-a-cpe"},
    ]}]}]}

    def test_only_vulnerable_cpes_count_once_each(self):
        self.assertEqual(enrich.cpe_products(self.NVD),
                         [["google", "chrome"], ["nodejs", "node.js"]])

    def test_no_configuration_is_no_products(self):
        self.assertEqual(enrich.cpe_products({}), [])

    def test_names_read_like_names(self):
        self.assertEqual(enrich.product_for({"cpe_products": [["php", "php"]]}), ("PHP", "NVD"))
        self.assertEqual(enrich.product_for({"cpe_products": [["google", "chrome"]]}),
                         ("Google Chrome", "NVD"))
        self.assertEqual(enrich.product_for({"cpe_products": [["apple", "macos"]]}),
                         ("Apple macOS", "NVD"))
        self.assertEqual(enrich.product_name("Microsoft", "Microsoft Exchange Server"),
                         "Microsoft Exchange Server")

    def test_kev_wins_over_nvd(self):
        f = {"kev_vendor": "Google", "kev_product": "Chromium V8",
             "cpe_products": [["google", "chrome"]]}
        self.assertEqual(enrich.product_for(f), ("Google Chromium V8", "CISA KEV"))

    def test_a_long_list_is_cut_and_says_so(self):
        f = {"cpe_products": [["v", f"p{i}"] for i in range(5)]}
        name, _ = enrich.product_for(f)
        self.assertTrue(name.endswith("+2 more"), name)

    def test_nothing_known_is_empty_not_guessed(self):
        self.assertEqual(enrich.product_for({"description": "A flaw in Google Chrome."}), ("", ""))

    def test_the_map_keeps_kev_and_findings_and_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "products.json")
            enrich.save_products([{"cve": "CVE-2026-1", "product": "PHP"}],
                                 {"CVE-2026-2": {"kev_vendor": "Apple", "kev_product": "Safari"}}, path)
            enrich.save_products([{"cve": "CVE-2026-3", "product": "Node.js"}], {}, path)
            got = brief.load_products(os.path.join(tmp, "enriched-x.json"))
        self.assertEqual(got, {"CVE-2026-1": "PHP", "CVE-2026-2": "Apple Safari",
                               "CVE-2026-3": "Node.js"})

    def test_enrich_writes_product_on_every_finding(self):
        stub_enrichment()
        with tempfile.TemporaryDirectory() as tmp:
            raw, out = os.path.join(tmp, "r.md"), os.path.join(tmp, "e.json")
            with open(raw, "w") as f:
                f.write(REPORT)
            sys.argv = ["enrich.py", "--report", raw, "--out", out, "--no-db"]
            with quiet():
                enrich.main()
            with open(out) as fh:
                d = json.load(fh)
        self.assertTrue(all("product" in f for f in d["findings"]))

    TITLES = {
        "Google Chrome Prior to 131.0.6778.69 Multiple Vulnerabilities": "Google Chrome",
        "PHP Multiple Vulnerabilities (8.3.14)": "PHP",
        "Red Hat Update for kernel (RHSA-2026:1234)": "kernel (Red Hat)",
        "Microsoft Windows Security Update for November 2026": "Microsoft Windows",
        "Oracle Java SE Critical Patch Update - October 2026": "Oracle Java SE",
        "Microsoft Exchange Server Remote Code Execution Vulnerability": "Microsoft Exchange Server",
        "November 2026 Cumulative Update": "",
        "": "",
    }

    def test_a_scanner_title_is_cut_to_the_product(self):
        for title, want in self.TITLES.items():
            with self.subTest(title=title):
                self.assertEqual(enrich.product_from_title(title), want)

    def test_scanner_titles_are_the_last_resort(self):
        f = {"provider": "qualys", "detection_titles": [
            "Apple Safari Prior to 18.1 Multiple Vulnerabilities",
            "Apple Safari Prior to 18.0 Multiple Vulnerabilities"]}
        self.assertEqual(enrich.product_for(f), ("Apple Safari", "Qualys"))
        f["cpe_products"] = [["apple", "webkit"]]
        self.assertEqual(enrich.product_for(f), ("Apple Webkit", "NVD"))

    def test_the_report_titles_column_is_read(self):
        row = ("| CVE-2026-0007 | PRESENT | qualys | 1,2 | 3 | 90 | 2026-11-01 | host-a | "
               "a \\| b | Google Chrome Prior to 1.0 Multiple Vulnerabilities ; PHP Multiple "
               "Vulnerabilities (8.3) |\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "raw.md")
            with open(path, "w") as fh:
                fh.write(row)
            got = enrich.parse_report(path)["CVE-2026-0007"]
        self.assertEqual(got["provider_reason"], "a | b")
        self.assertEqual(got["detection_titles"], [
            "Google Chrome Prior to 1.0 Multiple Vulnerabilities", "PHP Multiple Vulnerabilities (8.3)"])
        self.assertEqual(enrich.product_for(got), ("Google Chrome, PHP", "Qualys"))

    def test_an_old_report_has_no_titles(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "raw.md")
            with open(path, "w") as fh:
                fh.write(REPORT)
            got = enrich.parse_report(path)
        self.assertTrue(all(f["detection_titles"] == [] for f in got.values()))
        self.assertTrue(all(f["mail_source"] == "" for f in got.values()))

    def test_the_report_mail_source_column_is_read(self):
        """PrimeSec 10786589: whether a trusted sender mentioned the CVE.
        Only the agent's two words count; anything else is unknown."""
        base = "| CVE-2026-00%02d | PRESENT | qualys | 1 | 3 | 90 | 2026-11-01 | host-a | | t | %s |\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "raw.md")
            with open(path, "w") as fh:
                for i, cell in enumerate(["trusted", "unverified", "Unverified", "", "maybe"]):
                    fh.write(base % (i + 1, cell))
            got = enrich.parse_report(path)
        self.assertEqual([got["CVE-2026-00%02d" % i]["mail_source"] for i in range(1, 6)],
                         ["trusted", "unverified", "unverified", "", ""])

    def finding(self, **kw):
        f = {"cve": "CVE-2026-9", "priority": "Sev5", "status": "PRESENT",
             "host_count": 3, "rationale": "r"}
        f.update(kw)
        return f

    def test_the_card_highlights_the_product(self):
        html = brief.finding_block(self.finding(product="Google <Chrome>", product_source="NVD"))
        self.assertIn("Google &lt;Chrome&gt;", html)
        self.assertIn('title="from NVD"', html)

    def test_the_card_says_when_no_product_was_found(self):
        self.assertIn("product not identified", brief.finding_block(self.finding(product="")))

    def test_an_old_row_without_the_field_renders_as_before(self):
        self.assertNotIn("product not identified", brief.finding_block(self.finding()))

    def test_fleet_tickets_name_the_product_from_the_map(self):
        d = {"findings": [self.finding(cve="CVE-2026-1", product="PHP")],
             "counts": {}, "total": 1, "generated": "now",
             "_products": {"CVE-2026-2": "Apple Safari"},
             "_tickets": {
                 "CVE-2026-1": {"key": "CR-1", "cve": "CVE-2026-1", "status": "Open"},
                 "CVE-2026-2": {"key": "CR-2", "cve": "CVE-2026-2", "status": "Open"},
                 "CVE-2026-3": {"key": "CR-3", "cve": "CVE-2026-3", "status": "Open"}}}
        html = brief.fleet_tickets_section(d)
        self.assertIn("PHP", html)
        self.assertIn("Apple Safari", html)
        txt = "\n".join(brief.fleet_tickets_text(d))
        self.assertIn("Product: PHP", txt)
        self.assertIn("Product: Apple Safari", txt)
        self.assertEqual(txt.count("Product:"), 2)

    def test_the_text_digest_names_the_product(self):
        d = {"findings": [self.finding(product="PHP")], "counts": {"Sev5": 1},
             "total": 1, "generated": "now"}
        self.assertIn("CVE-2026-9  [PHP]", brief.render_text(d, "daily"))


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
        # enrich.py re-upserts every finding each night. If that wiped the
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
        r = self.run_db("note", "CVE-9999-1", "CR-1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no finding", r.stdout)

    def test_a_note_can_be_cleared(self):
        self.run_db("note", "CVE-2026-85046", "CR-1234")
        self.run_db("note", "CVE-2026-85046")
        self.assertIsNone(self.findings()[0]["remediation_note"])
        self.backdate("CVE-2026-85046", days=5)
        self.assertEqual(len(self.findings("--stale-days", "2")), 1,
                         "clearing the note should make it stale again")


class EmailTokens(unittest.TestCase):
    """brief.py reads the palette the Go lanes read (internal/emailkit)."""

    def setUp(self):
        self.brief = load("brief")
        self.file = json.loads((KIT / "fleet" / "lanes" / "email-tokens.json").read_text())

    def test_the_builtin_fallback_is_the_file(self):
        # The fallback exists so a missing file cannot cost the 6am digest; it
        # must therefore say exactly what the file says.
        self.assertEqual(self.brief._TOKEN_FALLBACK, self.file)

    def test_the_severity_bands_use_the_shared_tones(self):
        tones = self.file["tones"]
        for sev, name in (("Sev5", "red"), ("Sev4", "amber"), ("Sev3", "yellow"),
                          ("Sev2", "blue"), ("Sev1", "grey")):
            self.assertEqual(self.brief.PRI[sev][:2], (tones[name]["fg"], tones[name]["bg"]), sev)

    def test_the_digest_page_is_drawn_from_the_tokens(self):
        data = {"counts": {}, "findings": [], "total": 0, "generated": "now", "source_meta": {}}
        with quiet():
            html = self.brief.render(data, "daily")
        for key in ("navy", "page_bg", "band_text"):
            self.assertIn(self.file[key], html, key)

    def test_a_missing_tokens_file_does_not_stop_the_digest(self):
        real = os.path.join
        try:
            os.path.join = lambda *a: "/nonexistent/email-tokens.json" if a[-1] == "email-tokens.json" else real(*a)
            self.assertEqual(self.brief.email_tokens(), self.brief._TOKEN_FALLBACK)
        finally:
            os.path.join = real


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
    """

    def setUp(self):
        self.scout = load("scout")

    def test_an_html_page_is_not_called_malformed_xml(self):
        html = (b"<!DOCTYPE html>\n<html lang=\"en-us\"><head><title>Blog MSRC"
                b"</title></head><body><h1>MSRC Blog</h1></body></html>")
        self.assertTrue(self.scout.looks_like_html(html))

        with contextlib.redirect_stderr(io.StringIO()) as err:
            items = self.scout.parse_feed(html, "https://example.invalid/feed")
        log = err.getvalue()

        self.assertEqual(items, [])
        self.assertIn("NOT A FEED", log)
        self.assertIn("feeds.txt", log,
                      "the message must say where to go and fix it")
        self.assertNotIn("mismatched tag", log,
                         "an XML parser error for an HTML page is the bug")

    def test_a_byte_order_mark_does_not_make_a_feed_look_like_html(self):
        # The MSRC Update Guide RSS is served with a UTF-8 BOM. A naive
        # startswith check against the raw bytes sees the BOM first and can
        # misfile a perfectly good feed, which would swap one silent blind
        # spot for another.
        feed = ("\ufeff<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                "<rss version=\"2.0\"><channel><item>"
                "<title>Chromium: CVE-2026-1 Type Confusion</title>"
                "<link>https://example.invalid/v/CVE-2026-1</link>"
                "<pubDate>Sun, 04 Oct 2026 02:13:15 -0700</pubDate>"
                "</item></channel></rss>").encode("utf-8")

        self.assertFalse(self.scout.looks_like_html(feed))
        with quiet():
            items = self.scout.parse_feed(feed, "https://example.invalid/rss")
        self.assertEqual(len(items), 1)
        self.assertIn("CVE-2026-1", items[0]["title"])

    def test_genuinely_malformed_xml_still_says_malformed(self):
        # The new branch must not swallow the case it was built beside.
        bad = b"<?xml version='1.0'?><rss><channel><item></channel></rss>"
        self.assertFalse(self.scout.looks_like_html(bad))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.scout.parse_feed(bad, "https://example.invalid/f")
        self.assertIn("malformed XML", err.getvalue())

    def test_a_feed_that_declares_entities_is_refused(self):
        # XML-bomb and external-entity attacks both need an <!ENTITY>; a real
        # feed has none. A bare DOCTYPE (RSS 0.91) is still parsed.
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa">]>'
                b"<rss><channel><item><title>&a;</title></item></channel></rss>")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            items = self.scout.parse_feed(bomb, "https://example.invalid/f")
        self.assertEqual(items, [])
        self.assertIn("entities", err.getvalue())

        plain = (b'<?xml version="1.0"?><!DOCTYPE rss PUBLIC "-//Netscape//DTD RSS 0.91//EN" '
                 b'"http://my.netscape.com/publish/formats/rss-0.91.dtd">'
                 b"<rss><channel><item><title>CVE-2026-9 patched</title>"
                 b"<link>https://example.invalid/x</link></item></channel></rss>")
        with quiet():
            self.assertEqual(len(self.scout.parse_feed(plain, "https://example.invalid/f")), 1)

    def test_only_http_urls_are_fetched(self):
        # urlopen also opens file:// and ftp://: a pasted feeds.txt line must
        # not read a local file into the report.
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(self.scout.fetch("file:///etc/passwd"))
            self.assertIsNone(self.scout.fetch("ftp://example.invalid/feed"))
        self.assertIn("not an http(s) URL", err.getvalue())

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
        # brief.py drops the section when email_subjects is missing. Setting it
        # to [] would render "0 total", which is a different claim.
        self.assertNotIn("email_subjects", self.rollup())

    def test_deadlines_are_computed_the_same_way_the_daily_reports_them(self):
        kev = self.rollup()["kev_deadlines"]
        self.assertEqual(kev["overdue"], 1)
        self.assertEqual(kev["worst_overdue_days"], 9)

    def test_the_rendered_weekly_states_its_provenance(self):
        d = self.rollup()
        enriched = os.path.join(self.tmp, "enriched.json")
        with open(enriched, "w", encoding="utf-8") as f:
            json.dump(d, f)
        out = os.path.join(self.tmp, "w.html")
        subprocess.run([sys.executable, str(LANES / "brief.py"), "--weekly",
                        "--enriched", enriched, "--out", out],
                       capture_output=True, check=True)
        html = pathlib.Path(out).read_text(encoding="utf-8")
        self.assertIn("no mailbox read this run", html)
        self.assertNotIn("EMAILS READ THIS RUN", html)


class WeeklyIsDistinguishableFromDaily(unittest.TestCase):
    """The weekly subject must never equal the daily subject.

    On Monday 2026-10-05 the 06:00 daily and the 07:00 weekly went out with
    byte-identical subjects - "CTI Oct 05: no new CVEs in the last 24h" - on a
    report covering seven days. subject() accepted a `kind` parameter and used
    it in none of its six return paths, and Python does not warn about that.

    The operator read it as the daily having sent twice. That was the correct
    reading of the evidence he had.
    """

    def setUp(self):
        self.brief = load("brief")

    def cases(self):
        return {
            "quiet": {"counts": {}, "total": 0, "findings": [], "kev_deadlines": {}},
            "sev5": {"counts": {"Sev5": 4}, "total": 9, "findings": [],
                     "kev_deadlines": {"overdue": 4, "worst_overdue_days": 12}},
            "overdue only": {"counts": {}, "total": 3, "findings": [],
                             "kev_deadlines": {"overdue": 2, "worst_overdue_days": 5}},
            "present": {"counts": {}, "total": 5, "kev_deadlines": {},
                        "findings": [{"status": "PRESENT", "host_count": 3,
                                      "priority": "Sev3"}]},
            "unverified": {"counts": {}, "total": 4, "kev_deadlines": {},
                           "findings": [{"status": "UNKNOWN", "priority": "Sev3"}]},
            "reviewed": {"counts": {}, "total": 7, "findings": [],
                         "kev_deadlines": {}},
        }

    def test_no_branch_produces_the_same_subject_for_both_kinds(self):
        for name, data in self.cases().items():
            daily = self.brief.subject(data, "daily")
            weekly = self.brief.subject(data, "weekly")
            self.assertNotEqual(
                daily, weekly,
                f"{name}: daily and weekly subjects are identical - {daily!r}")

    def test_the_weekly_says_weekly(self):
        for name, data in self.cases().items():
            s = self.brief.subject(data, "weekly")
            self.assertIn("Weekly", s, f"{name}: {s!r} does not say it is weekly")

    def test_neither_kind_claims_the_wrong_window(self):
        quiet = self.cases()["quiet"]
        self.assertIn("24h", self.brief.subject(quiet, "daily"))
        self.assertNotIn(
            "24h", self.brief.subject(quiet, "weekly"),
            "the weekly subject claims a 24-hour window")
        self.assertIn("7 days", self.brief.subject(quiet, "weekly"))


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
        ExecStart must point at a runner that is actually in the kit.
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
            # Every token, not just the first: cti-agent-scout runs
            # "/usr/bin/python3 /opt/cti-agent/lanes/scout.py", where the
            # thing that must exist is the argument, not the interpreter.
            kit = root / "fleet-kit" / "fleet"
            found = any(
                (kit / sub / pathlib.Path(tok).name).exists()
                for tok in m.group(1).split()
                for sub in ("bin", "lanes")
            )
            if not found:
                problems.append(
                    f"{service.name} runs {m.group(1)!r}, none of which is in "
                    f"fleet/bin/ or fleet/lanes/")
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
                     trace=False, stream=None, claude_rc=0):
        """A fake Linux box for run-checkin: a FLEET_CODE laid out the way
        install-fedora.sh lays it out, read-only to this test's user, and a
        fake stat(1) that reports root ownership unless told otherwise.

        overrides maps a path relative to the box to {"u": uid, "a": mode} for
        stat to report, so a single wrong entry can be tested on its own.
        plant lists paths relative to HOME to create before the run.
        trace installs the real fleet-trace and a cti-budget stub; stream is
        the stream-json the fake claude prints when asked for it, and
        claude_rc its exit status.
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
        for name in ("fleet-board", "fleet-db", "fleet-journal", "cti-alert") + (
                ("cti-budget",) if trace else ()):
            (code / "bin" / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{ran}"\n')
        if trace:
            shutil.copy(root / "fleet-kit" / "fleet" / "bin" / "fleet-trace",
                        code / "bin" / "fleet-trace")
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
        root = pathlib.Path(__file__).resolve().parents[2]
        return subprocess.run(
            [sys.executable, str(root / "fleet-kit" / "fleet" / "bin" / "fleet-trace"), *args],
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
            r = self._fleet_trace(d, "tee", "--out", str(out), "--plain", str(d / "plain"),
                                  "--max-mb", "1",
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
        guard = root / "fleet-kit" / "fleet" / "bin" / "checkin-bash-guard"
        cmd = ('/opt/cti-agent/bin/cti-alert --unit cti-agent-checkin.service --for-real '
               '--kind ESCALATION --reason "%s"' % m.group(1))
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        r = subprocess.run([sys.executable, "-I", str(guard)], input=payload,
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_bash_guard_refuses_shell_syntax_and_fails_closed(self):
        """A prefix grant names a command, not the shell around it. The guard
        hook lets through one granted command with plain arguments and
        blocks (exit 2) redirection, pipes, chaining, substitution and line
        breaks - and anything it cannot parse."""
        root = pathlib.Path(__file__).resolve().parents[2]
        guard = root / "fleet-kit" / "fleet" / "bin" / "checkin-bash-guard"
        self.assertEqual(guard.read_text(encoding="utf-8").split("\n")[0], "#!/usr/bin/python3 -I")

        def run(payload):
            data = payload if isinstance(payload, str) else json.dumps(payload)
            return subprocess.run([sys.executable, "-I", str(guard)], input=data,
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
        root = pathlib.Path(__file__).resolve().parents[2]
        return root / "fleet-kit" / "fleet" / "bin" / "checkin-bash-guard"

    def _run_guard(self, cmd, env=None):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        e = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
        e.update(env or {})
        return subprocess.run([sys.executable, "-I", str(self._guard())], input=payload,
                              capture_output=True, text=True, check=False, env=e)

    def test_the_guard_holds_each_granted_command_to_its_arguments(self):
        """PrimeSec design review 39260, Scenario-223: a prefix grant such as
        cti-alert:* lets any arguments through, so the guard also holds a table
        of what each granted command may be given."""
        b = "/opt/cti-agent/bin/"
        allowed = (
            b + "fleet-board read", b + "fleet-board read @all", b + "fleet-board tail 6",
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
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("checkin_guard", str(self._guard()))
        spec = importlib.util.spec_from_loader("checkin_guard", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        root = pathlib.Path(__file__).resolve().parents[2]
        run = (root / "fleet-kit" / "fleet" / "bin" / "run-checkin").read_text(encoding="utf-8")
        granted = set()
        for line in run.splitlines():
            if "ALLOWED_TOOLS" in line:
                granted.update(re.findall(r"\$FLEET_CODE/bin/([a-z-]+)", line))
        self.assertTrue(granted, "found no grants in run-checkin")
        self.assertEqual(granted, set(mod.POLICY),
                         "run-checkin's Bash grants and the guard's POLICY table differ")

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

    def test_fleet_sanitize_cleans_by_the_same_cases_as_the_go_twin(self):
        """Scenario-222. internal/sanitize (Go) and fleet-sanitize (Python) read
        one file of cases, so the two cannot drift."""
        cases = json.loads((pathlib.Path(__file__).resolve().parents[2] / "internal" / "sanitize"
                            / "testdata" / "sanitize-cases.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(cases), 10)
        for c in cases:
            with self.subTest(c["name"]):
                r = subprocess.run([sys.executable, "-I", str(self._bin("fleet-sanitize")),
                                    "--source", "test"], input=c["input"].encode("utf-8"),
                                   capture_output=True, check=False)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.decode("utf-8"), c["output"])
                self.assertEqual(r.stderr, b"", "the cleaner must never write to stderr: that goes to the model")

    def test_a_beat_reads_the_board_and_memory_cleaned_and_a_lane_reads_them_raw(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            board = pathlib.Path(home) / "board.md"
            board.write_text("[2026-11-10 09:00] @scout -> @you INFO id=x1 ok \x1b[2Jhidden \r EVIL\n"
                             "[2026-11-10 09:01] @scout -> @you INFO " + "y" * 3000 + "\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
            env.update({"FLEET_HOME": home})
            beat = dict(env, CHECKIN_BEAT_ID="b-1")

            def board_read(e):
                return subprocess.run(["/bin/bash", str(self._bin("fleet-board")), "read"],
                                      capture_output=True, text=True, check=False, env=e)
            raw, clean = board_read(env), board_read(beat)
            self.assertIn("\x1b", raw.stdout)
            self.assertNotIn("\x1b", clean.stdout)
            self.assertNotIn("\r", clean.stdout)
            self.assertIn("[cut ", clean.stdout)
            self.assertLess(max(len(x) for x in clean.stdout.splitlines()), 1100)
            # The same for fleet-db: what a memory says reaches the beat cleaned.
            subprocess.run(["/usr/bin/python3", "-sE", str(self._bin("fleet-db")), "remember", "scout",
                            "t1", "note \x1b[31mred\x1b[0m"], check=True, env=env, capture_output=True)

            def db_recent(e):
                return subprocess.run(["/usr/bin/python3", "-sE", str(self._bin("fleet-db")), "recent"],
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
        that is a regular file in bin/ (or lanes/ for .py) and nothing else."""
        root = pathlib.Path(__file__).resolve().parents[2]
        inst = (root / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        body = inst[inst.index("cat > /usr/local/bin/cti-agent <<WRAP\n") + len("cat > /usr/local/bin/cti-agent <<WRAP\n"):]
        body = body[:body.index("\nWRAP\n") + 1]
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            code, state, fake = d / "code", d / "state", d / "fakebin"
            for p in (code / "bin", code / "lanes", state, fake):
                p.mkdir(parents=True)
            (code / "bin" / "fleet-db").write_text("#!/bin/sh\n")
            (code / "lanes" / "scout.py").write_text("")
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
            r = run("scout.py", "--days", "1")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"{code}/lanes/scout.py", r.stdout.splitlines())
            for cmd in ("../../../../usr/bin/env", "../../../../bin/bash", "/usr/bin/env",
                        "fleet-db/../../../x", "..", ".hidden", "Fleet-DB", "env",
                        "linked", "nope", "x.py", "../lanes/scout.py", "fleet-db\nid"):
                with self.subTest(refused=cmd):
                    r = run(cmd, "-c", "id")
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertEqual(r.stdout, "", "sudo must not have been reached")

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
                flags += self.MAN_GO_FLAG.findall(f.read_text(encoding="utf-8"))
            with self.subTest(cmd=d.name):
                self.assertTrue(flags or d.name == "cti-agent", f"no flags found in {d}")
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

    def test_every_lane_argument_is_in_its_man_page(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        arg = re.compile(r"add_argument\(\s*\"--([a-z][a-z0-9-]*)\"")
        for lane in ("enrich.py", "scout.py", "brief.py", "mailer.py"):
            src = (root / "fleet-kit" / "fleet" / "lanes" / lane).read_text(encoding="utf-8")
            with self.subTest(lane=lane):
                self._assert_documented(lane, arg.findall(src))

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
    --out|--text-out|--csv-out|--actions-out|--seen-out|--tickets-out|--websites-out) next=out ;;
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
  "cti-patchtuesday"*"--subject-only"*) echo "Microsoft Patch Tuesday for October 2026" ;;
  "fleet-db was-sent"*)               echo no ;;
  "fleet-db rollup"*)                 echo '{"total": 0, "counts": {}}' ;;
esac
exit 0
"""

_LANE_STUB = r"""import sys, os
a = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(os.path.basename(sys.argv[0]) + " " + " ".join(a) + "\n")
if "--subject-only" in a:
    print("CTI daily digest")
for flag in ("--out", "--text-out"):
    if flag in a:
        open(a[a.index(flag) + 1], "w").write("<p>x</p>")
"""


class RunnersToDev(unittest.TestCase):
    """--to-dev on a runner: real pipeline, mail to FLEET_DEV_EMAIL only, and
    none of the side effects a real send has."""

    BIN = ("cti-mailer", "cti-alert", "cti-jira", "cti-domains", "cti-appscan", "cti-appreport",
           "cti-patchtuesday", "fleet-db", "fleet-board")

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
        for name in ("enrich.py", "brief.py"):
            (self.code / "lanes" / name).write_text(_LANE_STUB)
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
        # The digest's real and dry sends go through mailer.py.
        (self.code / "lanes" / "mailer.py").write_text(_LANE_STUB)

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
                enrich_ = [c for c in calls if c.startswith("enrich.py ")]
                self.assertIn("--no-db", enrich_[0], "the rehearsal upserted into memory.db")
                self.assertIn(f"--out {out}/enriched-{day}.json", enrich_[0])
                self.assertIn(f"--enriched {out}/enriched-{day}.json", [c for c in calls if c.startswith("brief.py ")][0])
                jira = [c for c in calls if c.startswith("cti-jira ")]
                self.assertEqual(jira, [f"cti-jira --from-enriched {out}/enriched-{day}.json --dry-run --follow-up"])
                # What the preview reads beside the enriched file, copied in.
                self.assertTrue((out / f"enriched-{day}-tickets.json").exists())
                self.assertTrue((out / "products.json").exists())
                self.assertEqual(oct(out.stat().st_mode & 0o777), "0o700")

    def test_digest_real_run_keeps_the_real_files_log_and_db(self):
        self.agent_logs_its_env()
        day = datetime.date.today().isoformat()
        r, calls = self.run_lane("run-digest", "daily", "--for-real")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"cti-agent processed= report={self.home}/reports/raw-{day}.md", calls)
        enrich_ = [c for c in calls if c.startswith("enrich.py ")]
        self.assertNotIn("--no-db", enrich_[0])
        self.assertIn(f"--out {self.home}/state/enriched-{day}.json", enrich_[0])
        self.assertFalse((self.home / "dryrun").exists())

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

    def test_a_rehearsal_refuses_while_the_lane_is_running(self):
        cases = (("run-digest", ["daily"], "digest-daily"), ("run-digest", ["weekly"], "digest-weekly"),
                 ("run-appscan", [], "appscan"), ("run-domains", [], "domains"))
        for runner, pre, lane in cases:
            for mode in ("--dry-run", "--to-dev"):
                with self.subTest(runner=runner, lane=lane, mode=mode), hold_lane_lock(self.home, lane):
                    self.log.write_text("")
                    r, calls = self.run_lane(runner, *pre, mode)
                    self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
                    self.assertIn("pid 4242", r.stderr, "the refusal must say which run holds the lane")
                    self.assertEqual(calls, [], "a refused rehearsal did work")
                    self.assertFalse((self.home / "dryrun").exists())

    def test_a_real_run_goes_ahead_past_a_rehearsal_that_outlasts_the_wait(self):
        # A long operator dry run must not cost the timer's run: rehearsals
        # write only their own files, so the real run waits, then goes on.
        cases = (("run-digest", ["daily"], "digest-daily"), ("run-appscan", [], "appscan"),
                 ("run-domains", [], "domains"))
        for runner, pre, lane in cases:
            with self.subTest(runner=runner), hold_lane_lock(self.home, lane, kind="dry"):
                self.log.write_text("")
                r, calls = self.run_lane(runner, *pre, "--for-real", env="FLEET_LOCK_WAIT_SECONDS=1\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("going ahead without it", r.stderr)
                sends = [c for c in calls if c.startswith(("cti-mailer ",))]
                if runner != "run-digest":
                    self.assertTrue(sends and "--for-real" in sends[-1], calls)

    def test_a_failed_dry_digest_says_dry_run_on_the_board(self):
        (self.code / "lanes" / "enrich.py").write_text("import sys\nsys.exit(1)\n")
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
                 ("run-domains", [], "domains"))
        for runner, pre, lane in cases:
            with self.subTest(runner=runner), hold_lane_lock(self.home, lane):
                self.log.write_text("")
                t0 = time.monotonic()
                r, calls = self.run_lane(runner, *pre, "--for-real", env="FLEET_LOCK_WAIT_SECONDS=1\n")
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


class TestUserAgent(unittest.TestCase):
    """The agent names a contact from GRAPH_MAILBOX, never a hardcoded one,
    and the two lanes that fetch build it the same way as internal/useragent."""

    CASES = [
        ({}, "p/1.0"),
        ({"GRAPH_MAILBOX": "fleet@example.com"}, "p/1.0 (+mailto:fleet@example.com)"),
        ({"FLEET_USER_AGENT": "cti-agent-fleet/1.0", "GRAPH_MAILBOX": "fleet@example.com"},
         "cti-agent-fleet/1.0 (+mailto:fleet@example.com)"),
        ({"FLEET_USER_AGENT": "acme/2 (+https://acme.example)", "GRAPH_MAILBOX": "fleet@example.com"},
         "acme/2 (+https://acme.example)"),
        ({"GRAPH_MAILBOX": "fleet@example.com) evil ("}, "p/1.0"),
        ({"GRAPH_MAILBOX": "fleet@example.com\r\nX-Evil: 1"}, "p/1.0"),
        ({"FLEET_USER_AGENT": "a\r\nX-Evil: 1"}, "p/1.0"),
    ]

    def test_both_lanes(self):
        scout = load("scout")
        for lane in (enrich, scout):
            for env, want in self.CASES:
                with self.subTest(lane=lane.__name__, env=env):
                    self.assertEqual(lane.user_agent("p/1.0", env), want)

    def test_no_address_in_the_lanes(self):
        for name in ("enrich", "scout"):
            src = (LANES / f"{name}.py").read_text()
            self.assertNotRegex(src, r"mailto:[A-Za-z0-9]", name)

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
        (self.code / "agents" / "supplier" / "CLAUDE.md").write_text("STANDING INSTRUCTIONS")
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.log = self.tmp / "calls.log"
        self.stub("cti-mailer", 'echo "mailer $*" >> "$CALLS"\n')
        self.stub("claude",
                  'echo "claude $*" >> "$CALLS"\n'
                  'echo "stdin: $(head -c 20)" >> "$CALLS"\n'
                  'echo \'{"schema":"cti-supplier/1"}\'\n')
        self.problems = ""
        self.requests = 2
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
  echo '{"entries":[{"id":"settled-earlier"}]}' > "$DIR/owned.json"
fi
if [ "$MODE" = finish ]; then
  %s
  echo '["fleet-supplier-x"]' > "$DIR/seen.json"
  echo '{"entries":[{"id":"settled-earlier"},{"id":"settled-now"}]}' > "$DIR/owned.json"
  printf '%%s' "%s" > "$DIR/problems.txt"
fi
""" % (self.requests, digest_cmds, self.problems))

    def run_it(self, *args, env=None):
        e = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "FLEET_HOME": str(self.home),
             "FLEET_CODE": str(self.code), "FLEET_ENV": str(self.tmp / "none.env"),
             "CALLS": str(self.log), "FLEET_DEV_EMAIL": "dev@example.test",
             "CLAUDE_BIN": str(self.code / "bin" / "claude")}
        e.update(env or {})
        return subprocess.run(["bash", str(self.RUNNER), *args], check=False,
                              capture_output=True, text=True, env=e)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

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
        guard = KIT / "fleet" / "bin" / "checkin-bash-guard"
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKIN_")}
        return subprocess.run([sys.executable, "-I", str(guard)], input=payload,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

