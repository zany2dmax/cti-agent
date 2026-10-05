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
        self.assertIn(f"+3 more Sev4 in the full report", text,
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
        self.assertIn("CTI agent fleet", html)
        self.assertNotIn("Claude Code Agent Fleet", html)

    def test_a_url_alone_is_enough_and_names_the_org(self):
        os.environ["FLEET_ORG"] = "Construction Resources"
        os.environ["FLEET_REPO_URL"] = "https://github.com/example/cti-agent"
        text, url = brief.attribution()
        self.assertIn("Construction Resources Claude Code Agent Fleet", text)
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
            "FLEET_ALLOW_TO": "soc@example.com",
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

    def test_no_recipient_is_refused_rather_than_guessed(self):
        del os.environ["DIGEST_TO"]
        del os.environ["FLEET_ALLOW_TO"]
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
            self.env(FLEET_ALLOW_TO="dl@example.com,ok@example.com"),
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
            FLEET_ALLOW_TO="dl@example.com,ok@example.com"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cc"], ["ok@example.com"])

    def test_allowlist_can_supply_the_cc(self):
        # One edit instead of two: add a standing recipient to FLEET_ALLOW_TO
        # and they receive the digest.
        code, out = self.run_mailer(self.env(
            FLEET_ALLOW_TO="dl@example.com,alice@example.com,bob@example.com",
            DIGEST_CC_FROM_ALLOW_TO="true"))
        self.assertEqual(code, 0)
        self.assertEqual(sorted(json.loads(out)["cc"]),
                         ["alice@example.com", "bob@example.com"])

    def test_allowlist_cc_excludes_the_to_recipients(self):
        # DIGEST_TO is in the allowlist by definition, so without this every
        # digest would CC its own To line.
        code, out = self.run_mailer(self.env(
            FLEET_ALLOW_TO="dl@example.com", DIGEST_CC_FROM_ALLOW_TO="1"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cc"], [])

    def test_allowlist_cc_does_not_include_the_operator(self):
        # The operator is added to the allow SET in code so escalations always
        # work. Deriving the CC from the raw variable keeps them off the
        # digest unless they are listed deliberately.
        code, out = self.run_mailer(self.env(
            FLEET_ALLOW_TO="dl@example.com,alice@example.com",
            DIGEST_CC_FROM_ALLOW_TO="yes"))
        self.assertEqual(code, 0)
        self.assertNotIn("op@example.com", json.loads(out)["cc"])

    def test_allowlist_cc_merges_with_an_explicit_digest_cc(self):
        code, out = self.run_mailer(self.env(
            FLEET_ALLOW_TO="dl@example.com,alice@example.com,carol@example.com",
            DIGEST_CC="alice@example.com",
            DIGEST_CC_FROM_ALLOW_TO="on"))
        self.assertEqual(code, 0)
        cc = json.loads(out)["cc"]
        self.assertEqual(sorted(cc), ["alice@example.com", "carol@example.com"])
        self.assertEqual(len(cc), len(set(cc)), "merged CC contains a duplicate")

    def test_allowlist_cc_is_off_unless_explicitly_enabled(self):
        for value in ("", "ture", "maybe", "0", "false", "no"):
            code, out = self.run_mailer(self.env(
                FLEET_ALLOW_TO="dl@example.com,alice@example.com",
                DIGEST_CC_FROM_ALLOW_TO=value))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["cc"], [],
                             f"{value!r} should not enable allowlist CC")

    def test_allowlist_cc_never_applies_to_an_escalation(self):
        tmp = tempfile.TemporaryDirectory()
        old = dict(os.environ)
        os.environ.clear()
        os.environ.update(self.env(FLEET_ALLOW_TO="dl@example.com,alice@example.com",
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
            self.env(FLEET_ALLOW_TO="dl@example.com,notanemail"), "--cc", "notanemail")
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
                              env=self.env, capture_output=True, text=True)

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
                              input=stdin, timeout=30)

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

    def test_nothing_is_defined_after_the_main_block(self):
        src = pathlib.Path(__file__).read_text(encoding="utf-8")
        marker = 'if __name__ == "__main__":'
        self.assertIn(marker, src)
        after = src[src.index(marker):]
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
        for pattern in ("**/*.py", "**/*.go", "**/*.sh", "**/*.yml"):
            for f in root.glob(pattern):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

