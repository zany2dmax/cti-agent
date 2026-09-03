#!/usr/bin/env python3
"""Tests for the fleet lanes. Stdlib unittest only - no pip install.

    python3 -m unittest discover -s fleet-kit/tests -v
    task test:lanes

Network is never touched: the enrichment fetchers are stubbed, so these run
offline and deterministically. What they cover is the logic that decides what a
human sees - priority assignment, report parsing, digest rendering, and the
mailer's autonomy gate.
"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
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
            self.assertRegex(cve, r"^CVE-\d{4}-\d{4,7}$")

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
            # present + actively exploited -> today
            "CVE-2021-44228": ("P1", "present, KEV, EPSS 100%"),
            "CVE-2020-1472":  ("P1", "present, KEV, EPSS 99%"),
            "CVE-2025-33073": ("P1", "present, EPSS 21% (over the 10% bar)"),
            # present, not being exploited -> this patch cycle, regardless of CVSS
            "CVE-2026-9110":  ("P2", "present on 379 hosts"),
            "CVE-2026-45659": ("P2", "present on 186 hosts, CVSS only 5.5"),
            "CVE-2023-35636": ("P2", "present on 4 hosts, CVSS 6.5"),
            # cannot prove we are clean, and it is being exploited
            "CVE-2026-49975": ("P2", "UNKNOWN + KEV + EPSS 78%"),
            # exploited but not detected here -> verify coverage
            "CVE-2008-4250":  ("P3", "EPSS 94% but NOT_PRESENT"),
            "CVE-2022-0492":  ("P3", "KEV but NOT_PRESENT"),
            "CVE-2026-0826":  ("P3", "UNKNOWN + CVSS 9.8 = coverage gap"),
            # nothing to act on
            "CVE-2026-8206":  ("P4", "UNKNOWN, CVSS 4.3, no exploitation"),
        }
        for cve, (want, why) in expected.items():
            with self.subTest(cve=cve, rationale=why):
                self.assertEqual(pri[cve], want, f"{cve}: {why}")

    def test_present_never_ranks_below_not_present(self):
        """The regression that motivated the current thresholds."""
        pri, _ = self.build()
        order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        present_worst = max(order[pri[c]] for c in
                            ("CVE-2026-45659", "CVE-2023-35636", "CVE-2026-9110"))
        absent_best = min(order[pri[c]] for c in ("CVE-2008-4250", "CVE-2022-0492"))
        self.assertLess(present_worst, absent_best,
                        "a PRESENT finding ranked at or below a NOT_PRESENT one")

    def test_unknown_with_critical_cvss_is_not_p4(self):
        pri, _ = self.build()
        self.assertNotEqual(pri["CVE-2026-0826"], "P4",
                            "UNKNOWN means we did not look, not that we are clean")

    def test_sorted_by_priority_then_host_count(self):
        _, data = self.build()
        order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        keys = [(order[f["priority"]], -(f["host_count"] or 0))
                for f in data["findings"]]
        self.assertEqual(keys, sorted(keys), "findings are not ordered for triage")

    def test_counts_match_findings(self):
        _, data = self.build()
        for p in ("P1", "P2", "P3", "P4"):
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
        self.assertGreater(data["counts"]["P2"], 0)

    def test_degraded_banner_reaches_the_digest(self):
        data = {"generated": "2026-09-02T00:00:00+00:00", "source_meta": {},
                "counts": {"P1": 0, "P2": 0, "P3": 0, "P4": 0}, "total": 0,
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

    def test_subject_leads_with_p1(self):
        d = self.enriched()
        self.assertTrue(brief.subject(d, "daily").startswith("[P1]"))

    def test_subject_without_p1_does_not_cry_wolf(self):
        d = self.enriched()
        d["findings"] = [f for f in d["findings"] if f["priority"] != "P1"]
        d["counts"]["P1"] = 0
        self.assertFalse(brief.subject(d, "daily").startswith("[P1]"))

    def test_empty_run_still_says_something_useful(self):
        d = {"generated": "x", "source_meta": {}, "total": 0, "degraded": [],
             "counts": {"P1": 0, "P2": 0, "P3": 0, "P4": 0}, "findings": []}
        self.assertIn("no new CVEs", brief.subject(d, "daily"))
        self.assertIn("Nothing to action", brief.render(d, "daily"))

    def test_html_tags_balance(self):
        html = brief.render(self.enriched(), "daily")
        self.assertEqual(html.count("<table"), html.count("</table>"))
        self.assertEqual(html.count("<tr"), html.count("</tr>"))

    def test_p4_suppressed_daily_shown_weekly(self):
        d = self.enriched()
        self.assertNotIn("Awareness only", brief.render(d, "daily"))
        self.assertIn("Awareness only", brief.render(d, "weekly"))

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
        self.assertIn("P1", text)
        self.assertIn("Presence determined solely", text)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
