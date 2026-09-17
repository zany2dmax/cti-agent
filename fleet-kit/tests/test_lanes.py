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
import datetime
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

    def test_sev1_suppressed_daily_shown_weekly(self):
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
        self.assertIn("Sev5", text)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
