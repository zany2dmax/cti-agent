"""fleet-owners: owners.db and the owners.json snapshot the Go lanes read.

Run from fleet-kit: python3 -m unittest discover -s tests
"""
import json
import os
import pathlib
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "fleet-kit" / "fleet" / "bin" / "fleet-owners"
SAMPLE = ROOT / "fleet-kit" / "tests" / "testdata" / "app-owners-sample.txt"
# The Go side parses this same file in internal/appscan/ownersource_test.go,
# so the two languages cannot drift apart on the format.
GOLDEN = ROOT / "internal" / "appscan" / "testdata" / "owners-snapshot.json"


class FleetOwners(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.chmod(self.dir, 0o700)
        self.addCleanup(subprocess.run, ["rm", "-rf", self.dir])
        self.env = dict(os.environ, FLEET_OWNERS_DIR=self.dir, SUDO_USER="tester",
                        FLEET_GROUP="no-such-group-here")

    def run_tool(self, *args, ok=True):
        r = subprocess.run([sys.executable, str(TOOL), *args], env=self.env,
                           capture_output=True, text=True, timeout=30, check=False)
        if ok:
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def snapshot(self):
        with open(os.path.join(self.dir, "owners.json"), encoding="utf-8") as f:
            return json.load(f)

    def imported(self):
        self.run_tool("init")
        return self.run_tool("import", str(SAMPLE), "--allow-domains", "example.com, devshop.example")

    def test_init_is_private_and_idempotent(self):
        self.run_tool("init")
        db = os.path.join(self.dir, "owners.db")
        self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)
        # No such group: the snapshot stays owner-only rather than widening.
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, "owners.json")).st_mode), 0o600)
        self.assertIn("already exists", self.run_tool("init").stdout)
        self.assertEqual(self.snapshot()["apps"], [])

    def test_import_matches_the_golden_snapshot(self):
        out = self.imported().stdout
        self.assertIn("watchers= belongs on a web app's line", out)
        self.assertIn("not an email address", out)
        snap = self.snapshot()
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        for k in ("generated", "change"):
            snap.pop(k)
            golden.pop(k)
        self.assertEqual(snap, golden, "regenerate internal/appscan/testdata/owners-snapshot.json "
                         "only if the format change is deliberate - the Go reader checks it")

    def test_import_refuses_to_overwrite_without_replace(self):
        self.imported()
        r = self.run_tool("import", str(SAMPLE), ok=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--replace", r.stderr)
        self.run_tool("import", str(SAMPLE), "--replace")

    def test_edits_rewrite_the_snapshot_and_the_history(self):
        self.imported()
        before = self.snapshot()["change"]
        self.run_tool("set", "id:200", "--owner", "New.Owner@Example.com", "--component", "Shop")
        self.run_tool("watcher", "add", "id:200", "a@example.com", "b@example.com")
        self.run_tool("covers", "add", "id:200", "https://store.example.com/x")
        self.run_tool("site", "set", "www.new.example.net", "--owner", "web@example.com")
        self.run_tool("domain", "allow", "partner.example", "--note", "agency")
        snap = self.snapshot()
        self.assertEqual(snap["change"], before + 5)
        app = next(a for a in snap["apps"] if a["app"] == "id:200")
        self.assertEqual(app, {"app": "id:200", "owner": "new.owner@example.com", "component": "Shop",
                               "watchers": ["a@example.com", "b@example.com"], "covers": ["store.example.com"]})
        self.assertIn({"domain": "new.example.net", "owner": "web@example.com"}, snap["sites"])
        self.assertIn("partner.example", snap["allowedDomains"])
        hist = self.run_tool("history", "5").stdout
        self.assertIn("tester", hist)
        self.assertIn("domain allow", hist)
        self.run_tool("watcher", "rm", "id:200", "a@example.com")
        self.run_tool("rm", "id:200")
        self.assertNotIn("id:200", [a["app"] for a in self.snapshot()["apps"]])
        self.assertIn("was owner new.owner@example.com", self.run_tool("history", "1").stdout)

    def test_refused_changes_write_nothing(self):
        self.imported()
        snap = self.snapshot()
        for args in (("set", "id:101", "--owner", "not-an-email"),
                     ("set", "id:101", "--owner", "OWNER@example.com"),
                     ("set", "id:101", "--owner", "a@example.com", "--component", "watchers=evil@x.org"),
                     ("set", "site:x.example", "--owner", "a@example.com"),
                     ("set", "a|b", "--owner", "a@example.com"),
                     ("watcher", "add", "id:999", "a@example.com"),
                     ("watcher", "add", "id:101", *[f"w{i}@example.com" for i in range(10)]),
                     ("covers", "add", "id:101", "not a host"),
                     ("domain", "allow", "bad..example"),
                     ("rm", "id:999")):
            with self.subTest(args=args):
                r = self.run_tool(*args, ok=False)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.snapshot(), snap, "a refused change rewrote the snapshot")

    def test_history_is_append_only(self):
        self.imported()
        c = sqlite3.connect(os.path.join(self.dir, "owners.db"))
        for sql in ("UPDATE changes SET by='someone'", "DELETE FROM changes"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                c.execute(sql)
        c.close()

    def test_check_reports_what_stops_a_send(self):
        self.run_tool("init")
        r = self.run_tool("check", ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no allowed domains", r.stdout)
        self.imported_more()
        r = self.run_tool("check", ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("owner lead@example.com", r.stdout.replace("Lead", "lead"))
        self.run_tool("domain", "allow", "elsewhere.example")
        self.run_tool("domain", "rm", "elsewhere.example")
        self.run_tool("domain", "allow", "example.com", "devshop.example")
        r = self.run_tool("check")
        self.assertIn("0 problem(s) that stop a send", r.stdout)
        # A snapshot edited by hand, or left behind by a restore, is caught.
        p = os.path.join(self.dir, "owners.json")
        snap = self.snapshot()
        snap["change"] = 0
        with open(p, "w", encoding="utf-8") as f:
            json.dump(snap, f)
        self.assertIn("does not match owners.db", self.run_tool("check", ok=False).stdout)
        self.run_tool("snapshot")
        self.run_tool("check")

    def imported_more(self):
        self.run_tool("import", str(SAMPLE), "--allow-domains", "elsewhere.example")

    def test_export_reads_back_the_same(self):
        self.imported()
        first = self.snapshot()
        text = self.run_tool("export").stdout
        p = os.path.join(self.dir, "exported.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        self.run_tool("import", p, "--replace", "--allow-domains", "example.com,devshop.example")
        again = self.snapshot()
        for s in (first, again):
            s.pop("generated")
            s.pop("change")
        self.assertEqual(again, first)

    def test_backup_is_private_and_will_not_overwrite(self):
        self.imported()
        dest = os.path.join(self.dir, "b.db")
        self.run_tool("backup", dest)
        self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
        c = sqlite3.connect(dest)
        self.assertGreater(c.execute("SELECT COUNT(*) FROM apps").fetchone()[0], 0)
        c.close()
        self.assertEqual(self.run_tool("backup", dest, ok=False).returncode, 1)

    def test_root_reads_and_writes_only_trusted_paths(self):
        self.imported()
        # Relative: resolved in whatever directory root happens to be in.
        self.assertIn("absolute path", self.run_tool("import", "app-owners.txt", "--replace", ok=False).stderr)
        self.assertIn("absolute path", self.run_tool("backup", "b.db", ok=False).stderr)
        # A planted link is not followed, and a directory others can write is refused.
        target = os.path.join(self.dir, "target.db")
        link = os.path.join(self.dir, "link.db")
        os.symlink(target, link)
        self.assertEqual(self.run_tool("backup", link, ok=False).returncode, 1)
        self.assertFalse(os.path.exists(target), "backup followed a planted link")
        open_dir = os.path.join(self.dir, "open")
        os.mkdir(open_dir)
        os.chmod(open_dir, 0o777)
        self.assertIn("writable by someone other",
                      self.run_tool("backup", os.path.join(open_dir, "b.db"), ok=False).stderr)
        planted = os.path.join(open_dir, "app-owners.txt")
        with open(planted, "w", encoding="utf-8") as f:
            f.write("id:1 | someone@example.com\n")
        self.assertEqual(self.run_tool("import", planted, "--replace", ok=False).returncode, 1)
        loose = os.path.join(self.dir, "loose.txt")
        with open(loose, "w", encoding="utf-8") as f:
            f.write("id:1 | someone@example.com\n")
        os.chmod(loose, 0o666)
        self.assertEqual(self.run_tool("import", loose, "--replace", ok=False).returncode, 1)

    def listing(self, body="", name="apps.txt"):
        """A file in the shape cti-appscan --list-apps writes, in the 0700 test dir."""
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Application owners\n" + body)
        os.chmod(path, 0o600)
        return path

    def test_names_come_from_the_listing_and_show_in_list(self):
        self.run_tool("init")
        f = self.listing(
            "id:123456 | lead@example.com    # Billing Portal  https://billing.example.com/app  <- no owner\n"
            "id:777 | lead@example.com | watchers=qa@example.com    # Old   Wiki https://wiki.example.net/\n"
            "id:55 | lead@example.com    # no url here\n"
            "Named Entry | lead@example.com\n")
        self.run_tool("import", f, "--allow-domains", "example.com,example.net")
        out = self.run_tool("list").stdout
        self.assertIn("Billing Portal", out)
        self.assertIn("Old Wiki", out)  # inner spaces tidied
        self.assertIn("no url here", out)
        self.assertNotIn("<- no owner", out)
        self.assertIn("billing.example.com", self.run_tool("show", "id:123456").stdout)
        # The names are display-only: the lanes' snapshot never carries them.
        self.assertNotIn("Billing Portal", json.dumps(self.snapshot()))

    def test_names_refresh_reports_and_changes_only_what_differs(self):
        self.imported()
        self.run_tool("set", "id:900", "--owner", "lead@example.com")
        first = self.run_tool("names", self.listing(
            "id:900 | lead@example.com    # Shop  https://shop.example.com/\n"
            "id:31337 | lead@example.com    # Not In The Database https://x.example.com/\n")).stdout
        self.assertIn("2 set, 0 unchanged; 1 of them for applications not in owners.db yet", first)
        again = self.run_tool("names", self.listing(
            "id:900 | lead@example.com    # Shop  https://shop.example.com/\n", "again.txt")).stdout
        self.assertIn("0 set, 1 unchanged", again)
        renamed = self.run_tool("names", self.listing(
            "id:900 | lead@example.com    # Shop v2  https://shop.example.com/\n", "third.txt")).stdout
        self.assertIn("1 set", renamed)
        self.assertIn("Shop v2", self.run_tool("list").stdout)
        self.assertIn("2 set, 0 unchanged", self.run_tool("history").stdout)  # who refreshed them is on record

    def test_a_name_listed_before_the_owner_is_set_still_shows(self):
        # The order that used to lose the name: names first, set afterwards.
        self.imported()
        self.run_tool("names", self.listing("id:4242 | OWNER@example.com    # New Portal  https://new.example.com/  <- no owner\n"))
        self.run_tool("set", "id:4242", "--owner", "lead@example.com")
        self.assertIn("New Portal", self.run_tool("list").stdout)
        self.assertIn("new.example.com", self.run_tool("show", "id:4242").stdout)
        self.assertNotIn("New Portal", json.dumps(self.snapshot()))

    def test_scanner_text_cannot_carry_terminal_escapes(self):
        self.run_tool("init")
        f = self.listing("id:5 | lead@example.com    # Evil\x1b[31m name\x07  https://e.example.org/\n")
        self.run_tool("import", f, "--allow-domains", "example.com")
        out = self.run_tool("list").stdout
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("Evil [31m name", out)

    def test_a_database_from_before_names_gains_the_table(self):
        self.imported()
        db = os.path.join(self.dir, "owners.db")
        c = sqlite3.connect(db)
        c.execute("DROP TABLE app_names")
        c.execute("DROP TABLE scanner_apps")
        c.commit()
        c.close()
        self.assertIn("run: fleet-owners sync", self.run_tool("list").stdout)

    def test_an_address_is_one_address(self):
        self.imported()
        for bad in ("x@evil.example,y@example.com", "qa@example.com;evil.example", "qa@example.com\nx@evil.example"):
            with self.subTest(bad=bad):
                self.assertEqual(self.run_tool("watcher", "add", "id:101", bad, ok=False).returncode, 1)

    def test_replace_keeps_what_it_replaced_in_the_history(self):
        self.imported()
        self.run_tool("import", str(SAMPLE), "--replace")
        hist = self.run_tool("history", "200").stdout
        self.assertIn("replaced", hist)
        self.assertIn("lead@example.com", hist)
        self.assertIn("import", self.run_tool("show", "id:101").stdout)

    def test_allowing_an_allowed_domain_changes_nothing(self):
        self.imported()
        before = self.snapshot()["change"]
        self.assertIn("already allowed", self.run_tool("domain", "allow", "example.com").stdout)
        self.assertEqual(self.snapshot()["change"], before)

    def test_no_database_is_a_clear_error(self):
        r = self.run_tool("list", ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("fleet-owners init", r.stderr)


class Sync(unittest.TestCase):
    """sync asks the scanner (through a stand-in cti-agent wrapper) and reports drift."""

    # The harness only, not FleetOwners' tests (subclassing would run them twice).
    setUp = FleetOwners.setUp
    run_tool = FleetOwners.run_tool
    snapshot = FleetOwners.snapshot

    def fake_scanner(self, listing, stderr="", rc=0, mode=0o700):
        code = os.path.join(self.dir, "code")
        os.makedirs(os.path.join(code, "bin"), mode=0o700, exist_ok=True)
        os.chmod(code, 0o700)
        os.chmod(os.path.join(code, "bin"), 0o700)
        out = os.path.join(code, "listing.json")
        with open(out, "w", encoding="utf-8") as f:
            f.write(listing if isinstance(listing, str) else json.dumps(listing))
        exe = os.path.join(code, "bin", "cti-agent")
        with open(exe, "w", encoding="utf-8") as f:
            # The wrapper is how the scanner runs as the service account with
            # /etc/cti-agent/fleet.env; sync must call it, never cti-appscan.
            f.write(f"#!/bin/sh\n[ \"$1 $2 $3\" = 'cti-appscan --list-apps --json' ] || exit 9\n"
                    f"[ -z \"$FLEET_ENV$FLEET_HOME$FLEET_CODE\" ] || exit 8\ncat '{out}'\n"
                    f"printf '%s' '{stderr}' >&2\nexit {rc}\n")
        os.chmod(exe, mode)
        self.env["FLEET_OWNERS_WRAPPER"] = exe
        self.env["FLEET_ENV"] = "/var/lib/cti-agent/fleet.env"   # must not reach the scanner

    @staticmethod
    def jlisting(apps, unscanned=(), coverage=True):
        return {"format": "cti-applist/1", "coverage": coverage, "unscanned": list(unscanned),
                "apps": [{"id": i, "name": n, "host": h} for i, n, h in apps]}

    APPS = [("111", "Billing", "billing.example.com"),
            ("222", "Brochure", "brochure.example.com"),
            ("333", "Lab", "lab.example.net")]

    @property
    def LISTING(self):
        return self.jlisting(self.APPS, ["still.example.com"])

    def setup_db(self):
        self.run_tool("init")
        self.run_tool("domain", "allow", "example.com")
        self.run_tool("set", "id:111", "--owner", "lead@example.com")
        self.run_tool("set", "id:999", "--owner", "lead@example.com")       # deleted in Qualys
        self.run_tool("site", "set", "brochure.example.com", "--owner", "web@example.com")
        self.run_tool("site", "set", "still.example.com", "--owner", "web@example.com")
        self.run_tool("site", "set", "gone.example.com", "--owner", "web@example.com")

    def test_report_names_every_kind_of_drift_and_changes_no_owner(self):
        self.setup_db()
        self.fake_scanner(self.LISTING)
        before = self.snapshot()
        out = self.run_tool("sync").stdout
        self.assertIn("Qualys lists 3 web app(s)", out)
        self.assertIn("fleet-owners set id:222 --owner web@example.com", out)
        self.assertIn("fleet-owners site rm brochure.example.com", out)
        self.assertIn("id:333 (Lab, lab.example.net) has no owner", out)
        self.assertIn("id:999 is in owners.db but not in the scanner", out)
        self.assertIn("site:gone.example.com is no longer one of the domains lane's live websites", out)
        self.assertNotIn("site rm still.example.com", out)       # still unscanned: nothing to do
        self.assertIn("--apply", out)
        snap = self.snapshot()
        for k in ("generated", "change"):
            snap.pop(k, None)
            before.pop(k, None)
        self.assertEqual(snap, before, "sync without --apply must not change who is mailed")
        listed = self.run_tool("list").stdout
        self.assertIn("Billing", listed)

    def test_apply_moves_the_site_owner_to_the_web_app_and_nothing_else(self):
        self.setup_db()
        self.fake_scanner(self.LISTING)
        out = self.run_tool("sync", "--apply").stdout
        self.assertIn("2 change(s) applied", out)
        show = self.run_tool("show", "id:222").stdout
        self.assertIn("web@example.com", show)
        self.assertIn("Brochure", show)
        listed = self.run_tool("list").stdout
        self.assertNotIn("site:brochure.example.com", listed)
        self.assertIn("site:still.example.com", listed)
        self.assertIn("site:gone.example.com", listed)       # reported, never removed by --apply
        self.assertIn("id:999", listed)                      # likewise
        self.assertNotIn("id:333", listed)                   # no owner to give it: left to you
        hist = self.run_tool("history").stdout
        self.assertIn("sync: from site:brochure.example.com", hist)
        again = self.run_tool("sync").stdout
        self.assertNotIn("fleet-owners set id:222", again)

    def test_two_unowned_apps_on_one_site_are_left_to_you(self):
        self.setup_db()
        self.fake_scanner(self.jlisting([a if a[0] != "333" else ("333", "Lab", "brochure.example.com")
                                        for a in self.APPS], ["still.example.com"]))
        out = self.run_tool("sync", "--apply").stdout
        self.assertIn("give one of them web@example.com", out)
        self.assertNotIn("web@example.com", self.run_tool("show", "id:222", ok=False).stdout)
        # Nobody was given the owner, so the row that records it stays.
        self.assertIn("site:brochure.example.com", self.run_tool("list").stdout)

    def test_without_the_website_list_site_rows_are_judged_only_by_a_match(self):
        self.setup_db()
        self.fake_scanner(self.jlisting(self.APPS, coverage=False))
        out = self.run_tool("sync", "--apply").stdout
        self.assertIn("changes nothing this run", out)
        self.assertNotIn("gone.example.com", out)
        self.assertIn("site rm brochure.example.com", out)        # reported...
        self.assertIn("site:brochure.example.com", self.run_tool("list").stdout)   # ...not acted on
        self.assertNotIn("web@example.com", self.run_tool("show", "id:222", ok=False).stdout)

    def test_a_failed_listing_changes_nothing(self):
        self.setup_db()
        self.fake_scanner("", stderr="listing the web apps: 401", rc=1)
        r = self.run_tool("sync", ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("exit 1", r.stderr)
        self.fake_scanner(self.jlisting([]))
        r = self.run_tool("sync", ok=False)
        self.assertIn("listed no web apps", r.stderr)
        for bad, why in (("not json", "did not print JSON"),
                         ({"format": "cti-applist/9", "apps": [], "unscanned": [], "coverage": True}, "does not know"),
                         (self.jlisting([("12x", "A", "a.example.com")]), "not a number"),
                         ({"format": "cti-applist/1", "apps": [{"id": "1"}], "unscanned": [], "coverage": True},
                          "malformed web app")):
            with self.subTest(why=why):
                self.fake_scanner(bad)
                self.assertIn(why, self.run_tool("sync", ok=False).stderr)
        self.assertIn("id:999", self.run_tool("list").stdout)

    def test_a_url_in_an_apps_name_cannot_claim_a_site(self):
        # Anyone who can create a web app in Qualys picks its name. Only the
        # host field, from the real URL, is matched - never the name.
        self.setup_db()
        self.fake_scanner(self.jlisting([
            ("111", "Billing", "billing.example.com"),
            ("444", "Shop https://brochure.example.com <-", "evil.example.org"),
            ("555", "brochure.example.com", "")], ["brochure.example.com", "still.example.com"]))
        out = self.run_tool("sync", "--apply").stdout
        self.assertNotIn("now scans brochure", out)
        for app in ("id:444", "id:555"):
            self.assertNotIn("web@example.com", self.run_tool("show", app, ok=False).stdout)
        self.assertIn("site:brochure.example.com", self.run_tool("list").stdout)

    def test_scanner_names_are_tidied(self):
        self.setup_db()
        self.fake_scanner(self.jlisting([("111", "Bill\x1b[31ming\x07", "billing.example.com")]))
        out = self.run_tool("sync").stdout + self.run_tool("list").stdout
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_refuses_a_scanner_binary_others_can_change(self):
        self.setup_db()
        self.fake_scanner(self.LISTING, mode=0o722)
        r = self.run_tool("sync", ok=False)
        self.assertIn("writable only by it", r.stderr)

    def test_names_without_a_file_asks_the_scanner(self):
        self.setup_db()
        self.fake_scanner(self.LISTING)
        self.assertIn("Qualys lists 3 web app(s)", self.run_tool("names").stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
