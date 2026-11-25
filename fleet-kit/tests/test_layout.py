#!/usr/bin/env python3
"""fleet-kit/layout.sh: where the kit installs the fleet (docs/layout.md).

layout_load reads a fork's layout.env (never sources it), checks every value
and defaults the rest to the FHS layout; layout_relocate rewrites the default
paths and account name in an installed file to the layout's. Both run here
in bash against scratch files.

    python3 -m unittest discover -s fleet-kit/tests
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
LAYOUT = REPO / "fleet-kit" / "layout.sh"
UNIT = REPO / "fleet-kit" / "fleet" / "systemd-fedora" / "cti-agent-domains.service"

RELOCATED = """LAYOUT_CODE_DIR=/srv/fleet/code
LAYOUT_CONF_DIR=/srv/fleet/etc
LAYOUT_STATE_DIR=/srv/fleet/state
LAYOUT_LOG_DIR=/srv/fleet/log
LAYOUT_USER=fleet
"""


class Layout(unittest.TestCase):
    def setUp(self):
        self.kit = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.kit)

    def bash(self, script, layout=None, stdin=None):
        if layout is not None:
            (self.kit / "layout.env").write_text(layout)
        s = f'set -euo pipefail\n. "{LAYOUT}"\nlayout_load "{self.kit}"\n' + script
        return subprocess.run(["bash", "-c", s], capture_output=True, text=True, input=stdin, check=False)

    def values(self, layout=None):
        r = self.bash('printf "%s|%s|%s|%s|%s|%s|%s\\n" "$CODE_DIR" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR" '
                      '"$FLEET_USER" "$FLEET_GROUP" "${LAYOUT_RELOCATED:-}"', layout)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip().split("|")

    def test_no_file_is_the_fhs_layout(self):
        self.assertEqual(self.values(), ["/opt/cti-agent", "/etc/cti-agent", "/var/lib/cti-agent",
                                         "/var/log/cti-agent", "ctiagent", "ctiagent", ""])

    def test_a_layout_file_sets_them_all(self):
        self.assertEqual(self.values(RELOCATED), ["/srv/fleet/code", "/srv/fleet/etc", "/srv/fleet/state",
                                                  "/srv/fleet/log", "fleet", "fleet", "1"])

    def test_the_repo_is_the_kits_own_remote(self):
        subprocess.run(["git", "init", "-q", str(self.kit)], check=True)
        subprocess.run(["git", "-C", str(self.kit), "remote", "add", "origin", "https://example.com/fork/cti-agent"],
                       check=True)
        r = self.bash('echo "$AGENT_REPO"')
        self.assertEqual(r.stdout.strip(), "https://example.com/fork/cti-agent")
        r = self.bash('echo "$AGENT_REPO"', "LAYOUT_REPO=git@example.com:fork/cti-agent.git\n")
        self.assertEqual(r.stdout.strip(), "git@example.com:fork/cti-agent.git")

    def test_bad_values_stop_it(self):
        for bad, why in (
            ("LAYOUT_CODE_DIR=srv/fleet\n", "an absolute path"),
            ("LAYOUT_CODE_DIR=/\n", "not the root directory"),
            ("LAYOUT_CODE_DIR=/srv/../etc\n", "no . or .."),
            ("LAYOUT_CODE_DIR=/srv/fleet/\n", "no trailing /"),
            ("LAYOUT_CODE_DIR=/srv/fleet;rm -rf /\n", "letters, digits"),
            ("LAYOUT_CODE_DIR=/srv/fleet\nLAYOUT_CONF_DIR=/srv/fleet/etc\n", "is inside /srv/fleet"),
            ("LAYOUT_STATE_DIR=/etc/cti-agent/state\n", "is inside /etc/cti-agent"),
            ("LAYOUT_CODE_DIR=/srv/code\nLAYOUT_STATE_DIR=/opt/cti-agent/state\n", "holds the default path /opt/cti-agent"),
            ("LAYOUT_USER=Root\n", "a lower-case account name"),
            ("LAYOUT_STATE_DIR=/home/fleet/state\n", "which the units hide"),
            ("LAYOUT_CODE_DIR=/tmp/fleet\n", "which the units hide"),
            ("LAYOUT_REPO=file:///tmp/x\n", "an https://, ssh:// or git@ URL"),
            ("LAYOUT_CODEDIR=/srv/x\n", "is not a layout setting"),
            ("just words\n", "is not KEY=value"),
        ):
            with self.subTest(layout=bad):
                r = self.bash("echo LOADED", bad)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(why, r.stderr)
                self.assertNotIn("LOADED", r.stdout)

    def test_it_is_read_never_sourced(self):
        marker = self.kit / "RAN"
        r = self.bash("true", f"LAYOUT_USER=fleet\n$(touch {marker})\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(marker.exists())

    def test_the_rewrite(self):
        text = ("ExecStart=/opt/cti-agent/bin/run-domains --for-real\n"
                "User=ctiagent\nGroup=ctiagent\nchown root:ctiagent /etc/cti-agent/fleet.env\n"
                "Environment=FLEET_HOME=/var/lib/cti-agent\nLogsDirectory=cti-agent\n"
                "snapshots: /var/lib/cti-agent-update/x\nunit cti-agent-checkin.service\n"
                "audit trail in /var/log/cti-agent.\n\"/opt/cti-agent\"\nstaged in /opt/cti-agent.next\n")
        r = self.bash("layout_relocate", RELOCATED, stdin=text)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, (
            "ExecStart=/srv/fleet/code/bin/run-domains --for-real\n"
            "User=fleet\nGroup=fleet\nchown root:fleet /srv/fleet/etc/fleet.env\n"
            "Environment=FLEET_HOME=/srv/fleet/state\nReadWritePaths=/srv/fleet/log\n"
            "snapshots: /var/lib/cti-agent-update/x\nunit cti-agent-checkin.service\n"
            "audit trail in /srv/fleet/log.\n\"/srv/fleet/code\"\nstaged in /opt/cti-agent.next\n"))
        again = self.bash("layout_relocate", RELOCATED, stdin=r.stdout)
        self.assertEqual(again.stdout, r.stdout, "rewriting twice changed it again")
        same = self.bash("layout_relocate", "", stdin=text)
        self.assertEqual(same.stdout, text, "the default layout must change nothing")

    def test_a_real_unit_keeps_nothing_of_the_default_layout(self):
        f = self.kit / "unit.service"
        shutil.copy(UNIT, f)
        b = self.kit / "binary"
        b.write_bytes(b"\x00\x01/opt/cti-agent\x00")
        r = self.bash(f'layout_relocate_files "{f}" "{b}"', RELOCATED)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = f.read_text()
        for old in ("/opt/cti-agent", "/etc/cti-agent", "/var/lib/cti-agent", "User=ctiagent"):
            self.assertNotIn(old, text)
        self.assertIn("User=fleet", text)
        # systemd's StateDirectory=/LogsDirectory= are /var only: the unit grants the layout's instead.
        self.assertIn("ReadWritePaths=/srv/fleet/state\n", text)
        self.assertIn("ReadWritePaths=/srv/fleet/log\n", text)
        for gone in ("StateDirectory=", "StateDirectoryMode=", "LogsDirectory=", "LogsDirectoryMode="):
            self.assertNotRegex(text, rf"(?m)^{gone}")
        self.assertIn("/srv/fleet/code/bin/run-domains --for-real", text)
        self.assertEqual(b.read_bytes(), b"\x00\x01/opt/cti-agent\x00", "a binary was rewritten")


class Upstream(unittest.TestCase):
    def test_upstream_ships_no_layout(self):
        # A fork's layout.env never conflicts only because upstream has none.
        self.assertFalse((REPO / "layout.env").exists(), "layout.env is a fork's file")


class TheInstallerFollowsTheLayout(unittest.TestCase):
    def setUp(self):
        text = (REPO / "fleet-kit" / "install-fedora.sh").read_text(encoding="utf-8")
        self.code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))

    def test_it_loads_the_layout_instead_of_naming_paths(self):
        self.assertIn('. "$SRC/layout.sh"', self.code)
        self.assertIn('layout_load "$SRC/.."', self.code)
        for var in ("CODE_DIR", "CONF_DIR", "STATE_DIR", "LOG_DIR", "FLEET_USER", "FLEET_GROUP", "AGENT_REPO"):
            with self.subTest(var=var):
                self.assertNotRegex(self.code, rf"(?m)^{var}=", f"{var} is set by layout.sh, not here")

    def test_every_binary_is_stamped_with_it(self):
        for var, val in (("CodeDir", "CODE_DIR"), ("ConfDir", "CONF_DIR"), ("StateDir", "STATE_DIR"),
                         ("LogDir", "LOG_DIR"), ("User", "FLEET_USER")):
            with self.subTest(var=var):
                self.assertIn(f"-X $LAYOUT_PKG.{var}=${val}", self.code)
        self.assertIn("LAYOUT_PKG=github.com/zany2dmax/cti-agent/internal/layout", self.code)

    def test_the_installed_files_are_rewritten_before_they_are_read(self):
        first = self.code.index("relocate_install\nbold \"Audit")
        self.assertLess(self.code.index('bold "Skills"'), first, "the first pass runs after the orchestrator's files")
        self.assertLess(self.code.index("relocate_install\nif [ -n \"${LAYOUT_RELOCATED:-}\" ]"),
                        self.code.index('bold "Verification"'))
        self.assertIn('| layout_relocate > "$3"', self.code, "the composed CLAUDE.md is relocated before its hash")
        for where in ('find "$CODE_DIR"', 'find "$UNIT_DIR"', "/usr/local/sbin /usr/local/bin", 'find "$MAN_DIR"',
                      "/usr/share/bash-completion/completions /usr/share/zsh/site-functions"):
            with self.subTest(where=where):
                self.assertIn(where, self.code)


if __name__ == "__main__":
    unittest.main()
