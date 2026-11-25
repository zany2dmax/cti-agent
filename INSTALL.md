# Installing the fleet

From a clean Fedora machine to `cti-agent-doctor` with no FAIL. Each step
links into [RUNBOOK.md](RUNBOOK.md) where it goes deeper.

The steps, in order:

1. [Prerequisites](#1-prerequisites)
2. [Get the kit](#2-get-the-kit)
3. [Choose where it installs (optional)](#3-choose-where-it-installs-optional)
4. [Run the installer](#4-run-the-installer)
5. [Onboard: lanes, settings, secrets](#5-onboard-lanes-settings-secrets)
6. [Check the settings](#6-check-the-settings)
7. [Claude Code for the check-in](#7-claude-code-for-the-check-in)
8. [First dry runs](#8-first-dry-runs)
9. [Turn on the timers](#9-turn-on-the-timers)
10. [Run the doctor](#10-run-the-doctor)

Then: [updating](#updating) and [when the doctor fails](#when-the-doctor-fails).

Every command that changes something takes `--dry-run` or `--for-real`. With
neither, it prints usage and exits 2. Run `--dry-run` first and read it.

---

## 1. Prerequisites

**The machine.** Fedora, or another RHEL-family system (RHEL, CentOS, Rocky,
Alma). The installer reads `/etc/os-release`, and on any other system asks
before going on. It needs systemd; storing secrets as systemd credentials needs
systemd 254 or later, and the installer warns if the box is older.

**Packages.** The installer checks for `python3`, `git` and `go`, and installs
whichever is missing with `dnf` (`python3`, `git`, `golang`). You need `git`
before you can clone the kit:

```bash
sudo dnf install -y git
```

Go must be at least the version on the `go` line of [go.mod](go.mod)
(1.26 today). Check it once the installer has run, or now if Go is already
installed:

```bash
go version
```

The installer builds from source, so the box needs outbound HTTPS to the
repository it clones.

**Accounts for the lanes you'll run.** Each lane reads from your tools. Get
these ready before onboarding:

- Microsoft Graph: an Entra app registration and a shared mailbox, for every
  lane that reads or sends mail ([RUNBOOK 1](RUNBOOK.md#1-microsoft-entra-app-registration)).
- A vulnerability scanner for exposure ([RUNBOOK 2](RUNBOOK.md#2-qualys-api-access)),
  or `LOOKUP_PROVIDER=none` to skip it.
- An NVD API key ([RUNBOOK 3](RUNBOOK.md#3-the-nvd-api-key)).
- A Claude credential, for the check-in only ([step 7](#7-claude-code-for-the-check-in)).

[docs/lanes.md](docs/lanes.md) lists what each other lane needs.

## 2. Get the kit

Clone the kit to `/root/cti-agent-kit`. That's where `cti-agent-update` and
`cti-agent-doctor` expect it. Clone your organization's fork if you have one:
the box builds from the kit's own `origin`, so a fork's box builds the fork.

```bash
sudo git clone https://github.com/OWNER/REPO.git /root/cti-agent-kit
```

Don't clone it into `/opt/cti-agent` (the installer refuses to run from the
tree it installs into) or into a personal home directory (the next admin
won't find it).

## 3. Choose where it installs (optional)

By default the fleet uses the FHS layout: code in `/opt/cti-agent`, settings
in `/etc/cti-agent`, state in `/var/lib/cti-agent`, the audit trail in
`/var/log/cti-agent`, and a service account named `ctiagent`
([RUNBOOK: Where it lives](RUNBOOK.md#where-it-lives)).

To install elsewhere, commit a `layout.env` at the top of your fork before
installing. [docs/layout.md](docs/layout.md) has the keys and the rules.
Skip this step for the default layout.

## 4. Run the installer

See what it would do:

```bash
sudo /root/cti-agent-kit/fleet-kit/install-fedora.sh --dry-run
```

Then install:

```bash
sudo /root/cti-agent-kit/fleet-kit/install-fedora.sh --for-real
```

It creates the service account, builds every binary, installs the units, man
pages, tab completion and the `cti-agent` wrapper, and verifies what it
installed. On a new box it writes `/etc/cti-agent/fleet.env` from the example,
with empty secrets. It enables no timer.

Read its verification output, not just its exit status. A new box ends with:

```
Installed. No timer is enabled yet - that is deliberate.
    Next: sudo cti-agent-onboard --for-real  (which lanes, their settings, their secrets).
```

If it stops part-way, it says on which line, and that the box is partly
installed. Fix the cause and run it again: it's safe to re-run. More in
[RUNBOOK 8](RUNBOOK.md#8-installing-the-fleet).

## 5. Onboard: lanes, settings, secrets

`cti-agent-onboard` asks three things, in order:

1. **Which lanes this box runs.** The answer becomes `FLEET_LANES`. Leave out
   any lane whose tools you don't have: the installer turns its timer off, and
   the check-in treats it as off, not broken.
2. **Each empty setting those lanes need.** It shows the example's comment
   first. Enter leaves a setting as it is.
3. **Each secret those lanes read that isn't stored yet.** It offers one
   Claude credential for the check-in first. A yes runs
   `cti-agent-secrets set NAME`, which reads the value with no echo and stores
   it as a systemd credential.

The lane names are in `/opt/cti-agent/share/lanes.list`. See what it would
ask, for the lanes you chose:

```bash
sudo cti-agent-onboard --dry-run --lanes checkin,digest,scout
```

Then run it:

```bash
sudo cti-agent-onboard --for-real --lanes checkin,digest,scout
```

**Secrets are typed only into `cti-agent-secrets`.** Never put one on a
command line, in a settings file, or in a chat. Store only the secrets your
lanes use: the list is what the programs could read, so it can name one a
lane needs only with an option on. To store or rotate one later:

```bash
sudo cti-agent-secrets set CLIENT_SECRET
```

Working with Claude Code in your fork? The `/onboard` skill
(`.claude/skills/onboard`) walks you through this. It runs only the read-only
commands, and never asks for a secret.

More in [RUNBOOK 9](RUNBOOK.md#9-enabling-the-timers-in-order) and
`man cti-agent-onboard`. Secrets:
[RUNBOOK 11n](RUNBOOK.md#11n-moving-secrets-into-systemd-credentials).

## 6. Check the settings

Onboard ends with this check. Run it again after any edit:

```bash
sudo cti-agent fleet-config check
```

It reports settings that are required and missing, misspelt, set twice or in
the wrong file. It never prints a value. Fix each one it names, in the file it
names. A new box keeps every setting in `fleet.env`; splitting it into one
file per lane is optional ([RUNBOOK 11o](RUNBOOK.md#11o-settings-per-lane)).
What each setting means: [RUNBOOK 11m](RUNBOOK.md#11m-what-is-in-fleetenv).

## 7. Claude Code for the check-in

Only the check-in calls Claude. Skip this step if `FLEET_LANES` leaves out
`checkin`.

**Install Claude Code system-wide**, from the signed dnf repository. The
check-in refuses a copy in the service account's own home, which the account
could replace. Add the repository:

```bash
sudo tee /etc/yum.repos.d/claude-code.repo <<'REPO'
[claude-code]
name=Claude Code
baseurl=https://downloads.claude.ai/claude-code/rpm/stable
enabled=1
gpgcheck=1
gpgkey=https://downloads.claude.ai/keys/claude-code.asc
REPO
```

Then install it:

```bash
sudo dnf install claude-code
```

**Store one credential**: `ANTHROPIC_API_KEY` (a Console API key) or
`CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`, run on a machine where
you're already logged in). Onboard offers this. To do it by hand:

```bash
sudo cti-agent-secrets set ANTHROPIC_API_KEY
```

Store exactly one: the check-in refuses to start when more than one is set.

## 8. First dry runs

Nothing here sends, moves or files anything.

Confirm Graph can see the mailbox, and which permissions it has:

```bash
sudo cti-agent cti-mailer --check
```

Rehearse the daily digest:

```bash
sudo cti-agent run-digest daily --dry-run
```

The first run downloads the scanner's knowledge base, which takes several
minutes.

Run the check-in's checks, without a beat:

```bash
sudo cti-agent run-checkin --dry-run
```

Run every lane's credential check once, so the doctor has a report to read:

```bash
sudo cti-agent run-credcheck
```

```bash
sudo cat /var/lib/cti-agent/reports/credcheck.txt
```

For each other lane you chose, run its runner with `--dry-run` (the programs
column of `lanes.list`), for example:

```bash
sudo cti-agent run-vmscan --dry-run
```

## 9. Turn on the timers

One lane at a time, each after its gate. The order and the gate for every
timer are in [RUNBOOK 9: Every timer, and its gate](RUNBOOK.md#every-timer-and-its-gate),
and the steps for a new box are in
[On a new deployment](RUNBOOK.md#on-a-new-deployment-the-steps-after-the-installer).
Start with the digest alone:

```bash
sudo systemctl enable --now cti-agent-digest.timer
```

See every fleet timer, including the ones that are off. It ends with the
lanes that are off on purpose:

```bash
sudo cti-agent fleet-timers --all
```

## 10. Run the doctor

```bash
sudo cti-agent-doctor
```

It prints one line per check (version, settings, units, timers, credentials,
org pack, beat files), each OK, WARN or FAIL, and changes nothing. It exits
0 when nothing FAILs. While you're still turning lanes on, `timers` is WARN;
it's OK once every timer of the lanes in `FLEET_LANES` is enabled. The
Patch Tuesday timer is off on purpose and doesn't count against it.

The box is installed when the doctor shows no FAIL.

---

## Updating

Updates come from the kit's own `origin`: upstream for a plain clone, your
fork for a fork. See what's coming:

```bash
sudo cti-agent-update --dry-run
```

It prints the version now, the version available and the incoming commits.
Nothing is pulled. Read the kit's `CHANGELOG.md` for every version in between:
it says when a setting moves, a timer is added, or the box needs a command run
once.

Then update:

```bash
sudo cti-agent-update --for-real
```

In order, it:

1. takes a snapshot in `/var/lib/cti-agent-update/` (root only, the last three
   kept): the code, the settings, the fleet's units, the kit's and the Go
   source's commits, and a copy of `memory.db`
2. fast-forwards the kit and runs the installer from it
3. if the installer fails, puts the whole snapshot back, database included,
   and exits with the installer's status
4. ends with `cti-agent-doctor`

**If a good install misbehaves later**, put the last snapshot back. Look
first:

```bash
sudo cti-agent-update --rollback --dry-run
```

```bash
sudo cti-agent-update --rollback --for-real
```

It refuses while a lane is running. It leaves `memory.db` as it is, because
the lanes have written to it since; it names the snapshot's copy.

**If the fetch refuses a tag** ("would clobber existing tag"), the updater
prints the fix and runs nothing. Run exactly what it printed. Why a tag should
never move: [RUNBOOK 11i](RUNBOOK.md#a-pushed-tag-never-moves).

The `/update-fleet` Claude Code skill (`.claude/skills/update-fleet`) walks
through an update with you. See also `man cti-agent-update` and
[RUNBOOK 11d](RUNBOOK.md#11d-what-version-is-this-box-running).

## When the doctor fails

Each line says what to do. The usual fixes:

| Check | What it means | What to do |
|---|---|---|
| `version` FAIL | no `/etc/cti-agent/version`: the installer didn't finish | run the installer again ([step 4](#4-run-the-installer)) |
| `version` WARN | the kit is ahead of the install | `sudo cti-agent-update --for-real` |
| `settings` FAIL | `fleet-config check` found a problem | `sudo cti-agent fleet-config check` names each setting |
| `units` FAIL | a fleet unit failed | read its journal: `sudo cti-agent fleet-journal -u UNIT -n 50 --no-pager` |
| `timers` WARN | a lane in `FLEET_LANES` has its timer off | turn it on ([step 9](#9-turn-on-the-timers)), or run onboard again without that lane, then update |
| `credentials` WARN | no report yet, or it's more than 26 hours old | `sudo cti-agent run-credcheck`; check that `cti-agent-credcheck.timer` is on |
| `credentials` FAIL | a login failed; the line names the lane and the command | run that command's `--check` by hand; store a new secret with `sudo cti-agent-secrets set NAME` |
| `org pack` FAIL | the org pack failed its checks: not root-owned, writable by others, or a file it doesn't know; or there are two, a fork's `org/` in the kit and `/etc/cti-agent/org` | fix what the line names ([docs/org-pack.md](docs/org-pack.md)) |
| `beat files` FAIL | the orchestrator's files failed the check-in's own audit | run the installer again, then `sudo cti-agent run-checkin --dry-run` |

For machine-readable output:

```bash
sudo cti-agent-doctor --json
```

A command that works by hand while every timer fails is usually SELinux. That
case and others: [RUNBOOK 15](RUNBOOK.md#15-when-something-breaks).
