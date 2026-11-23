# What's new in CR Agent Fleet 2.0-rc1

**Release candidate 1 for 2.0 | November 2026 | Covers everything since 1.7.2**

CR Agent Fleet 2.0 changes **where the fleet keeps what it knows**. Secrets leave the settings file for encrypted systemd credentials, and each scheduled job is given only the ones it uses. Settings split into one file per lane. And the fleet's runtime is now Go and shell from end to end: every lane, runner and analyst step that was Python has been rewritten and held to the Python's own output before it was deleted.

This is a **release candidate**. It runs for a week on the box before 2.0 final, so anything the rewrite or the move left behind shows up while there's still a way back.

**Highlights**

- **Secrets in systemd credentials.** Encrypted to the machine (TPM-bound where present), granted per job, never printed, and never inherited by a program that doesn't need them.
- **Settings per lane.** `fleet.env` splits into a shared core file and one plain file per lane, so a lane no longer sees another lane's recipients or switches.
- **No Python in the runtime.** About 4,900 lines of Python retired: the mailer, the scout, enrich and brief lanes, the analyst's command guard, its trace recorder and its output cleaner. Each Go version was proven byte for byte against what the Python wrote.
- **The Weekly Brief gets FLEET ADVISORIES**, a roll-up of the week's advisory triage, so a reader of the Monday brief alone still sees a Wednesday sighting.
- **Standard *IX throughout.** Every path the fleet uses is a standard one, and the installer, the runbook and the kit README all list them.

**Upgrading:** run `sudo cti-agent-update --for-real`. **Nothing is required for this candidate.** 2.0 final will require the secrets move and the settings split, so do both during the candidate's week; see [During the candidate week](#during-the-candidate-week).

---

## Why 2.0

The fleet's version rule is simple: a major version means **the fleet will not work correctly until you act**. This candidate doesn't meet that test. A box that keeps everything in `fleet.env` still works, because every program reads a credential first and falls back to `fleet.env`.

**2.0 final removes that fallback.** From then on a secret must be a systemd credential, systemd 254 or later is required, and a box that never imported its secrets would stop sending mail and stop reaching every API. That is the 2.0 change. This candidate is the week to make the move with the fallback still there.

---

## Secrets as systemd credentials

Until now every secret lived in one file, `/etc/cti-agent/fleet.env`, and every scheduled job's environment held every one of them. The domains check could see the CrowdStrike key, and a program started by any lane inherited the lot.

### How it works

1. **`cti-agent-secrets import`** reads each secret from `fleet.env` and encrypts it to the machine with `systemd-creds`, into `/etc/credstore.encrypted/`. Values travel on stdin, never on a command line, and are never printed.
2. **Each unit is granted only what its programs read.** The grants are generated from the code (`ImportCredential=` lines in each unit), so they can't drift from what the programs actually use.
3. **systemd decrypts a job's credentials for that run only**, into a private directory that disappears when the run ends.
4. **Programs read the credential first.** A runner drops the `fleet.env` copy of any secret it has as a credential, so the programs it starts no longer inherit it. Only the model call gets the model token, in its own subshell.

**The logins move with their secrets.** A password is no use without its username, and a username tells an attacker where to aim. So the client IDs, usernames and API hosts (Microsoft tenant and app, Qualys, Jira, CrowdStrike, the Qualys pod) are credentials too. A lane that doesn't use a system sees none of its login.

### Hand runs get the same grants

`sudo cti-agent CMD` now runs as a short-lived systemd unit (`systemd-run`) with the same credentials its timer would get, and no others. The journal shows each one as `cti-manual-*`, with who ran it. Ctrl-C stops the unit.

### The new root tool: `cti-agent-secrets`

| Command | What it does |
|------|----------|
| `sudo cti-agent-secrets status` | Which secrets and logins are stored, which are still in the settings file, and which aren't set anywhere. Names only. |
| `sudo cti-agent-secrets import --dry-run` | What an import would store, by name. |
| `sudo cti-agent-secrets import` | Stores every secret and login found in `fleet.env`. |
| `sudo cti-agent-secrets set NAME` | Stores or rotates one, typed at a prompt that doesn't echo, or piped in. |
| `sudo cti-agent-secrets remove NAME` | Removes one. |

It has a man page and bash and zsh tab completion, like every other command.

---

## Settings per lane

With the secrets gone, `fleet.env` holds only ordinary settings: recipients, allowlists, paths, schedules and switches. Every job still loaded all of them. 2.0 splits them:

```
/etc/cti-agent/fleet.d/00-core.env     what several lanes read
/etc/cti-agent/fleet.d/<lane>.env      what only that lane reads
```

Each job loads core and its own file. The check-in loads every file, because its job is to check every lane. A hand run of a lane's runner loads exactly that lane's files.

**Which file a setting goes in is generated from the code**, not chosen by hand. A setting stays in its lane's file only if no program outside that lane could read it; otherwise it goes to core, and the manifest says why.

### The new root tool: `cti-agent-settings`

- `sudo cti-agent-settings split --dry-run` shows which setting goes to which file, by name only.
- `sudo cti-agent-settings split --for-real` writes the files, keeping every line and the comments above it, and moves `fleet.env` aside (root-only) so you can go back.

It refuses to split while a secret or login is still in `fleet.env`, when a setting would use `$NAME` from another lane's file (that lane would never load it, and the value would be empty), or when it can't tell where a quoted value ends. It never guesses.

### Know what you've set: `fleet-config`

`sudo cti-agent fleet-config check` reads every settings file and reports:

- required settings that are missing;
- settings no code reads, with the nearest real name in case it's a typo;
- settings set twice, and lines that aren't settings;
- settings equal to their default, which can go;
- every secret still in a settings file;
- after a split, a setting in the wrong lane's file, and a `$NAME` its lane doesn't load.

It never prints a value. It knows about 167 settings, from a manifest generated from the code and kept in step by a test.

---

## No Python in the runtime

1.7 ran its lanes as a mix of Go, shell and Python. In 2.0 no lane, no runner and nothing the analyst runs is Python. Python is left only for the SQLite tools (`fleet-db`, `fleet-owners`) and tools a person runs by hand.

| Retired | Replaced by | Proven against the Python by |
|-----|-----|-----------|
| `mailer.py` | `cti-mailer` (since 1.6.6) | the mailer's own test suite |
| `enrich.py` | `cti-enrich` | 4 whole runs, 4,064 scoring cases, 39 scanner titles, 22 product lookups |
| `brief.py` | `cti-brief` | 22 digests and 9 command lines, byte for byte |
| `scout.py` | `cti-scout` | 49 dates, 17 feed bodies (including an entity bomb and malformed XML), 42 escapes, 25 CVE strings, 5 whole runs |
| `checkin-bash-guard` | the same name, in Go | the same verdict on 279 calls and 9 counter sequences |
| `fleet-trace` | the same name, in Go | byte-identical traces |
| `fleet-sanitize` | `cti-sanitize` | the shared test cases, and now one implementation instead of two |

Before each Python program was deleted, it was run on fixed inputs to write golden files, and the Go tests are held to them. The handful of differences are listed in the CHANGELOG, and every one is deliberate: files written 0600 and atomically, a malformed input stopped with a message instead of a traceback, and so on.

The runners lost their inline Python too. The lane lock is now `cti-lock`, the check-in's start-up checks are `cti-checkin-check`, and the counts and request IDs the digest records come from the Go commands themselves. A test fails if Python comes back into any runner.

**Why it matters:** one language for the runtime means one set of tests, one HTTP client with the TLS floor, one JSON writer, and no interpreter for an attacker to reach from a lane.

---

## The Weekly Brief: FLEET ADVISORIES

Advisory triage, new in 1.7, only reached the Daily Brief. The weekly reads no mail and runs no model, so it had nothing to show, and a sighting on Wednesday never reached someone who reads only the Monday brief.

The weekly now rolls up the dailies' triage reports for the week up to yesterday:

- anything seen on our hosts, first;
- then everything judged likely or possible, each with the day it arrived;
- one line counting the rest;
- the days with no triage report, so a silent failure doesn't pass for a quiet week;
- the week's model cost, which is what the dailies spent. The weekly itself calls no model.

A dry run of the weekly reads the real reports, so its preview matches what the weekly will send.

---

## Standard *IX, everywhere

The fleet follows standard Linux naming, locations and configuration wherever it can, and now says so:

| What | Where |
|----|-----|
| Code | `/opt/cti-agent` |
| Settings | `/etc/cti-agent/fleet.env`, or `/etc/cti-agent/fleet.d/` once split |
| Secrets | `/etc/credstore.encrypted/` (systemd credentials) |
| State | `/var/lib/cti-agent` |
| Logs | the systemd journal, and the audit trail in `/var/log/cti-agent` |
| Units and timers | `/etc/systemd/system/cti-agent-*` |
| Commands | `/usr/local/bin/cti-agent`; root tools in `/usr/local/sbin` |
| Man pages | `/usr/local/share/man/man1` (`man -k cti`) |
| Tab completion | the standard bash and zsh completion folders |
| Service account | `ctiagent`, a system account with no login shell |

The installer prints this list on every run, along with each location's SELinux type, and nothing needs a custom SELinux policy. The runbook opens with the same table, and a test keeps the three lists in step.

---

## Fixes

- **A hold alert no longer says a lane stopped when it didn't.** When one application owner's report was held back, the email read "on hold ... stopped itself ... will resume", although every other report had gone out. It now says the run finished with items held back, leads with how many reports were sent, and says the held one isn't retried. The weekly AppSec failed-login alert gets the same wording.
- **Advisory triage no longer reads Qualys scan notices.** They're full of host names and IPs, so they passed the threat-intel check and cost a model call each to find nothing.
- **An email subject with a `|` in it is listed whole** in the digest's list of emails read.
- **Five programs stopped being granted a Qualys setting they never read**, caught by the same code scan that builds the credential grants.
- **Release candidates are first-class.** A tag like `2.0-rc1` gets a GitHub release marked Pre-release, and it never takes the Latest badge from the last final release.

---

## During the candidate week

**1. Update.**

```bash
sudo cti-agent-update --for-real
```

**2. Move the secrets and logins into credentials** (runbook section 11n). Needs systemd 254 or later; the installer says if the box is older.

```bash
sudo cti-agent-secrets import --dry-run
```
```bash
sudo cti-agent-secrets import
```

Run each lane's dry run, and the integration checks (`cti-mailer --check`, `cti-jira --check`, `cti-vmscan --check`, `cti-falcon --check`). Then delete the secret and login lines from `fleet.env` and run them again. Now nothing can fall back, so a pass means each one comes from its credential.

**3. Split the settings per lane** (runbook section 11o).

```bash
sudo cti-agent-settings split --dry-run
```
```bash
sudo cti-agent-settings split --for-real
```
```bash
sudo cti-agent fleet-config check
```

**4. Let every timer run once**, including the Monday weekly, and watch for anything missing.

**If something breaks:** put the one line back in `fleet.env` and report which check failed. While this is a candidate, `fleet.env` still works as a fallback. The split tool prints the exact commands to undo a split.

---

## What 2.0 final will add

- **No fallback for secrets.** A secret must be a systemd credential.
- **The installer refuses to upgrade a box that isn't ready**: systemd older than 254, or a needed credential not stored.
- **`fleet-config check` fails** on any secret still in a settings file.

Full detail, including every behaviour difference in the Go ports, is in the CHANGELOG under 2.0-rc1.
