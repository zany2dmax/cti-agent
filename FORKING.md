# Forking the fleet

How to make the fleet your organization's without editing the core, so every
upstream release merges cleanly. Install the box with [INSTALL.md](INSTALL.md);
this guide is about the fork you install it from.

- [The trust boundary](#the-trust-boundary)
- [What a fork changes, and what it never edits](#what-a-fork-changes-and-what-it-never-edits)
- [The org pack](#the-org-pack)
- [Choosing lanes](#choosing-lanes)
- [Turning off add-on vendors](#turning-off-add-on-vendors)
- [Vendor settings](#vendor-settings)
- [Installing somewhere else](#installing-somewhere-else)
- [Adding a vendor](#adding-a-vendor)
- [Adding a lane](#adding-a-lane)
- [Pulling from upstream](#pulling-from-upstream)
- [Releases in a fork](#releases-in-a-fork)
- [Checklist for a new fork](#checklist-for-a-new-fork)

---

## The trust boundary

**One fleet per organization, on its own box.** A fleet holds one
organization's mail, scanner and ticketing credentials, and one check-in
agent reads that organization's untrusted mail. Everyone who can administer
the box can see everything the fleet can.

Running several organizations from one box, one install or one set of
credentials is not supported. Give each organization its own fork, or at
least its own box. Why the boundaries are where they are:
[SECURITY.md: Trust boundaries](SECURITY.md#trust-boundaries).

## What a fork changes, and what it never edits

A fork adds files. It changes core only at the few lines a new vendor or lane
needs, and records each one in its recipe ([below](#the-org-pack)). Everything
else has a place made for it:

| You want to change | Where it goes | Never edit |
|---|---|---|
| Your name, recipients, mailbox, Jira project, schedules | settings on the box (`fleet.env` or `fleet.d/`), through `cti-agent-onboard` | a default in code |
| How the check-in or an agent should behave for you | the org pack: `org/orchestrator.md`, `org/agents/<agent>.md` | `fleet-kit/fleet/CLAUDE.md`, `fleet-kit/fleet/agents/*/CLAUDE.md` |
| An extra skill for the check-in | the org pack: `org/skills/<name>/SKILL.md` | `fleet-kit/fleet/skills/` |
| A lane's unit: command, timeout, description | its manifest, `fleet-kit/lanes/<lane>.toml`, then `task lane:write` (a core lane's manifest is still core: note it in the recipe) | `fleet-kit/fleet/systemd-fedora/*.service` |
| Which lanes the box runs | `FLEET_LANES` on the box | the installer's timer list |
| Where the fleet installs | `layout.env` at the top of the fork | paths in the units, runners or Go code |
| A new tool for an existing job | a new package and one selection line ([below](#adding-a-vendor)) | the other vendors' packages |
| A new recurring job | a new lane ([below](#adding-a-lane)) | another lane's runner |
| A bug in core | a fix sent upstream ([CONTRIBUTING.md](CONTRIBUTING.md)) | a private patch you then carry forever |

**Generated files** are rewritten by `task lane:write` and checked by
`task ship`, so a hand edit is lost or refused. Change the manifest instead.
They are:

- every `.service` unit in `fleet-kit/fleet/systemd-fedora/`
- the lane table in `fleet-kit/fleet/CLAUDE.md`, between its markers
- `internal/checkin/lanes_gen.go`
- `fleet-kit/fleet/lanes.list` and `fleet-kit/fleet/lane-settings.list`
- `fleet-kit/fleet/fleet.d.example/`
- the generated fields of `fleet-kit/fleet/settings.manifest`
- [docs/lanes.md](docs/lanes.md)

**Never edit the installed files on the box** either. An edit to
`/opt/cti-agent/orchestrator/CLAUDE.md` stops the installer from updating it
on every later install. Put the edit in the org pack.

Keep the Go module path as it is. Renaming it touches every import and
conflicts with every upstream release.

## The org pack

The org pack is what your organization adds to the fleet's prompts: notes for
the orchestrator and the three agents, and extra skills. In a fork it's the
`org/` folder at the top of the repository. Upstream never has an `org/`
folder, so it never conflicts with a pull.

Start from the example:

```bash
cp -R examples/org-pack org
```

The installer adds each file after the core text under
"Organization notes", on every install and update. A pack only adds: the
core text wins where the two disagree, and a pack can't replace a core skill.

**`org/recipe.md`** is your fork's list of what it added to the core, one line
each, with the commit: a provider package, a lane, a setting. It isn't
installed. It's for whoever pulls from upstream next, as the list of things to
check still work. The `/add-provider` and `/add-lane` skills append to it.

Check the pack before you commit it:

```bash
fleet-kit/bin/org-pack check org fleet-kit/fleet
```

On the box the installer refuses a pack that isn't root-owned, is writable by
others, holds a symlink or a file it doesn't know, or reuses a core skill's
name. A fork's pack and `/etc/cti-agent/org/` at once is refused too. The
layout and every rule: [docs/org-pack.md](docs/org-pack.md) and
[RUNBOOK 11p](docs/guides/configuration.md#11p-the-org-pack).

### Gaps by design

Each lane reports what it didn't cover: a web app nobody scanned, a domain
the weekly check couldn't reach. The check-in escalates every such gap,
unless your org pack's `expected-gaps.txt` says it's on purpose, with a
reason (and, if it should lapse, an `until=` date):

```
appscan | Example Staging | not_scanned | a copy of production, scanned on demand only
```

That's the fork's record of the risks it accepted. Commit it in `org/` with
the rest of the pack. [docs/org-pack.md](docs/org-pack.md#expected-gapstxt-gaps-by-design)
has the format.

## Choosing lanes

Run only the lanes you have tools for. On the box, `FLEET_LANES` lists them,
comma-separated, by the names in `fleet-kit/fleet/lanes.list`. Unset means
every lane. `cti-agent-onboard` sets it.

For each lane left out:

- the installer turns its timer off, and stops if a name isn't a lane
- `fleet-config check` stops requiring its settings
- `fleet-timers` lists it as off on purpose
- the check-in treats it as off, not broken, and skips its credential checks

What each lane needs is in [docs/lanes.md](docs/lanes.md). In short:

- `digest`, `scout`, `mailbox` and `checkin` need Microsoft Graph, a scanner
  for exposure (or `LOOKUP_PROVIDER=none`), and, for the check-in, a Claude
  credential.
- `appscan` and `appowners` need a web app scanner.
- `vmscan` needs Qualys VM and a network spreadsheet in SharePoint.
- `domains` needs a domain list in `/etc/cti-agent/domains.txt`.
- `supplier` needs a supplier mailbox and a Jira board.

To drop a lane later, run onboard again without it, then
`sudo cti-agent-update --for-real`, which turns its timer off.

## Turning off add-on vendors

Some lanes use an add-on vendor that a fleet may not have. Each has an off
switch, and with it off the lane runs cleanly and the check-in doesn't
escalate:

| Vendor | Setting | Off |
|---|---|---|
| The domain registrar (GoDaddy) | `DOMAINS_REGISTRAR` | `none`: the report says no registrar is configured, and `--check` passes |
| The mail gateway (Proofpoint on Demand) | `DOMAINS_MAIL_GATEWAY` | unset or `off` (the default) |
| Advisory triage (CrowdStrike Falcon and a model) | `TRIAGE_ENABLED` | unset (the default) |
| The CVE exposure lookup (Qualys) | `LOOKUP_PROVIDER` | `none`: every CVE reports UNKNOWN |

An unknown value stops the run rather than being read as off.

## Vendor settings

How your organization set up a vendor is a setting, not a code change. Each
defaults to what the fleet did before:

| Setting | File | What it's for |
|---|---|---|
| `QUALYS_PORTAL_HOSTS` | `00-core.env` | Further Qualys UI hosts to trust in report links. The UI host of the pod in `QUALYS_BASE_URL` is trusted already, so most platforms need nothing. |
| `VMSCAN_USER_OCTET` | `vmscan.env` | The third octet that marks a location's user network in the network sheet. Default `30`; `off` counts only rows labelled corp. |
| `VMSCAN_EXTRA_LABELS` | `vmscan.env` | Row labels your sheet uses beyond the built-in ones, comma-separated. |
| `VMSCAN_GAP_TEAMS` | `vmscan.env` | Who the VM scan report asks why a network isn't scanned. Default: the network team. |
| `JIRA_CLOSE_RESOLUTION` | `00-core.env` | The resolution set when Jira's close screen asks for one. Default `Done`. |

The file is where the setting goes once settings are split per lane
([RUNBOOK 11o](docs/guides/configuration.md#11o-settings-per-lane)); before that, everything is
in `fleet.env`. Each setting's comment is in
`fleet-kit/fleet/fleet.d.example/`.

## Installing somewhere else

The default layout is the FHS one: `/opt/cti-agent`, `/etc/cti-agent`,
`/var/lib/cti-agent`, `/var/log/cti-agent`, and the account `ctiagent`. To
change any of them, commit a `layout.env` at the top of the fork. Every key is
optional:

```
LAYOUT_CODE_DIR=/srv/fleet/code
LAYOUT_CONF_DIR=/srv/fleet/etc
LAYOUT_STATE_DIR=/srv/fleet/state
LAYOUT_LOG_DIR=/srv/fleet/log
LAYOUT_USER=fleet
```

Commit it like any other file (`.gitignore` ignores every other `*.env`,
but not this one):

```bash
git add layout.env
```

The installer and the updater read it, and refuse a bad value before changing
anything. Upstream never ships a `layout.env`, so it never conflicts.

**The box builds the fork.** The installer clones the Go source from the
kit's own `origin`, so a box installed from your fork builds your fork's code.
`LAYOUT_REPO` names another repository, if you need one. Rules and caveats,
including SELinux labels for moved paths: [docs/layout.md](docs/layout.md).

## Adding a vendor

To support a tool the fleet doesn't yet, put it behind the interface for that
job: a CVE lookup provider, a web app scanner, a registrar or a mail gateway.
That's one new package plus one line in the interface's one selection point.
[INTERFACES.md section 5](INTERFACES.md#5-how-to-put-a-new-tool-behind-an-interface)
has the contract.

In Claude Code, in your fork, the `/add-provider` skill walks through it: the
package, the selection line, settings, tests against a fake server, a probe
flag for the first live run, docs, and the recipe line. The registry tests
fail, naming the package, until the selection line is in.

If no interface fits the tool, don't add one in the fork. That's a design
change; raise it upstream.

## Adding a lane

A lane is one manifest, `fleet-kit/lanes/<lane>.toml`, plus its command, its
runner and its timer. The schema and what's generated from it:
[docs/lane-manifest.md](docs/lane-manifest.md).

In Claude Code, in your fork, the `/add-lane` skill walks through it, including
the parts no generator writes: the guard's handle list, the orchestrator's
notes, the check-in skill's row, and RUNBOOK section 9. Those are core files,
so each is a place a later upstream pull can conflict. The skill records the
lane in `org/recipe.md`.

Regenerate after any manifest change:

```bash
task lane:write
```

Then run every gate:

```bash
task ship
```

On the box: add the lane to `FLEET_LANES` if that's set, run
`sudo cti-agent-onboard --dry-run` for its settings and secrets, run the lane
by hand with `--dry-run`, and only then enable its timer
([RUNBOOK 9](docs/guides/setup.md#every-timer-and-its-gate)).

## Pulling from upstream

Once, in your fork's checkout, name the repository you forked from:

```bash
git remote add upstream https://github.com/UPSTREAM-OWNER/REPO.git
```

For each upstream release, fetch it:

```bash
git fetch upstream --tags
```

Merge the release tag, not `main`, unless you want unreleased work. For
example:

```bash
git merge 2.0-rc4
```

Conflicts can only come from core files your fork changed: the selection lines
and lane notes listed in `org/recipe.md`. Your own files never conflict,
because upstream doesn't have them:

- `org/`, the org pack and its recipe
- `layout.env`
- your providers' packages and your lanes' manifests

Read the release's section of `CHANGELOG.md` for settings that moved and
steps the box needs. Then regenerate, and check every item in
`org/recipe.md` still builds and passes:

```bash
task lane:write
```

```bash
task ship
```

`task ship` runs every gate and pushes. Then update the box, which pulls from
your fork:

```bash
sudo cti-agent-update --dry-run
```

```bash
sudo cti-agent-update --for-real
```

The `/update-fleet` Claude Code skill covers both halves: the fork, then the
box.

## Releases in a fork

**A pushed tag never moves.** The box's updater fetches tags, and a tag that
moved under it stops the update. If a pushed tag is wrong, cut the next
version instead. [RUNBOOK 11i](docs/guides/development.md#a-pushed-tag-never-moves) gives the
one `gh api` command that makes GitHub refuse to move or delete a tag. Your
fork's owner runs it once, for the fork.

The box stamps its version from the nearest tag in the kit, so a fork that
merges upstream's release tags reports upstream's version. To tag a release of
your own, follow [RUNBOOK 11i's steps](docs/guides/development.md#the-steps): `task ship`
checks that the latest tag's commit has its CHANGELOG section. Pick a name
upstream won't use, so `git fetch upstream --tags` never meets a clash. Those
steps edit `CHANGELOG.md` and `CHEATSHEET.md`, which upstream changes too, so
expect a conflict there on the next pull.

Upstream's GitHub Release workflow (`.github/workflows/release.yml`) runs only
in upstream's repository. In a fork, a tag is still a release to the box; it
just gets no Releases page.

## Checklist for a new fork

1. Fork the repository. Keep the Go module path.
2. Add the upstream remote ([above](#pulling-from-upstream)).
3. Copy `examples/org-pack` to `org/`, replace the notes with yours, and start
   `org/recipe.md`.
4. If you install outside the FHS paths, commit a `layout.env`
   (`git add -f`).
5. Create the tag ruleset for the fork ([RUNBOOK 11i](docs/guides/development.md#a-pushed-tag-never-moves)).
6. Install a box from the fork ([INSTALL.md](INSTALL.md)), choosing only the
   lanes you have tools for.
7. Turn off the add-on vendors you don't have, and set the vendor settings
   that differ for you.
8. Add vendors and lanes with `/add-provider` and `/add-lane`, never by
   editing another vendor or lane.
9. Run `sudo cti-agent-doctor` on the box: no FAIL.
