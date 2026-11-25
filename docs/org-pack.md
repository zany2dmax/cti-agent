# The org pack: one organization's notes, kept out of the core

The fleet's prompts and skills are written for any organization. What one
organization adds to them goes in its **org pack**: a small folder of notes
and extra skills that the installer adds to the core files on every install
and update.

Keeping those notes in the pack, and not in edits to the installed files,
means:

- **An update never overwrites them**, and never has to stop to ask.
- **Pulling upstream never conflicts with them**, because a fork's changes
  are in its own folder, not in core files.
- **The core rules still apply.** A pack can add to the instructions; it
  cannot remove or replace one.

## What goes where

| Kind of thing | Where it lives | Examples |
|---|---|---|
| Who you are and where things are | `fleet.env` settings | `FLEET_ORG`, `FLEET_ATTRIBUTION`, every `*_TO` recipient list, mailbox, Jira project, `SUPPLIER_BOARD_NAME`, `SUPPLIER_TPRM`, `VMSCAN_GAP_TEAMS` |
| What you run and what you have | `fleet.env` settings, `feeds.txt`, the domain and site files | vendor URLs, asset groups, feeds |
| How your organization wants things done | **the org pack** | your escalation habits, who owns what, what matters most this quarter, house terms, extra criteria for supplier requests |
| How the fleet works | **core** (this repository) | the lanes, the grant, the hard rules, the bash guard, report layout |

If a note would be true for every organization, it belongs in core: send it
upstream. If it is only true for yours, it belongs in the pack.

### The inventory behind this split (2026-11-24)

Before the pack existed, this is what in core was about one organization
rather than the fleet:

- **Recipients, the org's name, the attribution line, the supplier board and
  the third-party-risk wording** were settings already, with neutral
  defaults. Nothing to move.
- **The prompts** (the orchestrator's `CLAUDE.md`, the four skills, and the
  supplier, triage-reader and triage-judge prompts) are written for any
  organization. What an organization wants to add to them now goes in the
  pack. Before the pack, the only way was to edit the installed
  `CLAUDE.md`, which froze it against every later update.
- **The VM scan report** named "the network and M&A teams" as the people
  asked about unscanned networks. That's one organization's process, so it is
  now the setting `VMSCAN_GAP_TEAMS` (default: the network team).
- Generic roles named in report text (the security team, the network team,
  the help desk) are the fleet's audience, not one organization's, and stay
  in core.

## The layout

```
org/                         (or /etc/cti-agent/org/ on a box)
  README.md                  for people; not installed
  recipe.md                  what this fork added to the core, one line each; not installed
  expected-gaps.txt          the gaps this organization chose (lane health); installed for the lanes
  orchestrator.md            added after the orchestrator's CLAUDE.md
  agents/supplier.md         added after agents/supplier/CLAUDE.md
  agents/triage-reader.md    added after agents/triage-reader/CLAUDE.md
  agents/triage-judge.md     added after agents/triage-judge/CLAUDE.md
  skills/<name>/SKILL.md     an extra skill for the orchestrator
```

Every file is optional. An empty pack, or no pack, installs the core files
unchanged.

Each added file appears after the core text under the heading
`## Organization notes`, with one line saying the notes add to the
instructions above and never override them: where the two disagree, the core
text wins. An org skill is installed beside the core skills. The beat starts
with `/checkin` only, so mention an org skill in `orchestrator.md` if the beat
should use it.

`examples/org-pack/` is a sanitized example of each file.

### expected-gaps.txt: gaps by design

Each lane's health report ([lane-manifest.md](lane-manifest.md#the-health-contract))
lists what the lane didn't cover. This file is where the organization says
which of those gaps it chose, and why:

```
lane | subject | kind | reason | until=YYYY-MM-DD
appscan | Example Staging | not_scanned | a copy of production, scanned on demand before each release
appscan | id:100000001 | * | retired; kept in the scanner for its history | until=2027-03-31
```

- **The subject** is the name the lane reports, or `id:<ID>` for a source id.
  Prefer `id:` where the lane has one (a web app's id): a name can be given to
  a second subject, and a name declaration that matches two subjects covers
  neither.
- **The kind** is one of the lane's gap kinds (its manifest's `[health]
  kinds`), or `*` for any.
- **A gap a line covers is "by design",** with the reason, and the check-in
  never escalates it. Every other gap is an accident until somebody adds a
  line.
- **Every line needs a reason.** An `until=` date makes the exception lapse:
  after it, the gap is an accident again, and the check-in gets a reminder a
  week before.
- **A line that matches nothing is reported too,** so a stale exception
  doesn't linger.

It's in the pack, not on the box, because declaring a gap is accepting a
risk. In a fork, the file's git history records who accepted which risk and
when. `org-pack check` refuses a malformed line before anything is
installed, and the installer puts the file, root-owned, in
`/opt/cti-agent/share/expected-gaps.txt`, so no lane can declare its own gaps
expected. Only the lanes read it, never the model.

## Where it lives

- **A fork:** commit the pack as `org/` at the top of the repository. The
  installer runs from the checkout and finds it there.
- **A box installed from an upstream clone** (no fork): keep the pack in
  `/etc/cti-agent/org/`.

Both at once is refused, because there would be two answers to which notes
apply. Upstream never has an `org/` folder, so a fork's never conflicts.

`--purge` removes `/etc/cti-agent`, which includes a pack kept there. Keep a
copy, or keep it in a fork.

## The rules, and why

The pack steers the beat, the process that reads untrusted mail, so the
installer holds it to the same rules as the installed prompts. It checks the
pack before installing anything (`fleet-kit/bin/org-pack check`), and refuses
the install if any of these fails:

- **Root-owned, and writable by nobody else.** Every file and folder in it
  must be owned by root and not group- or world-writable. Otherwise the
  service account, or anyone in its group, could rewrite what the beat is
  told.
- **No symlinks.** A link could point the installer at a file outside the
  pack.
- **Only the files above.** A misspelt name (`agent/supplier.md`,
  `orchestrator.txt`) is refused by name rather than silently ignored.
- **An agent file names a core agent**, and **a skill never reuses a core
  skill's name.** A pack adds; it does not replace.
- **Each file is at most 64 KB.**

A skill the pack no longer has is removed from the box on the next install,
so the skills folder holds only the core skills and the pack's.

## Moving existing edits into the pack

If you edited the installed `/opt/cti-agent/orchestrator/CLAUDE.md`, the
installer stops updating it and says so on every install. To move the edits:

```bash
sudo diff -u /root/cti-agent-kit/fleet-kit/fleet/CLAUDE.md /opt/cti-agent/orchestrator/CLAUDE.md
```

Put what you added into `orchestrator.md` in the pack, then:

```bash
sudo rm /opt/cti-agent/orchestrator/CLAUDE.md
```

```bash
sudo cti-agent-update --for-real
```

The installer then writes the core file with your notes after it, and keeps
both current from then on.

## Checking a pack by hand

```bash
fleet-kit/bin/org-pack check org fleet-kit/fleet
```

On the box, add `--root-owned` to check ownership as the installer does.
`org-pack compose` prints a core file with the pack's notes after it, which
shows exactly what the installed file will say:

```bash
fleet-kit/bin/org-pack compose fleet-kit/fleet/agents/supplier/CLAUDE.md org/agents/supplier.md
```
