# Lane manifests

Each lane is described once, in `fleet-kit/lanes/<lane>.toml`.
`scripts/lanes --write` generates the lane's systemd unit(s) from it, and
`task ship` refuses to push when a generated file is stale
(`task lane:check`).

A manifest owns the lane's `.service` units, its row in the orchestrator's
lane table, its place in the list of lanes every check-in beat must account
for, which settings belong in its `fleet.d` file, and what it adds to the
check-in beat's grant. It is checked against its timers, the commands
manifest, and the grant `run-checkin` actually gives.

## Why

A lane used to be defined in about eight places by hand: the command, its
runner, the systemd unit and timer, the settings and commands manifests, the
orchestrator's lane table, the checkin skill, the installer, and the tests that
keep those in step. The units alone were eleven copies of one template, with a
handful of lines that differ. A forker adding a lane had to copy one and know
which lines to change.

## The schema

```toml
lane = "scout"                  # lower case; must match the file name
handles = ["@scout"]            # board handles the lane answers to ([] for none)
summary = "One line: what the lane does."
setting_prefixes = ["SCOUT_"]   # settings named like this go in fleet.d/scout.env
all_settings = false            # true for the one lane that loads every lane's file
beat_grants = [                 # what this lane adds to the check-in beat's grant
  "Bash(cti-vmscan --check)",   # Bash(x) is $FLEET_CODE/bin/x, exactly as granted
]                               # Read(d/**) is $FLEET_HOME/d

[orchestrator]                  # the lane's row in the orchestrator's lane table
order = 2                       # where the row goes; unique
runs = "`$FLEET_CODE/bin/cti-scout`"
when = "Every 4 hours (`cti-agent-scout.timer`)"
sends_to = "nobody: feeds the digest"

[[unit]]                        # one per systemd service; a lane may have several
name = "scout"                  # cti-agent-<name>.service and .timer
description = "CTI scout sweep (poll advisory feeds)"
exec = "/opt/cti-agent/bin/cti-scout --feeds /etc/cti-agent/feeds.txt ..."
timeout = 900                   # TimeoutStartSec, seconds
nice = 15                       # Nice
audit_log = false               # true: LogsDirectory for the audit trail
extra = """                     # optional: raw unit lines, after Group=
SupplementaryGroups=systemd-journal
"""

[unit.timer]                    # optional; checked against the .timer file
description = "CTI scout sweep every 4 hours"
on_calendar = "*-*-* 00,04,08,12,16,20:15:00"   # or on_boot and on_unit_active
persistent = true
```

Every lane also declares its **health report**, or why it has none: exactly
one of these, or `scripts/lanes --check` fails.

```toml
# The lane health contract (internal/health): what the lane should have
# covered, what it did, and each gap, in reports/health/<lane>.json.
[health]
written_by = "appaudit"         # one of this lane's units
fresh_hours = 26                # older than this, the report is itself a gap
kinds = ["not_scanned", "held"] # the gap kinds it reports

# ...or, until it has one:
health_exempt = "planned for 2.1: the feeds that have gone silent"
```

See [The health contract](#the-health-contract) below.

Every key is checked. An unknown key is refused by name, because a misspelt
key would otherwise be silently ignored. `exec` must run something under
`/opt/cti-agent/bin/`, and a unit name may appear in only one lane.

## What is generated, and what is not

- **The `.service` unit** is generated in full, from one template that holds
  every lane's shared hardening and layout, plus the manifest's values. Don't
  edit a unit; edit its manifest and run `scripts/lanes --write`.
- **Two blocks inside each unit** belong to `scripts/settings-manifest`: the
  settings files the unit loads and the credentials it imports. The lane
  generator keeps them exactly as they are, so the two generators never
  disagree. A new unit gets a placeholder, which `settings-manifest --write`
  fills in.
- **The `.timer` stays hand-written.** Each one carries its own reasons for
  its schedule (why Tuesday, why not `Persistent`), and those are worth more
  than a generated file. `scripts/lanes --check` fails when a timer's
  `Unit=`, `Description=`, `Persistent=`, or schedule (`OnCalendar=`, or
  `OnBootSec=` and `OnUnitActiveSec=`) disagrees with the manifest.
- **The orchestrator's lane table** in `fleet-kit/fleet/CLAUDE.md`, between
  its `BEGIN lane table` and `END lane table` markers, is generated from each
  lane's `[orchestrator]` table. The Handle column comes from `handles`.
- **`internal/checkin/lanes_gen.go`**, the lanes a check-in beat's verdict
  must account for (`cti-checkin-verdict` refuses a verdict that skips one or
  names another), is every unit of every lane in the table, in table order.
  The check-in lane itself has no `[orchestrator]` table and isn't in either.
- **Which `fleet.d` file a setting lives in.** `scripts/settings-manifest`
  reads the lanes' `setting_prefixes` (the longest matching prefix wins, so
  `WAS_OWNER_CC` is appowners' and the rest of `WAS_` is appscan's), maps
  each unit to its lane from the manifests (the weekly unit is the digest
  lane's), and gives the `all_settings` lane every lane's file. A setting
  that a program outside its lane also reads still goes to core, as before.
- **The command each unit starts** must exist as `cmd/<name>` or
  `fleet-kit/fleet/bin/<name>` and be listed in `commands.manifest`. An effect
  command (one that sends, moves or files) must be started with `--for-real`,
  and with no rehearsal mode: a timer that says `--dry-run` would quietly
  never send.
- **The check-in beat's grant is declared, not generated.** `run-checkin`
  builds it by hand, where it can be reviewed line by line with its reasons.
  `scripts/lanes --check` runs that code with the box's paths and compares
  the result with every lane's `beat_grants`, both ways:
  - a grant no lane declares fails, so a capability nobody signed for can't
    ship
  - a declared grant that isn't given fails too
  - widening a grant (`--check` to `--check:*`) shows as one of each

  checkin declares the fleet-wide tools, and each lane declares its own
  check. A test also holds the checkin skill's credential-check list to the
  declared `--check` grants. Each granted command still needs its row in
  the bash guard's policy table (`test_lanes.py` checks that).
- **`fleet-kit/fleet/health.list`**: each lane's health contract (its
  report's unit, freshness and gap kinds), installed in
  `/opt/cti-agent/share/` for `fleet-health` and `cti-agent-doctor`. Lanes
  with `health_exempt` are left out.
- **`fleet-kit/fleet/lanes.list`**: each lane, its units and the
  credential checks `run-credcheck` runs for it, one tab-separated line a lane. It
  goes to `/opt/cti-agent/share/` for the tools on the box that don't read
  TOML: the installer, `fleet-timers` and `fleet-config`, which use it for
  `FLEET_LANES`. `internal/checkin/lanes_gen.go` also maps each unit to its
  lane, for the verdict.
- **`fleet-kit/fleet/fleet.d.example/`**: `fleet.env.example` cut into the
  files a split box keeps, one per lane plus `00-core.env`, each setting with
  its comment. Secrets and logins are left out. `cti-agent-onboard` takes
  each setting's comment and file from here, and `task lane:write` runs the
  lane generator again after the settings one, because these follow
  `settings.manifest`.
- **[`docs/lanes.md`](lanes.md)**: the lane reference for people. For each
  lane it gives the units, what each runs and when, its time limit, the
  settings in its `fleet.d` file, the secrets its programs read, its
  credential checks and its beat grants. It also follows `settings.manifest`
  and `lane-settings.list`, so the same second run of the lane generator
  keeps it current.
- **`fleet-kit/fleet/lane-settings.list`** (written by
  `scripts/settings-manifest`, not this): per lane, the settings and secrets
  its programs read, for `cti-agent-onboard`. A setting named for another
  lane (by its prefix) is left out of a lane's list, even when a shared
  program can read it.
- `cti-agent-alert@.service` is not a lane; it is the failure handler every
  unit names, and it stays hand-written.

## The health contract

Every lane says what it *didn't* cover, so the check-in can tell a gap
somebody chose from one nobody noticed. The pieces:

- **The report.** The unit named by `written_by` writes
  `reports/health/<lane>.json` (schema `cti-lane-health/1`, built with
  `internal/health`): how many subjects the lane should have covered (`of`),
  how many it did (`covered`), and one gap per subject it missed, each with a
  `kind` from the manifest. A lane that couldn't work out its health at all
  writes `error` instead. In Go: `health.New`, `Add` per gap, `Apply` with the
  declarations, then `Write`.
- **What this organization chose.** The org pack's `expected-gaps.txt`
  ([org-pack.md](org-pack.md)) declares gaps by design, each with a reason and
  an optional `until=` date. `Apply` marks a gap a declaration covers as
  `expected`, with its reason. Every other gap is an accident.
- **The check-in reads it once.** `fleet-kit/fleet/health.list`, generated
  from the manifests, lists each lane's report, unit, freshness and kinds.
  Before each beat, `fleet-health delta` puts only what changed since the
  last beat in the beat's prompt. That's a new accident, one that cleared,
  or a report gone missing or stale. `fleet-health commit` records it after
  a beat that finished. The orchestrator's rules for it are core, in
  `fleet-kit/fleet/CLAUDE.md` "Lane health", so a new lane needs no
  orchestrator notes for its health.
- **The doctor** checks every report a box should have: present, current
  and not an error.

`health_exempt` is for a lane that has no report yet. Its reason is printed
in [lanes.md](lanes.md). That keeps "no report" declared too, never an
accident.

## Adding a lane

In a fork, the `/add-lane` Claude Code skill (`.claude/skills/add-lane`) walks
through all of this, including the parts no generator writes. `/add-provider`
does the same for a new vendor behind an existing interface.

1. Write `fleet-kit/lanes/<lane>.toml`.
2. Write its timer in `fleet-kit/fleet/systemd-fedora/`, if it has one.
3. Run these, then review the diff:

   ```bash
   scripts/lanes --write
   ```

   ```bash
   scripts/settings-manifest --write
   ```

The rest of a new lane is still done by hand for now:
- the "What to know about each" notes and the checkin skill's "Scheduled
  work" check, including its example verdict and lane count
- the commands manifest
- the installer's timer list

The tests in `fleet-kit/tests/test_lane_manifests.py` and `test_lanes.py` name
anything missed.

```bash
scripts/lanes --list
```

prints every lane, its units and when each runs.
