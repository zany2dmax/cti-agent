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
- **`fleet-kit/fleet/lanes.list`**: each lane, its units and the
  credential checks the beat runs for it, one tab-separated line a lane. It
  goes to `/opt/cti-agent/share/` for the tools on the box that don't read
  TOML: the installer, `fleet-timers` and `fleet-config`, which use it for
  `FLEET_LANES`. `internal/checkin/lanes_gen.go` also maps each unit to its
  lane, for the verdict.
- `cti-agent-alert@.service` is not a lane; it is the failure handler every
  unit names, and it stays hand-written.

## Adding a lane

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
