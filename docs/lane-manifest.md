# Lane manifests

Each lane is described once, in `fleet-kit/lanes/<lane>.toml`.
`scripts/lanes --write` generates the lane's systemd unit(s) from it, and
`task ship` refuses to push when a generated file is stale
(`task lane:check`).

This is the first part of the lane manifest work. Today a manifest owns the
lane's `.service` units and is checked against its timers. Later steps add the
orchestrator's lane table, the settings and commands manifest rows, and the
grants a lane needs, so adding or removing a lane is one file instead of
eight.

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

The rest of a new lane is still done by hand for now: the orchestrator's lane
table, the checkin skill, the commands manifest, and the installer's timer
list. The tests that keep those in step will name anything missed.

```bash
scripts/lanes --list
```

prints every lane, its units and when each runs.
