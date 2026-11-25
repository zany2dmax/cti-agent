---
name: add-lane
description: Add a new lane to a fork of the cti-agent fleet - its command, runner, lane manifest, timer, the orchestrator's notes and check, and everything the tests hold a lane to - so the check-in oversees it from its first run. Use when someone wants the fleet to do a new recurring job.
---

# /add-lane: a new recurring job for the fleet

A lane is one manifest, `fleet-kit/lanes/<lane>.toml` (schema in
`docs/lane-manifest.md`), plus the few things that need judgment. Generators
write the rest, and the tests name anything missed. Work through the steps in
order, and run `task ship` at the end.

## The rules

- **Say how to run it.** A command that sends, moves or files must take
  `--dry-run` or `--for-real`, and print usage and exit 2 with neither
  (`fleet_require_mode` in a runner, `cli.Resolve` in Go). The unit starts it
  `--for-real`; `scripts/lanes --check` refuses a unit that doesn't.
- **Every command and flag goes in `fleet-kit/fleet/commands.manifest`** in
  the same change, with its man page.
- **Standard library only, invented data in tests,** and no real names in
  any tracked file.
- **The check-in must oversee it,** or it is a lane nobody checks.

## Steps

1. **The command.** `cmd/<cti-name>/` in Go:
   - It reads its settings with `os.Getenv` in `cmd/`, never by name in a
     shared package's comments, or the settings generator credits every
     importer with that setting.
   - Add it to the Taskfile's build list.
   - Give it a `--check` if it logs in anywhere.

2. **The runner,** if the lane is more than one command:
   `fleet-kit/fleet/bin/run-<lane>`. Copy `run-vmscan`'s shape: it sources
   `fleet-mode.sh`, loads the settings files, calls
   `fleet_secrets_from_credentials`, and takes a mode. Write paths with the
   code directory followed by `/bin/` or `/share/`: a bare `/opt/cti-agent`
   reads as a call to the wrapper. Use `${A[@]+"${A[@]}"}` for arrays, for
   macOS bash.

3. **The manifest,** `fleet-kit/lanes/<lane>.toml`:
   - `lane`, `handles` (`@<lane>`) and `summary`
   - `setting_prefixes` for the settings it owns
   - `credential_checks` (its `--check`, which run-credcheck runs daily)
   - `[orchestrator]`: its row in the lane table; `order` must be unique
   - one `[[unit]]` per service, with `exec` starting
     `/opt/cti-agent/bin/`, plus a `[unit.timer]`

   Don't add `beat_grants` unless the check-in must run something of the
   lane's. Nothing the beat runs may read a secret, and a test holds the
   check-in unit to a Claude credential and Graph.

4. **The timer,** `fleet-kit/fleet/systemd-fedora/cti-agent-<unit>.timer`, by
   hand, with a comment saying why that schedule. Its `Description=`,
   `OnCalendar=` and `Persistent=` must match the manifest.

5. **Generate:**

   ```bash
   task lane:write
   ```

   That writes the `.service` unit, the orchestrator's lane table row, the
   check-in verdict's lane list, `lanes.list`, the `fleet.d` example and the
   settings manifest rows. Review the diff. If a setting landed in core
   that should be the lane's, another lane's program reads it, and
   `file-why:` says which.

6. **What the generators can't write:**
   - **The bash guard's handle list,** in `cmd/checkin-bash-guard/policy.go`
     (`var handles`), so a beat can address `@<lane>` on the board.
   - **The orchestrator's notes:** a "What to know about each" paragraph in
     `fleet-kit/fleet/CLAUDE.md` saying what a held or a quiet day means for
     this lane.
   - **The check-in skill,** `fleet-kit/fleet/skills/checkin/SKILL.md`: a
     "did it run" row in the Scheduled work table (usually
     `fleet-journal -u cti-agent-<unit>.service --since today --no-pager`,
     and the runner's `done` line). Also add its entry to the example verdict,
     and update the lane count ("all ten").
   - **RUNBOOK section 9** (`docs/guides/setup.md`): a row in the timer
     table, with its gate. If the lane needs an operating guide, it goes in
     `docs/lanes/<lane>.md`, with its own RUNBOOK number and a pointer in
     `RUNBOOK.md`.
   - **ARCHITECTURE.md:** the runner in the layout block, and the command in
     the commands table.
   - **`test_lanes.py` `AuditTrailUnits`:** the unit in `WITH` if it writes
     the audit log (`audit_log = true`), else in `WITHOUT`.
   - **A man page for the runner and the command.** Sections: NAME, SYNOPSIS,
     DESCRIPTION, OPTIONS, EXIT STATUS, EXAMPLES, SEE ALSO.

7. **The recipe line.** Append to the fork's `org/recipe.md`: "lane `<lane>`
   (`cti-agent-<unit>.timer`), <commit>".

8. **Ship it:**

   ```bash
   task ship
   ```

   Read what fails: the test names are the checklist. Then, on the box:
   - add the lane to `FLEET_LANES` if that is set
   - run `sudo cti-agent-onboard --dry-run` for its settings and secrets
   - run the lane by hand with `--dry-run`
   - only then enable its timer, as RUNBOOK section 9 (`docs/guides/setup.md`) says
