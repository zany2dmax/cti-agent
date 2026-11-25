---
name: update-fleet
description: Update a CTI fleet box, or bring a fork of cti-agent up to date with upstream - read what is incoming and what it asks of the box, update with its automatic snapshot, read cti-agent-doctor, and roll back if needed. Use when someone asks to update, upgrade, ship a release to the box, or pull upstream into their fork.
---

# /update-fleet: update a box, or a fork

Two jobs share this skill. Ask which one, or tell from what the person says:
- **The box:** the server running the fleet. It updates from its own kit
  checkout, `/root/cti-agent-kit`.
- **The fork:** someone's copy of the repository. It pulls upstream's
  changes, then ships to its own box.

## The rules

- **The person runs every `sudo` command** in their own terminal. You read
  the output with them.
- **Never move, delete or retag a release tag yourself,** and never `git push
  --force` without being asked. A moved tag is fixed by deleting the stale
  local copy, which the updater prints when it applies.
- **Never ask for a secret** in the conversation.

## Updating the box

1. **See what is coming:**

   ```bash
   sudo cti-agent-update --dry-run
   ```

   It prints the version now, the version available and the incoming
   commits. Nothing is pulled.

2. **Read what the update asks of the box.** In the kit's `CHANGELOG.md`, read
   every section between the box's version and the new one. Look for:
   - settings to add, move or rename. A setting's file can change: for
     example, the `TRIAGE_*` settings moved to `fleet.d/digest.env`
   - a new timer to turn on, or one the installer turns on for you
   - a box command to run once
   - anything marked **Upgrade**

   List those for the person before step 3, in the order to do them.

3. **Update:**

   ```bash
   sudo cti-agent-update --for-real
   ```

   - **It takes a snapshot first,** in `/var/lib/cti-agent-update/`. The
     snapshot holds the code, the config, the fleet's units and a copy of
     `memory.db`.
   - **It runs the installer.** If the installer fails, it puts the
     snapshot back whole and exits with the installer's status. Read the
     installer's error above that line, fix the cause, and run it again.
   - **It ends with `cti-agent-doctor`.**

4. **Read the doctor.** Every line should be OK:
   - **WARN `version`:** the kit is ahead of the install, so run step 3 again.
   - **FAIL `settings`:** `sudo cti-agent fleet-config check` names each
     setting.
   - **WARN `timers`:** a lane this box runs has its timer off. Turn it on
     per RUNBOOK section 9, or leave the lane out of `FLEET_LANES`.
   - **FAIL `credentials`:** a login broke. The line names the lane.
   - **FAIL `units`:** a unit failed. Read its journal with
     `sudo cti-agent fleet-journal -u <unit> -n 50 --no-pager`.

5. **If the new release misbehaves** after a good install:

   ```bash
   sudo cti-agent-update --rollback --dry-run
   ```

   ```bash
   sudo cti-agent-update --rollback --for-real
   ```

   That puts back the code, config, units and kit from before the update. It
   leaves `memory.db`, because the lanes have written to it since. It refuses
   while a lane is running.

6. **If the fetch refuses a tag** ("would clobber existing tag"), the updater
   prints the fix:
   - a moved tag: two `git tag -d` commands, one per checkout
   - a rewritten history: the reset steps

   Read which one it printed, and have the person run exactly that.

## Bringing a fork up to date

1. In the fork, fetch upstream, then merge or rebase onto the release tag
   (not `main`, unless they want unreleased work).
2. Conflicts should only be in files the fork changed in core. The fork's own
   folders (`org/`, its providers' packages, its lanes' manifests) never
   conflict, because upstream doesn't have them. `org/recipe.md` lists what
   the fork added. Check each item still builds and passes:

   ```bash
   task lane:write
   ```

   ```bash
   task ship
   ```

   The registry tests and `lane:check` name anything upstream's changes
   broke.
3. Then update the fork's box as above. Its kit pulls from the fork.
