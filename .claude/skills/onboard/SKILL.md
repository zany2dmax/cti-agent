---
name: onboard
description: Walk an operator through setting up a CTI fleet box after install-fedora.sh - which lanes it runs (FLEET_LANES), the settings those lanes need, and their secrets - using cti-agent-onboard. Use when someone is setting up a new box, adding or dropping a lane, or asks what a box still needs configured.
---

# /onboard: set up a fleet box

This skill is for a person setting up a box, working with you. It's not for
the fleet's own check-in agent, which never runs it.

## The rules

- **Never ask for, accept or repeat a secret in this conversation.** That
  covers tokens, passwords, client secrets, API keys and anything
  `settings.manifest` marks `secret: yes` or `credential: yes`. Secrets are
  typed only into `cti-agent-secrets set NAME`, which reads them with no echo.
  If the operator pastes one, tell them to rotate it.
- **You run only the read-only commands:** `--dry-run`, `fleet-config check`
  and `fleet-timers`. The operator runs `--for-real` in their own terminal,
  because it prompts them and writes `/etc`.
- **Explain each setting from its source:** the comment in
  `fleet-kit/fleet/fleet.d.example/<file>.env` (on the box,
  `/opt/cti-agent/share/fleet.d.example/`) and its row in
  `fleet-kit/fleet/settings.manifest`. Don't guess what a setting does.

## Steps

1. **What is installed.** Have the operator run, on the box:

   ```bash
   sudo cti-agent-onboard --dry-run
   ```

   It prints the lanes the box runs now, the empty settings those lanes
   can't run without (required, or `ask: yes` in `settings.manifest`), and
   the secrets not stored yet. Nothing is written. Settings with a default
   are not listed: they need no answer.

2. **Choose the lanes.** Go through `fleet-kit/fleet/lanes.list` with the
   operator: each line is a lane and its summary. Ask what they have:
   - **appscan and appowners** need a web app scanner (Qualys WAS).
   - **domains** needs a registrar (GoDaddy) and a mail gateway (Proofpoint).
   - **vmscan** needs Qualys VM and a network spreadsheet in SharePoint.
   - **supplier** needs a supplier mailbox and a Jira Kanban board.
   - **digest, scout, mailbox and checkin** need only Microsoft Graph, a
     scanner for exposure (or `LOOKUP_PROVIDER=none`), and a Claude
     credential for the check-in.

   A lane they don't have stays out. Dry-run their choice:

   ```bash
   sudo cti-agent-onboard --dry-run --lanes LANE,LANE
   ```

3. **Explain what will be asked.** For each setting the dry run lists, read
   its comment in the example file and say in one line what it is and what
   value fits. For example, `DIGEST_TO`: who gets the daily digest, one or
   more addresses. Point out the ones where a wrong value fails quietly.
   The example comments say which: the Qualys pod, and the send gate's
   allow lists.

4. **The operator runs it.**

   ```bash
   sudo cti-agent-onboard --for-real --lanes LANE,LANE
   ```

   It asks each setting (Enter skips one), offers one Claude credential for
   the check-in, then each secret. A yes runs `cti-agent-secrets set`, which
   prompts them directly. Tell them to store only the secrets their lanes
   use: the list is what the programs could read, so it can include, for
   example, Falcon's keys when advisory triage isn't turned on.

5. **Check it.** Have them run these, and read the results with them:

   ```bash
   sudo cti-agent fleet-config check
   ```

   ```bash
   sudo cti-agent cti-mailer --check
   ```

   Then, for each lane, its own `--check` if it has one (`fleet-kit/fleet/lanes.list`,
   third column).

6. **Turn the lanes on.** RUNBOOK section 9 (`docs/guides/setup.md`) has the order and the gate
   for each timer. The installer never enables a timer, and onboard doesn't
   either.

If they want to drop a lane later: run onboard again without it, then run
the installer again (`sudo cti-agent-update --for-real`). The update turns
off the dropped lane's timer.
