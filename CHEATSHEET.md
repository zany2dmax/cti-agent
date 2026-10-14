# CTI Agent Fleet: Operator Cheat Sheet

For anyone who needs to SSH to the fleet box and answer: is it up, is it working,
when does it run next, and what would it send? Everything here is read-only or a
dry run unless it is marked **SENDS MAIL** or **WRITES**.

Full detail: `man cti-agent`, `man <command>` for any command below, and
`RUNBOOK.md`.

## 1. The ground rules

- **Run fleet commands through the wrapper:** `sudo cti-agent <command> [args]`.
  It switches to the `ctiagent` service account, loads `/etc/cti-agent/fleet.env`
  and sets the same paths the timers use. Running the binaries directly gives
  you different settings from the timers.
- **Dry runs are safe.** `--dry-run` builds the whole report and sends nothing.
  A command without it may send mail or write to Jira.
- **Do not edit the state files by hand** (anything under `/var/lib/cti-agent`)
  unless this sheet or the runbook says to.

| What | Where |
|---|---|
| Settings and secrets (root:ctiagent, 0640) | `/etc/cti-agent/fleet.env` |
| Installed version record | `/etc/cti-agent/version` |
| Domain inventory (not in git) | `/etc/cti-agent/domains.txt` |
| Programs | `/opt/cti-agent/bin`, `/opt/cti-agent/lanes` |
| State, reports, memory database | `/var/lib/cti-agent/{state,reports}` |
| Message board | `sudo cti-agent fleet-board tail 30` |
| Go source the installer builds from (root's clone) | `/opt/cti-agent/agent` |
| Kit you install from (runners, units, lanes) | any operator's own clone, e.g. `~/cti-agent` |

## 2. The one-minute health check

```bash
systemctl list-timers 'cti-agent-*'          # every lane, last and next run
systemctl --failed 'cti-agent-*'             # anything in a failed state
sudo cat /etc/cti-agent/version              # what is installed
sudo cti-agent fleet-db recent               # memory, open tasks, finding counts
sudo cti-agent fleet-board tail 20           # what the fleet said recently
sudo cti-agent cti-budget status             # heartbeat ceilings and cooldown
```

All good looks like: no failed units, every timer has a NEXT time, the board has
no recent `ERROR` lines, and the budget says `ready` or `denied` with a reason.

## 3. What version is installed?

None of these need anyone's home directory.

```bash
sudo cat /etc/cti-agent/version                         # tag, commit, build and install time
sudo git -C /opt/cti-agent/agent log --oneline -3       # the source it was built from
git ls-remote https://github.com/zany2dmax/cti-agent.git HEAD   # latest published commit
sudo cti-agent cti-mailer --check                       # also logs its version and checks Graph
```

If the `commit=` in `/etc/cti-agent/version` is not the latest published
commit, the box is behind. Update it (section 11).

## 4. When does everything run?

```bash
systemctl list-timers 'cti-agent-*'                  # NEXT and LAST for each lane
systemctl list-timers cti-agent-domains.timer        # one lane
systemctl cat cti-agent-digest.timer                 # its schedule (OnCalendar=)
```

| Lane | Timer | Schedule (box clock) | Sends to |
|---|---|---|---|
| Daily digest | `cti-agent-digest` | every day 06:00 | digest audience |
| Weekly digest | `cti-agent-weekly` | Mondays 07:00 | digest audience |
| Mailbox cleanup | `cti-agent-mailbox` | every day 07:00 | nobody (moves mail) |
| AppSec weekly | `cti-agent-appscan` | Mondays 07:30 | App Dev audience |
| Domains weekly | `cti-agent-domains` | Mondays 08:00 | domains audience |
| Patch Tuesday (paused: sources block Azure) | `cti-agent-patchtuesday` | Wednesday after the 2nd Tuesday, 07:30 | digest audience |
| Feed scout | `cti-agent-scout` | every 4 hours at :15 | nobody |
| Orchestrator heartbeat | `cti-agent-checkin` | every 2 hours | escalations only |

A failed unit emails the operator automatically (`cti-agent-alert@`).

## 5. Logs

```bash
journalctl -u cti-agent-digest.service --since today --no-pager
journalctl -u cti-agent-digest.service -n 100 --no-pager
journalctl -u 'cti-agent-*' --since "-2h" --no-pager      # every lane, last 2 hours
journalctl -u cti-agent-checkin.service -f                # follow the heartbeat live
systemctl status cti-agent-domains.service                # last result and exit code
```

Useful filters:

```bash
journalctl -u cti-agent-digest.service --since today --no-pager | grep -E 'FAILED|WARNING|ERROR'
journalctl -u cti-agent-digest.service --since today --no-pager | grep -E 'ticket|follow-up|WRITE GATE'
```

## 6. Dry runs: see what it would send

None of these send mail, file tickets or advance a baseline.

```bash
sudo cti-agent run-digest daily --dry-run
sudo cti-agent run-digest weekly --dry-run
sudo cti-agent run-appscan --dry-run
sudo cti-agent run-domains --dry-run
sudo cti-agent run-patchtuesday --dry-run
sudo cti-agent run-patchtuesday --month 2026-09        # replay a past month, never sends
sudo cti-agent run-mailbox-cleanup                     # plan only; moves nothing
sudo cti-agent cti-alert --unit cti-agent-digest.service --dry-run
```

Then read the result:

```bash
sudo less /var/lib/cti-agent/reports/digest-daily-$(date +%F).txt
sudo less /var/lib/cti-agent/state/domains-$(date -u +%F).txt
sudo less /var/lib/cti-agent/state/appscan-$(date -u +%F).txt
sudo ls -t /var/lib/cti-agent/reports | head        # newest reports first
```

Patch Tuesday without the scanner (fast, public sources only):

```bash
sudo cti-agent cti-patchtuesday --month 2026-09 --dry-run --provider none 2>&1 | less
```

## 7. Real runs (SENDS MAIL)

Normally the timers do this. Run by hand only to re-send after a failure.

```bash
sudo systemctl start cti-agent-domains.service     # exactly as the timer would
journalctl -u cti-agent-domains.service -n 50 --no-pager
sudo cti-agent run-domains                         # same, in your terminal
sudo cti-agent run-digest daily                    # refuses if today's already went
```

- The daily, weekly and Patch Tuesday lanes record each send and will not send
  the same day or month twice.
- The domains run replaces last week's baseline, so the next Monday's "changed
  since last week" compares with today.
- **Never re-run a digest that exited 3.** It was sent but not recorded; the
  journal prints the exact `fleet-db sent ...` command to record it instead.
- `run-mailbox-cleanup --for-real` **WRITES**: it moves mail in the mailbox.

## 8. Is a send recorded?

```bash
sudo cti-agent fleet-db was-sent $(date +%F) daily      # yes / no
sudo cti-agent fleet-db was-sent $(date +%F) weekly
sudo cti-agent fleet-db was-sent 2026-October patchtuesday   # the month as the subject names it
```

## 9. Jira tickets

```bash
sudo cti-agent cti-jira --check                         # account, project, write gate
E=/var/lib/cti-agent/state/enriched-$(date +%F).json
sudo cti-agent cti-jira --from-enriched "$E" --follow-up           # preview, changes nothing
sudo python3 -m json.tool "${E%.json}-tickets.json" | less   # today's ticket list (no jq here)
```

The domains lane's weekly lock-down ticket for IT (one per run, or a comment
on the open one when the list changed):

```bash
A=/var/lib/cti-agent/state/domains-$(date -u +%F)-actions.json
sudo cti-agent cti-jira --domains-actions "$A"        # preview the ticket, changes nothing
```

`WRITE GATE CLOSED` in the output means `JIRA_ALLOW_CREATE` does not list the
project, so nothing is filed or commented.

## 10. Heartbeat, board and memory

```bash
sudo cti-agent cti-budget status               # beats used, ceilings, cooldown
sudo cti-agent fleet-board tail 30             # last 30 board lines
sudo cti-agent fleet-board read @you           # lines addressed to the operator
sudo cti-agent fleet-db recent 20              # recent memories, open tasks, counts
sudo cti-agent fleet-db findings --priority Sev5
sudo cti-agent cti-kev --horizon 30            # KEV deadlines due in 30 days
```

## 11. Updating the box

Run the installer from your own clone. Make one the first time
(the repository is public, so no key is needed):

```bash
git clone https://github.com/zany2dmax/cti-agent.git ~/cti-agent   # once
```

Then, each update:

```bash
cd ~/cti-agent && git pull
sudo sh fleet-kit/install-fedora.sh --dry-run   # what it would change
sudo sh fleet-kit/install-fedora.sh             # install; keeps fleet.env and state
sudo cat /etc/cti-agent/version                 # confirm the new commit
systemctl list-timers 'cti-agent-*'             # timers still scheduled
```

Install a new domain inventory:

```bash
sudo install -o root -g ctiagent -m 0640 /tmp/domains.txt /etc/cti-agent/domains.txt
sudo cti-agent run-domains --dry-run
```

Pause or resume one lane:

```bash
sudo systemctl disable --now cti-agent-domains.timer
sudo systemctl enable --now cti-agent-domains.timer
```

## 12. Mail and Microsoft Graph

```bash
sudo cti-agent cti-mailer --check       # token, granted roles, version
sudo cti-agent mailer.py --check        # the Python mailer's view of the same
sudo cti-agent cti-mailbox              # cleanup plan (dry run is the default)
```

`MISSING Mail.Read` or `MISSING Mail.Send` means the app registration lost a
permission or admin consent.

## 13. Troubleshooting

| Symptom | First thing to run |
|---|---|
| No daily email today | `journalctl -u cti-agent-digest.service --since today --no-pager` |
| A unit shows failed | `systemctl status <unit>`, then its journal |
| Heartbeat not running | `sudo cti-agent cti-budget status` (cooldown or ceiling?) |
| "journal unavailable" in a hand-run alert | Expected: only the alert unit can read the journal |
| Patch Tuesday sources show 403 | The Qualys blog refuses Azure addresses; it is optional |
| Domains report says lookups failed | `DOMAINS_DNS_SERVERS` in fleet.env; outbound UDP/TCP 53 |
| Tickets missing from the daily | Section 9; look for `WRITE GATE CLOSED` |
| SELinux suspicion | `sudo ausearch -m avc -ts recent` |
| Outbound connectivity | `curl -sS -o /dev/null -w '%{http_code}\n' https://graph.microsoft.com` (any code = reachable) |

## 14. Help

```bash
man cti-agent            # the wrapper and the list of commands
man run-digest           # any command has a page
apropos cti-             # list them all
```
