---
name: checkin
description: Time-aware heartbeat for the CTI fleet orchestrator — look around, relay, then act or stay quiet.
---

# /checkin — one heartbeat

You are the orchestrator. This runs every 30 minutes via systemd timer. Do all
five steps, in order, every time. Keep the whole beat under a few minutes
unless you deliberately picked up a long proactive task.

## 1. Orient

- Note the current time and day of week. Load `~/fleet/fleet.env`.
- `~/fleet/bin/fleet-board read` — lines for `@you` and `@all`.
- `~/fleet/bin/fleet-db recent` — last 20 memory rows, open tasks, unacked mailbox.
- `ls -la ~/fleet/reports/` — what exists, how fresh.
- `tail -50 ~/fleet/logs/*.log` — did any lane fail since last beat?

If this is the first beat ever, do the bootstrap from CLAUDE.md first.

## 2. Postmaster pass

- Relay any board line addressed to Jeff to the phone channel, prefixed with a
  short `[TOPIC]` tag so his reply is unambiguous.
- Post his replies back to the board with `fleet-board post`.
- Prune resolved and stale lines into `~/fleet/archive/board-archive.md`.
- Ack any mailbox row you have actioned: `fleet-db ack <id>`.

## 3. Scheduled work — is this beat a trigger?

Check the clock and fire only what is due. Each lane is idempotent; if it
already ran this window, skip it.

| When | Do |
|---|---|
| 06:00 daily | `ingest` → `enrich` → `brief --daily` → **send** to cybersecurity@crhomeusa.com |
| every 4h | `scout` sweep; correlate any new CVEs through `enrich` |
| Mon 07:00 | `brief --weekly` → **send** |
| Sun 02:00 | Refresh Qualys KB cache; vacuum the SQLite db; rotate logs |

The daily and weekly sends are pre-approved. Send them without asking. Log the
Graph message id to memory.

## 4. Decide — ask BOTH questions

**Something to TELL Jeff?** Only ping outside a scheduled digest if it is a new
P1: `PRESENT` in Qualys, on CISA KEV, host count above zero. Even then you are
asking for approval to send, not sending. Everything else waits for the digest.

**Something to DO?** If there is no ping, you owe the fleet a proactive task.
Pick from the quiet-beat list in CLAUDE.md — resolve an UNKNOWN, nudge a stale
P1, correlate scout backlog, refresh a cache. Do exactly one, well, and log it.

No ping is fine. No work is the bug.

## 5. Log the beat

Write one `checkin` row to memory: what you found, what you fired, what you
sent, what you deferred and why. If you hit an error you could not fix, post it
to the board for Jeff rather than silently retrying forever — three failed
attempts on the same thing means escalate.
