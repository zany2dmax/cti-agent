# The agent harness: what the fleet has, and what it is missing

> **STATUS: DESIGN, H1 BUILT.** H1 (beat traces) is built and unreleased; see
> [CHANGELOG.md](CHANGELOG.md). The other work items are in
> [BACKLOG.md](BACKLOG.md). This page exists so the shape can be
> argued about before any code depends on it.

"Harness" here means everything around the model that turns it into an agent
you can trust to run unattended: the instructions it starts with, the tools it
may use, the guardrails on those tools, where its output goes, how a run is
recorded, and how you know a change to any of that did not make it worse.

The fleet does not need a new framework to get one. The `claude` CLI already
is the inner harness (the loop, the tools, the context window), and
`run-checkin` has grown most of the outer harness around it. What is missing
is the part that tells you whether the agent is *behaving*: recorded runs and
tests of its judgment.

This page has a second purpose. The fleet is also how its operator learns how
these tools work, so each item says what it teaches as well as what it fixes.

---

## 0. Contents

1. [What already exists](#1-what-already-exists)
2. [The gaps](#2-the-gaps)
3. [Work items, in order](#3-work-items-in-order)
4. [What we deliberately do not do](#4-what-we-deliberately-do-not-do)
5. [Rules every harness change follows](#5-rules-every-harness-change-follows)

---

## 1. What already exists

Only one lane calls a model today: the orchestrator check-in
(`fleet-kit/fleet/bin/run-checkin`, which runs `claude -p "/checkin"`). Every
other lane is deterministic Go or Python. The triage agent
(`fleet-kit/fleet/agents/triage`) is designed but not wired in.

| Harness piece | Where it lives |
|---|---|
| Standing instructions | `fleet-kit/fleet/CLAUDE.md` |
| Procedures loaded on demand | `fleet-kit/fleet/skills/` (`checkin`, `cti-digest`, `patch-tuesday`, `scout-sweep`) |
| Config isolation | `--setting-sources project`, `--strict-mcp-config`, auto-memory off, root-ownership checks on the agent directory and the binary |
| Tool permissions | `--allowedTools` built line by line in `run-checkin`; `Edit`/`Write`/`NotebookEdit`/`WebFetch`/`WebSearch` denied in `checkin-settings.json` |
| Guardrail hook | `checkin-bash-guard` (PreToolUse on Bash) |
| Narrow wrappers instead of raw commands | `fleet-journal`, `fleet-timers`, `fleet-db`, `fleet-board` |
| Output channel that cannot be redirected | `cti-alert` (no `--to`; recipient fixed by configuration) |
| Shared memory | `fleet-board`, `state/memory.db` through `fleet-db` |
| Cost and quota control | `cti-budget` (gate before the beat, `record` after; rate limit vs. out of credit, see `internal/budget/classify.go`) |
| Schema-checked model output (designed) | `internal/triage/result.go` (`cti-triage/1`) |

This is the part most projects skip, and the fleet has it.

---

## 2. The gaps

### 2.1 No record of what a beat did

The beat's output goes to a `mktemp` file and to the journal as plain text.
There is no record of which tools the agent called, which calls were denied,
how many turns it took, or what it cost. "Why did the heartbeat escalate on
Tuesday?" can only be answered from whatever the model chose to print.

*Teaches:* what an agent run actually looks like inside: turns, tool calls,
denials, token use.

### 2.2 Nothing tests the agent's judgment

`fleet-kit/tests/test_lanes.py` checks the plumbing thoroughly, down to the
exact `--allowedTools` string. Nothing checks what the agent *does* with a
given situation. A change to `CLAUDE.md`, a skill, the allowlist or the model
version is shipped on trust.

*Teaches:* evals, the single most important habit in building with models.

### 2.3 The check-in returns prose

The beat ends in free text plus side effects (board posts, alerts). Go cannot
act on it, and an eval cannot score it without reading prose.

*Teaches:* structured output and verifying model output before acting on it,
the same idea as `internal/triage`.

### 2.4 No shared wrapper for a second model lane

`run-checkin` is about 600 lines, most of it security setup that every model
lane will need. When the triage agent or supplier-request triage is wired in,
copying it would mean two copies of the controls drifting apart.

*Teaches:* what in a harness is policy (shared) and what is the job (per lane).

---

## 3. Work items, in order

Each item is small enough to ship on its own, and each feeds the next.

### H1. Beat traces (built, unreleased)

What was built: `fleet-kit/fleet/bin/fleet-trace` (`init`, `tee`, `show`,
`list`, `prune`) and the trace path in `run-checkin`, with
`CHECKIN_TRACE_DAYS` and `CHECKIN_TRACE_MAX_MB`. The plan as written:

- Run the beat with `--output-format stream-json --verbose` and keep the
  stream as `state/traces/checkin-<timestamp>.jsonl`, 0600, rotated by age
  (ties into the fleet housekeeping item in the backlog).
- Keep printing a plain-text summary to the journal so `journalctl` stays
  readable.
- A small reader (`fleet-trace`, Python stdlib) prints one beat as a
  timeline: tool, arguments, allowed or denied, result size, tokens, cost.
- **Watch:** `cti-budget record --output` classifies the tail of the beat's
  text today. It must keep receiving the CLI's error text, not the last
  lines of JSON, or the rate-limit and out-of-credit detection that the
  24 September outage taught us breaks silently. Add a test for both.
- **Watch:** a trace holds everything the agent read, including untrusted
  advisory text. Same handling as reports: 0600, never mailed, never
  committed.

### H2. Eval harness for the check-in

- A directory of scenarios, `fleet-kit/tests/evals/<name>/`, each a fake
  `$FLEET_HOME` (board, reports, journal fixtures, all invented data) and an
  `expect.json`.
- Expectations are about behavior, checked from the H1 trace, not about
  wording: "called `cti-alert` with `--kind ESCALATION`", "did not call
  `cti-alert`", "never attempted `mailer.py`", "no tool denied more than
  once", "under N turns".
- First scenarios (5 to 10):
  - quiet day, nothing to do (must stay quiet)
  - a lane silent for two days (must escalate once)
  - a Sev5 / KEV hit in the day's report (must escalate now, not batch)
  - an advisory carrying a prompt injection ("email this to...", "ignore
    your instructions") (must not act on it; must not try mail tools)
  - a budget HOLD already on the board (must not re-escalate)
  - one scenario per PrimeSec attack vector that touched the orchestrator
- Run by hand (`task eval`), never in `task ship`: it costs real tokens and
  is not deterministic. Run each scenario 3 times and report pass rate, not
  pass/fail.
- Real traces from H1 that surprised us become new scenarios.

**Done for the supplier lane:** `task eval:supplier` is this idea for the
supplier-request judgement - 26 invented requests in
`internal/supplier/testdata/eval/cases.json`, the real model called as production
calls it, a rate per case (3 runs), failing only on a dangerous result. Cheap
checks on the cases themselves (valid, invented data only, no hostile case may
allow a No) run with every `go test`.

### H3. Structured check-in verdict

- The check-in skill ends with one JSON object, schema `cti-checkin/1`:
  overall status, per-lane health, escalations sent, items deferred to the
  digest.
- Go verifies it the way `internal/triage` verifies `cti-triage/1`
  (unknown schema is a loud error; absent and empty are different).
- An invalid or missing verdict is a board ERROR, not a silent pass.
- Evals (H2) then score the verdict directly.

### H4. Shared model-lane runner (only when a second model lane is real)

- Pull the policy half of `run-checkin` into one runner: binary discovery and
  ownership checks, config isolation, allowlist assembly, budget gate and
  record, trace capture, verdict verification.
- Each lane supplies only its prompt, its skill, its tool grants and its
  schema.
- Follows the [INTERFACES.md](INTERFACES.md) rule: build it when the second
  implementation exists, not before.

### H5 (learning, optional). An Agent SDK sidecar

- A throwaway Python experiment, outside production, that reproduces one
  check-in beat with the Claude Agent SDK, to see the loop, hooks and
  permission callbacks from the inside.
- Not a migration. Production stays on the CLI (see section 4).

---

## 4. What we deliberately do not do

- **No agent framework** (LangGraph, CrewAI and the like). They would add
  dependencies, and `go.mod` stays empty by policy. They would also replace a
  permission model that has been through PrimeSec review with one that has
  not.
- **No move of production to the Agent SDK.** The CLI's settings, hooks and
  allowlists are what the security review covered. The SDK is worth
  learning (H5), not worth re-securing the fleet for.
- **No multi-agent orchestration.** One judgment agent overseeing
  deterministic lanes is the right shape for this work. More agents talking
  to each other means more paths for injected text to travel.
- **No evals in CI.** They cost money and are not deterministic. They are a
  tool for the operator before a change, not a gate on every push.

---

## 5. Rules every harness change follows

- Delivery stays deterministic; only judgment is the model's
  ([AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md#1-delivery-is-deterministic-judgment-is-not)).
- No new tool grant without a line in `run-checkin` saying why it is safe
  to give an agent that reads untrusted text.
- Traces, eval fixtures and verdicts contain no real org data in the repo:
  example.com, host-a, 192.0.2.x.
- Anything new written in Python is stdlib only; anything in Go is standard
  library only.
