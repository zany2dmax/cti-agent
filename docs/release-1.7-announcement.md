# What's new in CR Agent Fleet 1.7

**Release 1.7 | November 2026 | Covers everything since 1.6.6 (including 1.6.7)**

CR Agent Fleet 1.7 is our biggest release yet for **security of the fleet itself**. It completes the **agent harness**, the tooling that makes the fleet's AI analyst testable and accountable. It gives the fleet a first look at its own threat intelligence, and makes the weekly VM scan report something the network team can act on.

**Highlights**

- **Advisory triage.** Threat-intel emails are now checked against what we actually run, using CrowdStrike Falcon. The results appear in the Daily Brief.
- **An audit trail.** Every email, ticket and owner change the fleet makes is recorded in standard syslog format, ready for a SIEM.
- **Hardened by design.** The TLS 1.2 floor and https-only rule apply to every outbound call. Models see fewer secrets and less personal data. Every write is validated, and every release ships with an SBOM.
- **A smarter VM scan weekly.** It now takes its scan list straight from Qualys, files spreadsheet fixes as a help-desk ticket, and counts what it says it counts.
- **The agent harness, complete.** The fleet's AI analyst now comes with evals that test its judgement, a verdict on every run that is checked against what actually happened, and one shared set of rules for every AI lane.

**Upgrading:** run `sudo cti-agent-update --for-real`. One setting needs action on some boxes; see [Before you upgrade](#before-you-upgrade).

---

## Advisory triage: does this advisory affect us?

Threat-intel mail used to stop at "here is an advisory." Starting in 1.7, the fleet reads each advisory and checks it against our own CrowdStrike Falcon data. The answer is one of four:

| Verdict | What it means |
|----|----------|
| **Likely** | A host here runs the affected product, or has seen one of the advisory's indicators. |
| **Possible** | The product is here but isn't known to be fixed, or the evidence is partial. |
| **Unlikely** | Nothing in Falcon matches. |
| **Unknown** | The lookup failed, so the fleet won't guess. |

### How it works

1. **The reader** is a model with no tools. It sees only the advisory and lists its vendors, products, versions and ATT&CK techniques. Code then removes any claim the advisory doesn't support.
2. **The lookups** check each remaining item in Falcon: installed apps (with roughly how many hosts are below the fixed version), hosts that saw each indicator, and alerts naming each technique in the last 30 days.
3. **The judge** is a second model with no tools. It never sees the advisory, only the numbered facts the lookups produced, and it must cite the facts behind each verdict. Code then checks its work:
   - It drops any fact the judge made up.
   - It downgrades "likely" to "possible" when no host is involved.
   - It replaces any reason that claims something it can't back up.
   - It raises anything installed and not known to be fixed to at least "possible."

**Sightings come first and come from code**, so a host that saw an indicator is reported even if the judge fails.

### In the Daily Brief: FLEET ADVISORIES

Turn it on with `TRIAGE_ENABLED=1`. The daily digest then gains a **FLEET ADVISORIES** section:

- sightings first;
- then likely and possible items, each with its reason, facts and checks;
- one line for everything else;
- the day's model cost.

It triages any threat-intel message, whoever sent it, so a colleague's forward counts too. Supplier requests, W-9 and ACH threads, and auto-replies never reach a model. Advisories that name a CVE go to the existing CVE report. A failure costs the section, never the digest.

### New: `cti-falcon`, the fleet's view of CrowdStrike

| Command | What it does |
|------|----------|
| `cti-falcon --check` | Tests the read-only API client: one small read per scope, counts only, and revokes the token on exit. |
| `cti-falcon --find-app NAME` | Lists installed apps matching a name, with host, version and platform counts. |
| `cti-falcon --new-apps DAYS` | Lists apps first seen in the window that the estate never had before: **the systems nobody told us about.** |

Each app comes with what Falcon knows about the hosts running it: workstation, server or domain controller, internet exposure, criticality, and a **SUSPICIOUS** flag where Falcon marks the app. Browser extensions are now looked up too.

Version bumps no longer show up as "new" apps. Every skipped app comes with its reason, and a partial read says **WARNING: INCOMPLETE**. No host name or ID is ever printed.

You can also run triage by hand with `cti-triage`. The replay options (`--facts-file`, `--judgement-file`, `--show-judge-input`) let you rerun a verdict without paying for new model calls.

---

## The agent harness: an AI analyst you can trust to run unattended

The fleet's AI analyst, the check-in "heartbeat," has always had guardrails: an allowlist of tools, a guard on every command, wrappers instead of raw commands, and an alert channel it can't redirect. What it was missing was a way to tell whether it was *behaving*. 1.7 completes **the agent harness**, the four-part plan in `HARNESS.md` to close that gap.

| | Piece | What it answers | Status |
|-|-----|------|-----|
| **H1** | Beat traces (`fleet-trace`) | *What did the analyst actually do?* | Shipped in 1.6.1, made privacy-safe in 1.7 |
| **H2** | Evals (`task eval:checkin`) | *Does it make the right call?* | **New in 1.7** |
| **H3** | Checked verdict (`cti-checkin/1`) | *Is what it reports true?* | **New in 1.7** |
| **H4** | Shared model-lane library | *Does every AI lane follow the same rules?* | **New in 1.7** |

### H2: evals that test judgement, not plumbing

The fleet's tests always checked the plumbing, down to the exact tool allowlist. Nothing checked what the analyst *decides*. Until now, a change to its instructions, its tools or its model version shipped on trust.

`task eval:checkin` runs the **real** heartbeat against invented fleets. That means the real runner, guard, trace, board and memory, and the real `claude` CLI. Recording fakes stand in for anything that would touch systemd, Microsoft Graph or Qualys, so nothing is ever mailed. There are ten scenarios, drawn from real beat traces and the fleet's hard rules:

- a quiet day (it must stay quiet);
- the daily credential checks;
- a check that fails;
- lanes that aren't due yet;
- an escalation that has since been resolved;
- **an advisory carrying a prompt injection** (it must not act on it);
- a budget HOLD already raised (it must not escalate again);
- a check that contradicts its own lane;
- a failed digest;
- an overdue KEV.

Each scenario runs three times and is scored on behaviour from the trace, the fakes' call log, the board and the memory store, not on wording. The result is a pass rate. Only a critical failure fails the run.

**The recorded baseline:** 30 of 30 must-pass checks met and no critical failures, at 8 to 16 turns and $0.12 to $0.15 a beat. Any future change to the analyst's instructions, permissions or model gets compared against those numbers.

**The evals have already paid for themselves.** They caught the analyst trusting a misleading status line over the lane's own evidence. The fix went into the status line (`cti-mailer --check`), and the fix is in this release.

Evals cost real tokens and aren't deterministic, so they run by hand before a change, never on every push. Their cheap half, which checks that scenarios are valid and that fleets build and score, runs in `task test`. The supplier lane has its own equivalent, `task eval:supplier`, which runs 53 invented requests against the real model.

### H3: a verdict on every beat, checked against the facts

Every check-in now ends with one structured `cti-checkin/1` verdict:

- overall status: ok, attention, escalated or degraded;
- every lane's state;
- the alerts it sent;
- its board and memory writes;
- what it deferred;
- **whether it saw injected instructions.**

The verdict isn't taken on faith. The new `cti-checkin-verdict` parses it strictly and checks it against the counts the command guard kept during the beat, which the model can't touch. If the analyst says it sent one escalation, the guard must have seen exactly one. Each verdict is saved next to its trace. A missing, invalid or contradicted verdict is flagged on the board, at most once a day for each kind.

### H4: one set of rules for every AI lane

The heartbeat and the supplier judge now get their model-call controls from one shared library, `share/model-lane.sh`:

- find the `claude` binary, and on Linux trust it only if it is root-owned in a system location;
- validate the model name;
- require exactly one credential;
- scrub the model's environment;
- start the trace;
- enforce a timeout.

A control added for one lane is now automatically there for the next one, including advisory triage.

Moving the supplier lane onto the library showed exactly the drift it was built to stop. The supplier lane:
- accepted any `claude` on the PATH;
- didn't validate its model name;
- dropped one credential type, so boxes set up that way failed every judgement silently.

All three are fixed.

### H1, revisited: traces that keep decisions, not data

Beat traces shipped in 1.6.1. In 1.7 they keep what the analyst *did*: every tool call and its arguments, what was denied, the turns, tokens and cost. They no longer keep a copy of every email and advisory it read. See [Security](#security-hardening-the-fleet-itself) for the details.

### What we deliberately didn't do

- **No agent framework.** The harness adds no dependencies, so the no-dependency rule stands, and it keeps the permission model that PrimeSec has already reviewed.
- **No multi-agent sprawl.** One judgement agent oversees deterministic lanes. Delivery stays in code; only judgement belongs to the model.

---

## An audit trail: who did what, when

Every email sent or moved, every Jira ticket filed or changed, and every change to the owners data now writes one **RFC 5424 syslog line**. Each line records who did it, to what, when, and whether it worked. A run ID ties together everything one scheduled run did.

- **Where:** `/var/log/cti-agent/audit-YYYY-MM-DD.log`, one file per UTC day.
- **Kept:** 120 days by default (`AUDIT_RETAIN_DAYS`), pruned by the daily mailbox cleanup.
- **Shipping to a SIEM:** set `AUDIT_SYSLOG_ADDR=host:port` and the same lines go to your collector over TLS. Or point the collector at the files. Splunk, Elastic, Wazuh, rsyslog and syslog-ng all read this format.
- **Never written:** message bodies, subjects, ticket text or credentials.
- **Tamper-aware by design:** the heartbeat can't write to or delete the trail it is accountable to.

New command: `cti-audit --check` confirms the trail is writable and the collector is reachable.

---

## Security: hardening the fleet itself

This release closes a long list of findings from the PrimeSec AI guardrail review. Each fix is recorded in the CHANGELOG with the finding IDs it closes.

**Encryption in transit, everywhere.** All nine Go API clients now go through one HTTP helper:
- TLS 1.2 minimum;
- https only, refused before the request is sent, so a credential never travels in clear;
- no redirect to plain http.

The Python lanes share the TLS floor, and the mailer follows no redirects at all. A repo test fails the build if new code bypasses the helper.

**Models hold no secrets.** The model that judges supplier requests used to inherit every fleet credential: CrowdStrike, mail and Jira. It now gets only what it needs to run, and starts from an empty home folder, so files planted in the service account's home can't reach it.

**Models see less personal data.** The supplier judge no longer sees remittance addresses, payment terms, contact names or the sender's full address, only their domain. Everything that remains passes through a redaction step that strips tax IDs, bank account and routing numbers, IBANs and card numbers. The people who review the request still get the full form.

**Sender trust, done properly.** `FLEET_SENDER_AUTH=off` used to trust *every* sender, forged or not, and it is gone. In its place, `FLEET_UNAUTHENTICATED_SENDERS` lists the exact domains to accept when a mail gateway hides the real sender. Each acceptance is recorded in the audit trail. ***Action may be required:*** see [Before you upgrade](#before-you-upgrade).

**Threat intel is judged by content, not sender.** A forwarded advisory counts. A forged "feed" email with no threat content in it doesn't get a model's attention.

**Heartbeat traces keep decisions, not mail.** Check-in traces no longer keep a 14-day plaintext copy of everything the analyst read. By default they keep what the model said and did. Tool results are replaced with their size and a fingerprint. Set `CHECKIN_TRACE_KEEP=full` temporarily for an investigation.

**Every write is validated.** The budget ledger, processed-message log and delivery log share one safe writer that refuses impossible values, such as a cooldown set to the year 9999. Every `fleet-db` write command checks its arguments and gives a clear refusal instead of a Python traceback. When reading, the fleet repairs what it can and says what it repaired, so a clock that steps back can't stop every lane.

**Supply chain you can prove.** Every `task ship` writes a **CycloneDX 1.5 SBOM** and fails if a third-party dependency has crept in. Every GitHub Release now has its SBOM attached.

---

## VM scan weekly: built for the network team

1.7 includes the 1.6.7 rework of the weekly VM scan report.

**Straight from Qualys.**
- **Which scans ran** now comes from the Qualys API, not from scan-complete emails. A scan whose notice was lost (as in the 13 November Microsoft outage) is still reported and still counts.
- **Which scans should have run** comes from Qualys's own scan schedules. A schedule that launched nothing leads the report as **[NO RESULT]**. `VMSCAN_SCANS` is no longer needed.
- **Every scheduled scan is reported, whatever it's called.** A rename in Qualys no longer turns into "0 covered, 65 gaps."

**Coverage that matches the real network.** The check now finds each location's 10.X.30 network whatever its label (`corp`, `inside`, `Employee LAN`). "Decommissioned" only counts at the start of a location's header, either spelling.

**Spreadsheet fixes become one help-desk ticket.** Rows the coverage check can't read go to the help desk as one unassigned Jira ticket, for routing to the network team. The ticket is commented on only when the list changes. A clean-up section flags:
- overlapping networks;
- out-of-block rows;
- duplicate public IPs;
- misspelled headers.

The weekly email names the ticket and says what happened to it this week.

**Says what it counts.** "Locations covered" is now "Asset Groups targeted," because that's what it measures. New "check in Qualys" lines flag Asset Groups that only cover decommissioned sites, and Asset Groups that no scan targeted.

---

## Daily Brief: every fleet ticket, in one place

**FLEET TICKETS** now lists every ticket the fleet files:
- the network team's spreadsheet ticket, next to the domains lock-down ticket;
- one TPRM line for open supplier-request tickets;
- any new lane's tickets automatically.

It also stays populated on days when the scanner won't load.

---

## Operations and tooling

- **GitHub Releases for every tag**, with notes taken from the CHANGELOG and the SBOM attached. Older tags can be backfilled.
- **The installer checks real connectivity** in one section after config: the fixed hosts first, then every host `fleet.env` names (Qualys pod, Jira, CrowdStrike, GoDaddy, Proofpoint, Anthropic). It used to promise this check and never run it.
- **`cti-mailer --check`** now reports the owner lane the way the lane itself decides it, rather than a misleading "unset" warning.

---

## Fixes

- FLEET TICKETS is no longer empty on days the scanner won't load.
- A nested slot marker in scanned page text can no longer plant a second ticket line in the domains report.
- The weekly's FLEET TICKETS heading no longer claims a re-check it didn't do.
- A week with no scheduled scan no longer reports every location as unscanned.
- The installer no longer prints "disabled" twice for a disabled timer.

---

## Before you upgrade

**Most boxes: just run the update.**

```bash
sudo cti-agent-update --for-real
```

**Action required if `FLEET_SENDER_AUTH=off` is set:**

```bash
grep FLEET_SENDER_AUTH /etc/cti-agent/fleet.env
```

If it prints `off`, add `FLEET_UNAUTHENTICATED_SENDERS=` followed by the scanner's From domain (for example `qualys.net`), and the feed domains if triage is on. Then remove the old line. Until you do, scan notices are reported as unauthenticated and feed mail is no longer trusted.

**Other things to check:**

- **Supplier lane:** the model must now authenticate with `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` in `fleet.env`, because a login stored in the service account's home is no longer seen. If the heartbeat already works on the box, nothing changes.
- **VM scan:** if `VMSCAN_SCANS` lists the old scan titles, remove it.
- **Advisory triage (optional):** create the read-only CrowdStrike API client, add the three `FALCON_*` settings, then run:

  ```bash
  sudo cti-agent cti-falcon --check
  ```

  Then set `TRIAGE_MODEL`, and `TRIAGE_ENABLED=1` when you're ready for FLEET ADVISORIES.
- **SIEM (optional):** set `AUDIT_SYSLOG_ADDR`, then run:

  ```bash
  sudo cti-agent cti-audit --check
  ```
- **Any URL in `fleet.env` or `feeds.txt` that starts with `http://`** is now refused. Change it to `https://`.

Full detail, including every PrimeSec finding ID closed, is in the CHANGELOG under 1.6.7 and 1.7.
