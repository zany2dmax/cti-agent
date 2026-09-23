# SECURITY

The threat model, trust boundaries and security-relevant design decisions for
this repository.

This file is longer than a disclosure policy because the system it describes
holds credentials to a mail tenant and a vulnerability scanner, writes a
document that names exploitable machines, modifies a shared mailbox
unattended, and is being extended to pass attacker-authored text to a model.
Each of those deserves an explicit answer rather than an assumption.

Sections describing work that is designed but not built are marked as such.
A threat model that claims controls it does not have is worse than none.

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [What this system handles](#what-this-system-handles)
- [Trust boundaries](#trust-boundaries)
- [AI triage: untrusted input reaching a model with tools](#ai-triage-untrusted-input-reaching-a-model-with-tools)
- [Data sensitivity: the report is a targeting list](#data-sensitivity-the-report-is-a-targeting-list)
- [Credentials and secrets](#credentials-and-secrets)
- [Microsoft Graph permissions](#microsoft-graph-permissions)
- [The send gate](#the-send-gate)
- [Autonomy gates](#autonomy-gates)
- [Mailbox modification](#mailbox-modification)
- [Supply chain](#supply-chain)
- [Host hardening](#host-hardening)
- [Build and release gates](#build-and-release-gates)
- [Output handling](#output-handling)
- [Failure philosophy](#failure-philosophy)
- [Known gaps and accepted risks](#known-gaps-and-accepted-risks)
- [If you are deploying this yourself](#if-you-are-deploying-this-yourself)

---

## Reporting a vulnerability

Open a GitHub security advisory on this repository, or contact the maintainer
privately. Please do not open a public issue for anything exploitable.

Include what you did, what happened, and what you expected. A proof of concept
is welcome but not required.

---

## What this system handles

Four things, each with a different worst case:

| Asset | Worst case if it leaks or is abused |
|---|---|
| Entra app credentials (`CLIENT_SECRET`) | read, and depending on grants send and move, mail across a tenant |
| Qualys API credentials | read access to the organisation's complete vulnerability posture |
| Generated reports | a list pairing "this CVE is exploitable" with "these machines have it" |
| The shared CTI mailbox | a security team's reporting inbox, read by several people |

The reports are the asset people underestimate. They are not a summary of
public advisories; they are the intersection of public exploitability with
private asset inventory, which is precisely a targeting list.

---

## Trust boundaries

Everything crossing into this system from outside is untrusted, and the
degrees differ:

| Input | Source | Trust | Handling |
|---|---|---|---|
| CTI advisory emails | third parties, via a shared mailbox | **untrusted** | parsed for indicators; HTML escaped before rendering; never executed |
| Vendor wrap-up pages (Qualys blog, BleepingComputer) | public internet | **untrusted** | fetched over HTTPS, parsed, escaped |
| NVD, EPSS, CISA KEV | public internet | **untrusted but reputable** | parsed as JSON, values escaped |
| Qualys API responses | our scanner, over the network | **semi-trusted** | XML parsed; host names treated as sensitive output |
| Microsoft Graph responses | our tenant | **semi-trusted** | message bodies are third-party content and stay untrusted |
| `fleet.env` | the operator | **trusted** | it holds the credentials; whoever can write it already controls the process |
| Environment from systemd | the host | **trusted** | same reasoning |

The consequence worth stating plainly: **an email body is attacker-controlled
input.** Anyone can send mail to a published security address. Every design
decision downstream of the mailbox assumes the sender is hostile.

---

## AI triage: untrusted input reaching a model with tools

> **STATUS: DESIGN. NOT YET IMPLEMENTED.**
> No code in this repository does any of what this section describes. It is
> written down before the build so the trust boundaries are agreed first, and
> so that a later change cannot quietly hand the analysis agent a capability
> this section rules out. Read every "must" below as a requirement on work not
> yet done, not as a description of a control that exists.

This is the newest and sharpest boundary in the system, and the one most
likely to be got wrong by a well-meaning change. The agent's standing
instructions are written and reviewable at
[`fleet-kit/fleet/agents/triage/CLAUDE.md`](fleet-kit/fleet/agents/triage/CLAUDE.md);
the organisation profile it reads to judge relevance is a hand-written
template at
[`ORG-PROFILE.md`](fleet-kit/fleet/agents/triage/ORG-PROFILE.md), and is
deliberately categories rather than inventory, because the repository is
public.

### The problem

CVE-keyed automation misses a large fraction of real threat intelligence.
A representative daily roundup from a commercial feed contained seven items;
**four carried no CVE at all** — an autonomous-agent campaign against
retailers, a rogue-MFA-provider technique against Entra ID, a claimed
zero-day with no assigned identifier, and a malicious package. A pipeline
that keys on `CVE-\d{4}-\d{4,}` sees none of it.

Fixing that with per-sender template parsers fails two ways: it is a treadmill
against every new feed, and a template that stops matching returns zero items,
which is indistinguishable from a quiet day. So the analysis is done by a
model, which needs no template and handles a one-off warning from a peer as
well as a formatted roundup.

That means **text written by an unknown third party is passed to a model.**
If that model has tools, the content is trying to use them.

### Why a separate agent, not the orchestrator

The fleet already runs an orchestrator agent on a heartbeat. It would be the
convenient place to put this. It is the wrong place.

The orchestrator holds the most authority in the fleet: it writes the message
board, escalates to the operator, spends the model budget, and invokes the
mailer. Handing attacker-authored content to the component with the most
privilege inverts least privilege.

The analysis agent must therefore be **separate, with its own standing
instructions and its own — much smaller — set of permissions**:

| | Orchestrator | Analysis agent |
|---|---|---|
| Read the mailbox | yes | **no** — it is handed a prepared file |
| Send mail | via the mailer | **no** |
| Write the message board | yes | **no** |
| Shell / arbitrary commands | limited | **no** |
| Network access | yes | **no** |
| Filesystem | fleet state | **one input file, one output file** |

If the analysis agent is fully subverted by a crafted advisory, the worst case
must be a wrong JSON document, validated by code that does not trust it.

This is not hypothetical. The campaign that prompted this design documents the
attackers running a purpose-written skill to strip their own harness's content
filters, and falling back to an older model after newer ones refused. The
defence cannot be "the model will decline."

### Deterministic floor, model ceiling

Code does the extraction and keeps the trust boundary. The model does the
judgment. Neither substitutes for the other.

**Floor** — regex over stripped text, always runs, no model: CVE IDs, MITRE
technique IDs, defanged indicators, links, counts. If everything else fails,
the digest still reports *that* non-CVE intelligence arrived and what raw
artifacts it contained. Today only the CVE half of this floor exists, in
`internal/cti`; the rest is unbuilt.

**Ceiling** — the model: how many distinct items, what each is about, and
whether it plausibly matters to this organisation.

A model that is unavailable, rate-limited, timed out, or returning malformed
output degrades to the floor **and says so in the output.** The digest never
waits on it and never fails because of it.

### Four controls that make non-determinism acceptable here

1. **The model must annotate, never gate.** Every non-CVE item reaches the
   digest regardless of what the model concludes about it. A model deciding
   something is irrelevant, and being wrong, must not be able to make it
   disappear. Suppression must not be a capability the analysis agent has.

2. **Output must be verified against the source text.** Every indicator the
   model reports must appear verbatim in the message it was given, or be
   dropped and flagged — that kills hallucinated indicators. Every indicator
   the regex floor found that the model omitted must be reported anyway — that
   kills silent omission. The model must be unable to add facts or quietly
   remove them.

3. **Output must be schema-validated.** Anything that does not parse is a lane
   failure, reported as such. It must never be treated as an empty result.

4. **Output must be escaped on render**, the same as every other third-party
   string that reaches an email from this system.

### Instruction-injection posture

Content from the mailbox must be delivered to the agent as **data inside a
delimited block**, with standing instructions that text within it is evidence
to be analysed and never instructions to be followed. That is a mitigation,
not a guarantee — which is why it is the *fourth* line of defence, behind
having no tools to hijack, no ability to suppress, and mechanical verification
of the output.

If a future change gives the analysis agent a tool, the question to answer
first is: *what does a crafted advisory make that tool do?*

---

## Data sensitivity: the report is a targeting list

A generated report pairs exploitability with named machines. Treat it as such.

- Written mode **0600** by the Go commands — reports, state files, manifests
  and the processed-message log, with tests asserting the mode.
- Excluded by `.gitignore` — `reports/`, `digest-*.html`, `enriched-*.json`,
  `*-vuln-report.md` and others.
- Mailed only to addresses on an allowlist.
- Carries a "do not commit" banner when it contains real hostnames.

**The Python lanes rely on the unit's umask.** `brief.py` and `enrich.py`
write the digest HTML, the digest text and `enriched-*.json` — which carries
host names — with a bare `open(path, "w")` and no `chmod`. Every service unit
now sets `UMask=0077`, so those land `0600` too. Run a lane outside systemd
and it inherits your shell's umask instead, which is worth remembering when
replaying by hand.

`REPORT_HOSTNAMES` controls disclosure:

| Value | Output |
|---|---|
| `full` *(default)* | real hostnames |
| `redact` | stable pseudonyms. Irreversible only **with** `REPORT_REDACTION_SALT` set — see below |
| `count` | host counts only |

**The default is `full` deliberately**, and the reasoning is worth keeping:
a pseudonym cannot be looked up in the scanner, so a redacted report says a
critical finding exists without saying where, and somebody has to rerun the
pipeline to act on it. An unactionable security report is not a safe security
report. The controls that make that defensible are the file mode, the
gitignore and the allowlist — not obscurity.

**Set `REPORT_REDACTION_SALT` if you use `redact`, and treat it as required
rather than optional.** The salt has no default. Without it a pseudonym is an
unsalted truncated hash of the host name, which anyone holding a list of
candidate names can confirm by hashing them — and corporate naming schemes are
small enough to brute-force. The report prints a warning banner when the salt
is unset, but the pseudonyms in it are not meaningfully protective.

---

## Credentials and secrets

- All credentials live in one file — `fleet.env` in production, `.env` in a
  checkout — never in code, never in systemd unit files, never in arguments.
- `internal/fleetenv` is the single reader, so a run by hand gets the same
  configuration as a run by systemd, and there is one place to audit.
- **No default mailbox and no default recipient.** An unconfigured install
  refuses to start rather than guessing an address.
- Each command validates only the credentials it uses, so a missing-variable
  error names things that are actually required.
- On Fedora the installer relabels for SELinux. A `fleet.env` staged in a home
  directory and moved into `/etc` keeps its original label and systemd cannot
  read it, which presents as every timer failing while manual runs work.

**Git history is permanent.** A credential committed once should be treated as
compromised and rotated, not deleted. `scripts/scrub-history.sh` exists for
rewriting history, but rewriting is remediation, not prevention — forks,
clones and caches may retain what was pushed. The scrub pattern file is itself
gitignored.

---

## Microsoft Graph permissions

Three application permissions, each optional except the first:

| Permission | Needed by | Notes |
|---|---|---|
| `Mail.Read` | reading the CTI mailbox | not needed if you grant `Mail.ReadWrite`, which supersedes it |
| `Mail.Send` | sending digests and alerts | required by `mailer.py --check`; omit only if you want markdown reports and nothing else |
| `Mail.ReadWrite` | mailbox cleanup only | omit if you are not running that lane |

**Application permissions are tenant-wide by default.** `Mail.Send` means the
app can send as any mailbox in the tenant; `Mail.ReadWrite` means it can read
and move mail in any of them. Confine the app with an Exchange Application
Access Policy — or RBAC for Applications — **before** granting, not after.
The policy is scoped to the app, so it covers permissions added later.

**Nothing in this codebase can permanently delete mail.** `internal/graph`
implements move-to-folder and nothing else; Graph's `DELETE /messages/{id}`
and the purge endpoints are deliberately absent. "Delete" means Deleted Items,
which is recoverable, and emptying that folder stays a person's job.

`mailer.py --check` decodes the token and reports which roles were actually
granted, including any that are consented but unused. Consent is the step
people skip, and an unused permission is standing risk with no benefit.

---

## The send gate

`FLEET_ALLOW_TO` is an allowlist enforced in code, not a convention:

- It covers **To and Cc**. Exempting Cc would make the control trivially
  bypassable — a header name does not change who receives the findings.
- A recipient outside it refuses the send and names the address.
- A one-off requires an explicit `--approve`.
- There is no default recipient anywhere in the system.

### There are two outbound paths, and only one is gated

`mailer.py` is the path for every digest and report, and it is gated as above.
No lane sends mail directly; the orchestrator invokes the mailer rather than
reimplementing it.

**`cti-alert` is the exception.** It calls Graph `sendMail` directly
(`cmd/cti-alert/main.go`), because the thing it reports on may be the mailer
itself — an alerter that depends on the component it alerts about is not an
alerter. It is **not** subject to `FLEET_ALLOW_TO`. Its recipient is
`FLEET_OPERATOR_EMAIL`, falling back to `DIGEST_TO`, and its body embeds up to
40 lines of `journalctl` output, which can contain host names, paths and
logged subjects.

Two consequences worth being deliberate about: set `FLEET_OPERATOR_EMAIL`, so
the fallback to the whole distribution list never happens; and treat alert
mail as carrying the same sensitivity as a report.

---

## Autonomy gates

The orchestrator runs unattended. Its standing instructions
(`fleet-kit/fleet/CLAUDE.md`) prohibit, among other things:

- sending mail to anyone outside the allowlist, or adding to it
- `--for-real` on mailbox cleanup — the timer does that, not the agent
- `cti-patchtuesday --mark-sent`, which asserts an email reached people and
  causes the daily digest to suppress a release's CVEs
- creating or modifying tickets, scanner configuration, scans or exceptions
- deleting anything outside the log and archive directories
- anything touching a production host

Auto-sending is limited to scheduled reports on an established schedule to an
allowlisted list. Everything else is proposed on the message board and waits.

Model usage is rationed by `cti-budget` — window and daily ceilings with
exponential backoff — so an agent loop cannot consume a shared subscription.

---

## Mailbox modification

`cti-mailbox` is the only component that modifies the mailbox, and it runs on
a timer with nobody watching. Four properties follow:

1. **Dry run is the default.** Moving requires `--for-real`, which the unit
   file passes explicitly. A flag that must be added to cause an effect cannot
   be triggered by a misconfigured unit.
2. **It cannot permanently delete.** See the Graph section above.
3. **It acts only on messages a completed run recorded as processed.** No
   record, no move — that log is its entire authority.
4. **Only two kinds of message move**: an advisory the agent took a CVE from,
   and a message whose own headers declare it an automatic reply. Everything
   else is left where a human can see it.

Rule 4 is a security property, not tidiness. The mailbox is a shared reporting
address: it receives phishing reports from colleagues, alerts, and ordinary
mail. "The agent read it looking for CVEs and found none" is not "this has
been dealt with," and filing a colleague's phishing report before anyone
triaged it is the most damaging thing this lane could plausibly do.

Auto-reply detection is **headers only** — `Auto-Submitted: auto-replied`,
`X-Auto-Response-Suppress`. Subject text does not delete mail, because a
subject is trivially forged.

---

## Supply chain

**`go.mod` has no dependencies.** The Go binaries are standard library only.
The Python lanes are standard library only — no `pip install`, no
`requirements.txt`, no virtualenv on the deployment host.

That is a deliberate security position, not minimalism for its own sake: no
transitive dependency tree to audit, no dependency-confusion surface, no
package-repository compromise in the build path, and nothing to update when a
popular library has an advisory.

The cost is more code written here. The benefit is that `govulncheck` has a
small and comprehensible surface — which matters, because this system parses
untrusted HTML and XML from the public internet through `encoding/xml` and
`net/http`. An advisory in either is a live finding for this repository.

---

## Host hardening

The Fedora units are not just `ExecStart` lines. Each service runs with
`ProtectSystem=strict`, an empty `CapabilityBoundingSet`,
`SystemCallFilter=@system-service`, `RestrictAddressFamilies` limited to what
the lane needs, `NoNewPrivileges`, `PrivateTmp` and a `StateDirectory` with
mode `0750`, under a dedicated service account that owns nothing else.

SELinux is left enforcing. The installer relabels `/etc/cti-agent`,
`/opt/cti-agent` and `/var/lib/cti-agent` on every run and fails verification
if `fleet.env` does not match policy, because a config file staged in a home
directory and moved into `/etc` keeps its original label — which presents as
every timer failing while manual runs work, with an empty journal.

Every unit sets `UMask=0077`, so a lane that writes with a bare `open()` and
no `chmod` — which both Python lanes do — cannot leave a group-readable file
behind.

---

## Build and release gates

`task ship` is the only thing that pushes, and it stops at the first failure:

```
fmt → build → test → lint → scan → gosec → govulncheck → push
```

It exists because a push once outran a red test when the two were separate
commands.

**Static analysis policy.** There is no blanket exclusion list. A finding is
either fixed or annotated at the line with the reason it is intentional
(`#nosec RULE -- reason`, `//nolint:linter // reason`). A suppression whose
justification lives in a config file is one nobody re-examines.

`scripts/nosec-audit.py` reports `#nosec` annotations that suppress nothing —
a suppression that has outlived its finding is a comment claiming a review
that no longer happens.

Linter output limits are set to report everything. The defaults truncate, and
a run once reported three occurrences of an issue that had twenty-six.

---

## Output handling

- **HTML escaping** on every third-party string that reaches an email —
  advisory text, product names, subject lines, org names.
- **URL scheme allowlist** on the one link that is operator-configurable: an
  attribution URL that is `javascript:` or `data:` is dropped. Every other
  rendered link is built from a constant `https://` prefix or a regex that
  pins the scheme — safe by construction rather than checked at render, which
  is worth knowing before someone adds a link from a parsed source.
- **Log injection (CWE-117)**: log calls in the ingest lane that carry outside
  text pass through a sanitiser that replaces control characters, so a newline
  in a path or a parse error cannot forge a journal record. A forged record in
  the journal an operator reads to diagnose a failure is worth more to an
  attacker than it looks. Two gaps remain, listed under known gaps: the final
  `fmt.Printf` lines in the ingest lane, and `cti-mailbox`, which prints
  attacker-controlled subject lines straight to the journal.
- **Subject lines**: the Patch Tuesday subject is ASCII by construction and
  tested for it, so no gateway or inbox rule can be broken by a character in
  it. The daily digest subject, built in `brief.py`, is **not** — it can
  contain an em dash. That is the subject most likely to have a rule keyed on
  it, so it is a gap rather than a nuance.

---

## Failure philosophy

This matters enough to be a security property in its own right.

**Every failure in this system falls toward reporting more, never less.** A
missing release manifest, an unreadable state file, an absent `FLEET_HOME`, a
scanner that cannot be reached, a model that will not respond — each results
in more output, louder output, or clearly-labelled missing output. None
results in silence.

**"Not measured" and "measured, nothing found" are never rendered alike.** The
exposure reporting distinguishes four states — not attempted, not yet
measurable, measured and clean, and a real finding — because a report that
cannot tell them apart will print the reassuring one.

**A failed unit is loud.** `cti-alert` emails the operator and posts to the
message board. It exits 0 on every path systemd can reach, so the alerter's
own unit never appears failed and makes `systemctl --failed` misleading. It
exits 2 only on a usage error — no unit named — which the templated unit
cannot produce.

The recurring defect class in this codebase has never been a crash. It has
been a check that ran and had no effect, or a refusal indistinguishable from a
quiet day. Reviews should be read with that in mind: **when output looks
unusually clean, verify the component did work — not that it exited 0.**

---

## Known gaps and accepted risks

Stated rather than discovered. Everything here was found by fact-checking this
document against the code; several are worth fixing and are not yet fixed.

**Fixed since this document was written**

- ~~The Python lanes write world-readable files.~~ `UMask=0077` is now set in
  every service unit, so a lane writing with a bare `open()` cannot land a
  group- or world-readable file. Existing files on a deployed host keep their
  old mode until rewritten — `chmod 0600` the state directory once.
- ~~`cti-mailbox` logs attacker-controlled subject lines unsanitised.~~ The
  sanitiser moved to `internal/safelog` and both lanes use it; its truncation
  is rune-safe rather than byte-slicing.

**Worth fixing**

- **The daily digest subject can contain a non-ASCII character** (an em dash
  from `brief.py`), unlike the Patch Tuesday subject, which is tested for
  ASCII. Inbox rules are keyed on subjects.
- **The alert path is not recipient-gated** and falls back from
  `FLEET_OPERATOR_EMAIL` to `DIGEST_TO`, so a misconfiguration can mail
  journal excerpts to the whole distribution list.
- **Three `fmt.Printf` calls at the end of the ingest lane** print a
  configured path without the sanitiser the `log` calls in the same file use.
  They reach the journal identically.
- **`mailer.py --attach` has no path allowlist.** The send gate covers
  recipients, not payloads; any readable file up to 3 MB can be attached.
- **A comment in `.gitignore` claims `internal/report` redacts by default.**
  It does not — the default is `full`. Someone reading that comment will draw
  the wrong conclusion about what a stray report contains.

**Accepted, with reasons**

- **`REPORT_HOSTNAMES` defaults to `full`.** Reasoned above: an unactionable
  report is not a safe report. The compensating controls are the file mode,
  the gitignore and the allowlist.
- **No secret scanning in the build gate.** `task ship` does not run one.
  Prevention rests on `.gitignore` and review; `scripts/scrub-history.sh` is
  remediation, and remediation is late.
- **The Application Access Policy is the operator's job.** No code here can
  verify the app is confined to one mailbox. `mailer.py --check` reports
  granted roles, not tenant scoping.
- **The orchestrator's prohibitions are instructions, not enforcement.** They
  live in a markdown file the agent reads. The controls that are actually
  enforced are the ones in code: the send gate, dry-run defaults, the absence
  of a delete verb.
- **Model-based triage will be non-deterministic.** The controls designed for
  it are compensating, not eliminating. A model can still be wrong about
  relevance — which is why it must not be able to suppress.
- **Eleven `#nosec` annotations exist**, each inline with its reason: six
  G304, three G706, one G204, one G306. `.golangci.yml` has no exclusion list.
  `scripts/nosec-audit.py` reports any that suppress nothing.
- **One installer path is built but not verified.** The ingest binary is built
  to `$CTI_AGENT_DIR`, outside the directory the installer's verification loop
  checks, so a lane can run older code than everything around it. Check its
  mtime after a deploy.
- **`internal/report.escape()` escapes only the pipe character**, enough for a
  markdown table cell but not general escaping. That output is attached as
  markdown, not rendered as HTML.
- **This repository is public.** Nothing internal — hostnames, addresses,
  identifiers, reports — belongs in a commit. Sample output is synthetic, and
  git history is permanent.

---

## If you are deploying this yourself

A short checklist, in order:

1. Create the Entra app with **only** the permissions you will use.
2. Apply an Application Access Policy confining it to the CTI mailbox, and
   verify with `Test-ApplicationAccessPolicy`, **before** granting consent.
3. Set `FLEET_ALLOW_TO` **and** `DIGEST_TO` before the first send. There is no
   default address anywhere, so an install with neither refuses rather than
   guesses — but note that leaving `FLEET_ALLOW_TO` unset does not refuse: it
   falls back to `DIGEST_TO`, and `FLEET_OPERATOR_EMAIL` is always allowed.
   The gate is only as narrow as those two variables.
4. Set `FLEET_OPERATOR_EMAIL`, so alert mail never falls back to the whole
   distribution list.
5. Decide `REPORT_HOSTNAMES` deliberately, and set `REPORT_REDACTION_SALT` if
   you choose `redact` — without it the pseudonyms are not protective.
6. Add `UMask=0077` to the units, so the Python-written digest and enriched
   JSON are not group-readable.
7. Confirm `fleet.env` is `0600`, owned by the service account, and correctly
   labelled if SELinux is enforcing.
8. Run every lane with `--dry-run` and read the output before enabling a timer.
9. For mailbox cleanup specifically, dry-run for several days and confirm the
   archive list contains nothing but advisories before `--for-real` goes
   anywhere near a timer.

The operational detail for each step is in [RUNBOOK.md](RUNBOOK.md).
