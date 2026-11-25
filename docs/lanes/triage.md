# Advisory triage

The CrowdStrike API client advisory triage reads, and running triage by hand.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [11j. The CrowdStrike API client](#11j-the-crowdstrike-api-client)
- [11k. Advisory triage by hand](#11k-advisory-triage-by-hand)

---

## 11j. The CrowdStrike API client

Advisory triage will read from CrowdStrike Falcon: which applications we run,
which hosts saw an indicator, and which ATT&CK techniques our detections fired
on. That part isn't built yet. What exists is `cti-falcon --check`, which
proves the API client works before anything depends on it.

**Create the client** in the Falcon console: Support and resources > Resources
and tools > **Client Management** > Create API client. Name it
`cti-agent-fleet`, and tick **Read** only for:

| Scope | What triage uses it for |
|---|---|
| Hosts | host name, OS and last-seen for a host ID |
| Assets | installed applications per host (Falcon Discover) |
| IOC Management | which hosts saw a domain, IP or hash |
| Alerts | detections and their ATT&CK techniques |

Tick no Write box, and not the older **IOCs** scope: its routes are retired.
The secret is shown once. Put it in 1Password, then into
`/etc/cti-agent/fleet.env`, together with the base URL shown next to it:

```
FALCON_BASE_URL=https://api.us-2.crowdstrike.com
FALCON_CLIENT_ID=...
FALCON_CLIENT_SECRET=...
```

Only the four published API hosts are accepted (US-1, US-2, EU-1, GovCloud).
Anything else is refused before a request is made, so a typo can't send the
secret somewhere else.

**Check it:**

```bash
sudo cti-agent cti-falcon --check
```

It gets a token, then makes one `limit=1` read per scope on the exact route
triage will call. It prints OK, DENIED or ERROR for each, with a count at
most, and revokes its token before it exits. It exits 0 only when all four
work. It never prints the token, the secret, an ID or a record.

| What you see | What it means |
|---|---|
| `token : FAILED ... HTTP 401` | The client ID or secret is wrong, or the client was deleted. |
| `token : FAILED ... this API client is in eu-1 - set FALCON_BASE_URL=...` | The client lives on another cloud. Use the host it names. |
| `token : FAILED ... HTTP 403` | The client may restrict which IP addresses can use it. Allow the box's address. |
| `Assets: READ DENIED` | The scope isn't ticked, or, if it is, Falcon Discover / Exposure Management isn't licensed. The inventory then comes from Qualys and Entra only. |
| `IOC Management: READ OK ... no hosts for the test value` | Expected. The probe asks about `example.com`, a reserved name no host should have seen. |
| `IOC Management: READ ERROR ... HTTP 404` | The route answered 404 without the service's own JSON, or the message is about the route. The lookup triage needs doesn't work. Check the scope, then whether CrowdStrike has moved the route. |

**What we run (Falcon Discover).** Discover keeps one record per application
per host, hundreds of thousands of them, so nothing copies it wholesale. Two
read-only questions instead:

```bash
sudo cti-agent cti-falcon --find-app chrome
sudo cti-agent cti-falcon --find-app "Google Chrome" --exact --vendor "Google LLC"
sudo cti-agent cti-falcon --new-apps 1
sudo cti-agent cti-falcon --fields
```

- `--find-app` answers "do we run this?": each matching application with its
  host count, top versions and platforms. Over `--max-rows` (2,000 records by
  default) it says the counts are a lower bound. This is the lookup triage
  will make when an advisory names a product.
- `--new-apps 1` answers "what appeared today that we never had?". It reads
  the records first seen in the window, groups them, and asks for each whether
  the same vendor had it before the window: first by the exact name, then, if
  the name carries a version number (`Microsoft .NET 8.0.34 - Windows Server
  Hosting`), by the same name at any version. An earlier record counts only if
  its name differs in the version numbers alone, so `Zoom Rooms` never makes a
  new `Zoom 6.1` look known. Up to 500 apps, 4 lookups at a time.
- A browser extension has no vendor in Discover. It's looked up by name
  among extensions only (a software type containing "extension"), so a
  desktop app of the same name can't make it look known. Any other app with
  no vendor is not checked. The limit: Discover gives no publisher for an extension, so a
  malicious extension that copies the exact name of one already installed
  counts as seen before. Falcon's `SUSPICIOUS` flag is the check on that.
- It lists the **new** ones, and the ones it **could not check**, by reason,
  which you should treat as possibly new: no vendor and not an extension (a
  name-only lookup would match look-alikes), over the 500 cap, a name holding a quote, backslash,
  `*` or control character, or a lookup the API rejected. One rejected
  lookup marks that one app, never the whole run. Updates and new hosts for
  something we already run are only counted.
- Two limits, both erring towards "new". The any-version match reads up to
  300 earlier records, so a product with many look-alikes from the same
  vendor can be called new when it isn't. Only a short list of build tags
  (`-x64`, `-beta`, `rc1` and so on) can follow a version number, so
  `Agent 2.0-client` is never matched with `Agent 1.0-server`.
- **Run it daily, `--new-apps 1`.** About 32,500 records were first seen in
  one week of November 2026, more than the 10,000 it reads by default. When it
  can't read the whole window it prints `WARNING: INCOMPLETE` with the share
  it did read. Apps first seen in the rest are missing from every list.
- Both modes show, per app, what Falcon knows about the hosts: **host type**
  (workstation, server, domain controller), **exposure** (Falcon's internet
  exposure) and **criticality**. Each line appears only when Falcon gave a
  value. **`SUSPICIOUS`** appears when Falcon flags the application itself.
  An app already in the estate that Falcon flags is listed under its own
  heading, never only counted.
  The software type is shown in brackets when it isn't a plain application.
- `--fields` prints the field names of one Discover record, with their types
  and never their values. Use it to see where a field lives. It was added
  because the platform came back `unknown`.

Names typed or found in advisories are hostile input to the filter. For
`--find-app` only
letters, digits, space and `. _ - ( ) / &` are allowed, 2 to 80 characters.
Anything else, including `+`, `*` and `,`, is refused before any request, so a
name can't add a clause to the query. For an app like `Notepad++`, search for
`notepad`. The exact lookups `--new-apps` makes use names Discover itself
returned, which carry `®`, `+`, `:` and non-Latin scripts. They're checked
only for the characters that could leave the quoted filter value (quote,
backslash, `*`, control characters). Names coming back from Discover are cleaned of control characters
before they're printed. Neither mode ever prints a host name or ID.

---

## 11k. Advisory triage by hand

`cti-triage` is advisory triage: it turns one advisory into facts from our
own tools (phase 3), and `--judge` weighs them (phase 4). By hand it writes
nothing. With `TRIAGE_ENABLED=1` the daily digest runs it on every message
with no CVE and lists the result under FLEET ADVISORIES (see "In the daily
digest" below).

**Set up** in `/etc/cti-agent/fleet.env`, next to the `FALCON_*` settings:

```
TRIAGE_MODEL=sonnet
TRIAGE_BLIND_SPOTS=sites without the Falcon sensor; servers outside Falcon
```

The reader runs with a stripped environment and an empty home directory: no
Falcon secret, no mail credentials, and no `.claude` folder (the fleet's home
holds the orchestrator's). So it needs `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN` in `fleet.env`, as the timers already use. A login
stored under a home directory isn't seen.

`TRIAGE_BLIND_SPOTS` is your own words for what Falcon can't see. It's
printed on every fact sheet, so "not installed" never reads as "not affected".

**Run it** on an advisory saved as a text file (paste the mail body):

```bash
sudo cti-agent cti-triage --show-input --message adv.txt
sudo cti-agent cti-triage --facts --message adv.txt --subject "the mail's subject"
```

What happens:

1. **Code extracts** CVEs, ATT&CK IDs, defanged indicators and links (no
   model).
2. **The reader**, a model started with no tools, sees only the advisory. It
   names the vendors, products, versions and techniques it concerns. It never
   sees our data, so a poisoned advisory can at worst make it name a wrong
   product.
3. **Code removes** every claim the advisory doesn't support: a product,
   vendor or fixed version not in the text as a whole word (`1.0` doesn't
   count because `131.0` is there, nor `SQL` because `MySQL` is), a product
   too short or too common to look up, a quote not in the text word for
   word, a technique that isn't an ATT&CK ID. Techniques the reader added are
   marked *inferred*. The title, affected-versions text and any refusal
   reason are printed as the reader's words.
4. **Falcon lookups**, capped per advisory (5 products, 25 indicators, 10
   techniques), each value re-checked for its exact shape first:
   - **Products**: installed apps that match, with host counts, host types,
     exposure, and about how many run a version older than the fixed one.
   - **Indicators**: hosts that saw each domain, IP or hash, plus the hosts of
     defanged links. Ordinary reference links aren't looked up. A hit prints
     `SEEN ON N HOST(S)`. Treat it as an incident lead, whatever else the
     sheet says. "Not seen" covers only Falcon's own lookback for this
     lookup, which is limited. It's not proof the indicator never reached a
     host.
   - **Techniques**: Falcon alerts naming it in the last 30 days. A
     sub-technique is counted under its parent.

**Cost:** `--read` and `--facts` make one model call and print its tokens
and cost on stderr. `--show-input` makes none. To compare runs without paying
again, save the reader's answer and replay it:

```bash
sudo cti-agent cti-triage --read --json --message adv.txt > saved.json
sudo cti-agent cti-triage --facts --message adv.txt --subjects-file saved.json
```

| What you see | What it means |
|---|---|
| `LOOKUP FAILED` on every technique | The Alerts filter field `technique_id` is wrong for this tenant. The rest of the sheet is fine. |
| `not looked up: the product name has characters a lookup does not allow` | The reader's product name holds `+`, `'` or similar. Try `cti-falcon --find-app` with a shorter name. |
| `READER REFUSED` | The reader judged the advisory to be trying to change its task. Only code's own extraction was looked up. |
| `reader claims removed` | What the reader said that the advisory doesn't support. A few are normal. Many means the reader is guessing. |

### The judge: `--judge`

```bash
sudo cti-agent cti-triage --judge --message adv.txt --subject "the mail's subject"
```

This runs everything above, then a second no-tools model, the judge. It sees
the fact sheet as numbered facts (`F1`, `F2`...) and the reader's subjects
(`S1`, `S2`...). It never sees the advisory. For each subject it says
`LIKELY`, `POSSIBLE`, `UNLIKELY` or `UNKNOWN`, why, and which facts it relied
on. `TRIAGE_JUDGE_MODEL` picks its model (default: `TRIAGE_MODEL`).

Code then checks the answer:

- **Facts it cites must exist** and be about that subject (or the advisory
  as a whole). Others are dropped.
- **`likely` needs a strong fact**: a host that runs the product or saw an
  indicator. Without one it becomes `possible`.
- **Reasons are checked.** A reason that says we're affected, not affected or
  safe is replaced, and so is one that claims a sighting or an installation
  without citing a fact for it. The output then says the reason is by code.
- **Code raises what it knows**, marked `raised`:
  - a product installed and not known to be fixed is at least `possible`;
  - every subject is at least `possible` when one of our hosts saw an
    indicator;
  - `unlikely` becomes `unknown` when that subject's inventory lookup failed.
- **A skipped subject is `unknown`**, never left out.

**`SIGHTINGS` comes first, from code.** It's printed even when the judge
fails, refuses or answers nonsense. In that case the output says `JUDGE
UNAVAILABLE`, the verdicts are code's alone, and the exit status is 1.

**Cost:** two model calls, both printed on stderr. To try the judge alone
on the same facts, save the sheet once:

```bash
sudo cti-agent cti-triage --facts --json --message adv.txt > sheet.json
sudo cti-agent cti-triage --show-judge-input --message adv.txt --facts-file sheet.json
sudo cti-agent cti-triage --judge --message adv.txt --facts-file sheet.json
```

`--show-judge-input` makes no call: it's exactly what the judge would read.
`--judgement-file` checks a saved judge answer without a call.

| What you see | What it means |
|---|---|
| `raised: F3: the product is installed and not known to be fixed` | The judge said less than code knows. Code's floor wins. |
| `the judge's reason was removed` | It said we're affected or safe, or claimed something it didn't cite. The facts listed are what's known. |
| `JUDGE CLAIMS REMOVED` | Everything code changed, one line each. Now and then is normal. On every run, the judge's instructions or model need a look. |
| `JUDGE UNAVAILABLE` | The call failed, timed out, refused, or wasn't `cti-judgement/1`. Sightings and code's floors are still right. |

### In the daily digest: `TRIAGE_ENABLED`

Off by default. To turn it on, check the hand runs above work on the box
first, then add to `/etc/cti-agent/fleet.env`:

```
TRIAGE_ENABLED=1
TRIAGE_MAX_PER_RUN=10
```

**Prose-only advisories.** An article forwarded with no CVE, technique ID,
indicator or hash in it isn't picked up from just anyone. Put feeds that
write that way on `TRIAGE_SENDERS` (or `MAILBOX_FEED_SENDERS`), in
`name@example.com` or `@example.com` form. Their authenticated mail is read
whatever it holds.

`TRIAGE_ENABLED` is `0` or `1`. Only `1` turns it on. `0` or unset is off,
and the digest's log says `triage: off`. Any other value is also off, and the
log says it isn't 0 or 1.

Then preview before the timer sends it:

```bash
sudo cti-agent run-digest daily --dry-run
sudo journalctl -u cti-agent-digest --since today | grep -E "triage|advisories"
```

What the daily does with it:

1. **Ingest** saves every threat-intel message to
   `state/enriched-DATE-advisory-input.json`, whoever sent it. A message
   counts if it holds a CVE, an ATT&CK ID, a defanged indicator or link, a
   public IP or a file hash, so a colleague's forward counts, provided the
   receiving server authenticated its sender (a forged From with a CVE in it is
   not sent to the model). So does
   anything from an authenticated sender on `TRIAGE_SENDERS` (default:
   `MAILBOX_FEED_SENDERS`), even prose with none of those. Supplier
   requests, W9 and ACH threads and auto-replies hold none and never reach
   a model. Neither does the scanner's own mail (Qualys WAS and VM scan
   results), though it's full of host names and IPs: ingest logs how many
   it left out. A Qualys address listed on `TRIAGE_SENDERS` by name is the
   one exception.
2. **Step 2c** runs `cti-triage --batch` on it. The reader lists each
   message's items and their CVEs. Items naming a CVE are left to the CVE
   report and listed as such. The rest go through Falcon and the judge. A message where the reader finds
   nothing, and code has nothing to look up, is listed on one line as "no
   threat found". The judge isn't asked about it. It judges at most
   `TRIAGE_MAX_PER_RUN` and starts none after 20 minutes. The report goes
   to `state/enriched-DATE-advisories.json`.
3. **The brief** lists every one under **FLEET ADVISORIES**: sightings
   first (`SEEN ON OUR HOSTS`), then likely and possible with reason, facts
   and checks, then one line each for the rest, then any not triaged and
   why. Nothing in it is a link.

A dry run triages too, in its own directory, so the preview is the real
thing. It pays for the same model calls. The brief prints the day's model
cost at the end of the section.

**If it fails**, the digest still goes out. The section says triage
"reported nothing today", the journal has `triage: WARNING`, and the input
is kept. To rerun triage alone on it:

```bash
sudo cti-agent cti-triage --batch /var/lib/cti-agent/state/enriched-$(date +%F)-advisory-input.json --out /tmp/adv.json
```

To turn it off, remove `TRIAGE_ENABLED` or set it to `0`. Nothing else
changes.
