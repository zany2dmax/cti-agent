# The domains lane

The weekly domains check: registrar, DNS, web and mail records, and the one
Jira ticket for IT.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [11g. The weekly domains lane](#11g-the-weekly-domains-lane)

---

## 11g. The weekly domains lane

`cti-agent-domains.timer`, Tuesdays 08:00, to the security team through
`cti-mailer --lane dom`. What it checks is in
[fleet-kit/README.md → The weekly domains check](../../fleet-kit/README.md#the-weekly-domains-check).

### 1. The inventory (not in the repository)

```bash
sudo install -m 0640 -o root -g ctiagent /dev/null /etc/cti-agent/domains.txt
sudoedit /etc/cti-agent/domains.txt
```

One domain per line, then the markers that choose its row in the security
team's decision chart; `#` comments:

```text
example.com          send receive     # 1: active mail domain
example.net          send             # 2: send-only (no MX needed)
example.org          receive          # 3: receive-only
parked.example                        # 4/5: no mail at all (null MX preferred)
app.example          saas             # 6: an application or service sends as it
unsure.example       unknown          # 7: senders not known - reported, never tightened
old-brand.example    receive legacy   # 9: outbound moved to the main domain
```

`send receive legacy` is row 8. **`send` alone now means send-only**, so mark
every domain that also receives mail `send receive`. A domain with no marker is
checked as one that must not send or receive (`v=spf1 -all`, DMARC
`p=reject`, null MX `0 .`). A typo in a marker is reported in the email rather
than silently read as "no mail". `man cti-domains` has the full chart.
`domains.txt` is in `.gitignore`, and a test fails if one appears anywhere in
the tree.

### 2. The GoDaddy token

Create a Personal Access Token in the GoDaddy developer portal with **only**
`domains.domain:read`. Put it in `GODADDY_PAT` in `/etc/cti-agent/fleet.env`.
The lane makes one call, `GET /v1/domains`, and never requests auth codes.

| Error | Means |
|---|---|
| `HTTP 401` | token missing, expired or revoked |
| `HTTP 403` | token lacks `domains.domain:read`, or the account is not eligible - GoDaddy's code in the message says which |
| `HTTP 429` | rate limited; the next weekly run will retry |

Without a token the report still runs DNS, web and mail checks, and its subject
carries `[REGISTRAR NOT CHECKED]`.

### 3. Recipients and the first run

```bash
# in fleet.env
DOM_TO=$FLEET_OPERATOR_EMAIL           # or the security team's list
DOM_ALLOW_TO=$DOM_TO

sudo cti-agent cti-mailer --check      # lists DOM_TO / DOM_ALLOW_TO
sudo cti-agent run-domains --dry-run   # renders, sends nothing, baseline untouched
sudo systemctl enable --now cti-agent-domains.timer
```

The first real run says *"First run: no previous week to compare with"*. The
week-over-week section starts the Tuesday after. State is
`$FLEET_HOME/state/domains-state.json` (0600); move it aside to start over.

### 3b. What the report contains, and the lock-down ticket

In order: **INVENTORY vs GODADDY** (only when the account and `domains.txt`
disagree: domains in the account but not listed, listed but not in the
account, and listed registrations cancelled, expired or transferred out more
than 45 days ago, which are set aside for removal and not probed);
**WEBSITES** (live, redirecting, registrar-hosted, parked, DNS but no working
page, none); NEEDS ACTION, CHANGED SINCE LAST WEEK, REVIEW and NOTES; then
**DNS CHANGES FOR IT** - the exact records each domain needs to match its
profile, and items to review.

`cti-domains --actions-out` writes those changes, and after the email has gone
`run-domains` passes them to `cti-jira --domains-actions`, which files **one
lock-down ticket** for IT (every change needs the same registrar access). When
that ticket is already open it adds a comment only if the list has changed,
and says once when nothing is left. A dry run only previews the ticket; with
`JIRA_ALLOW_CREATE` empty nothing is written; a Jira failure is logged and
never stops the report. Read DNS CHANGES FOR IT in a `--dry-run` before the
first Tuesday run: every unmarked domain gets a null MX in it.

**Filing the lock-down ticket in another project (INF).** By default it goes to
`JIRA_PROJECT_KEY`. To send it elsewhere set, in `fleet.env`:

```bash
JIRA_DOMAINS_PROJECT_KEY=INF
JIRA_DOMAINS_ISSUE_TYPE=<the type name exactly as INF spells it>
JIRA_ALLOW_CREATE=CR,INF
```

CVE and AppSec tickets are unaffected. The lane finds its ticket by the labels
`cti-agent` and `cti-domains-lockdown` in that project, and keeps what it last
said as an issue property on it. A ticket someone created by hand has neither,
so the next run files a new one: to have the lane adopt an existing ticket
(INF-590 replaced CR-24907), add both labels to it in Jira first, and close the
old ticket yourself. The lane also adopts a ticket only if its own account filed
it or the person who filed it is listed in `JIRA_TRUSTED_REPORTERS` (their Jira
account id, from the URL of their profile page): a label is text anyone who can
edit the ticket can write. A hand-made ticket from anyone else is ignored, and
the next run files a new one. The service account needs Browse, Create, Comment and
Attach in the new project; `cti-jira --check` looks only at `JIRA_PROJECT_KEY`.

### 4. Public DNS, and outbound port 53

The lane asks public resolvers (1.1.1.1, 8.8.8.8) rather than this host's DNS.
On the first real run the internal resolver answered for the organisation's
own domains from an internal zone with no SPF or DMARC, and the report called
both domains spoofable. Check the box can reach public DNS:

```bash
dig @1.1.1.1 example.com TXT +short     # use one of your domains
```

If outbound 53 is blocked, set `DOMAINS_DNS_SERVERS` to a resolver that
answers with the public view, or `system` to accept the internal one.

### 4b. Outbound port 25

The lane greets each domain's MX on port 25 to check STARTTLS. Many networks
block outbound 25; if every probe fails the report says *"outbound port 25 is
almost certainly blocked from this host"* once, in its footer, and nothing per
domain. To test from the box:

```bash
timeout 5 bash -c '</dev/tcp/<an-mx-host>/25' && echo open || echo blocked
```

Either open it for this host or set `DOMAINS_SMTP=off`.

### 5. Proofpoint on Demand

With any domain's MX on PoD, the weekly gains a **PROOFPOINT ON DEMAND**
section: domains whose mail is received elsewhere (acquisitions not yet
moved, named by provider, with how many weeks), an MX on another
organisation's PoD tenant (High), senders whose SPF does not authorise PoD,
and what is left after a move (an old SPF include, a Google DKIM key). The
tenant is learned from the MX records; pin it with `PROOFPOINT_POD_TENANT`
if a week could ever have more domains off the gateway than on it.

An SPF record at the 10-lookup limit may list the PoD addresses instead of the
include. Put them in `PROOFPOINT_POD_IPS` (addresses or CIDR ranges) and such a
record counts as authorising PoD.

The weekly also has a **SPF INCLUDES - WHO EACH ONE IS FOR** section: every
`include:` / `redirect=` in the domains' own SPF records, once, with the vendor
behind it (SMTP2GO, KnowBe4, Mailchimp, Microsoft 365 and so on) and the
domains that carry it, so "do we use that vendor?" is one answer and one
removal. An include the report does not know is shown first as **NOT
RECOGNISED**; once someone has found out who it is, add it to
`DOMAINS_SPF_VENDORS` (`suffix=description`) and the next report says so. The
CSV has the same per domain in `spf_includes_described`. Only a record's own
includes are described, not what a vendor's record includes in turn.

### 6. DKIM selectors and DMARC reports

DKIM keys cannot be listed, only probed by selector. If a sending domain shows
"no DKIM key at the selectors tried", find the selector from a message header
(`DKIM-Signature: ... s=<selector>`) and add it to `DOMAINS_DKIM_SELECTORS`.

`DOMAINS_DMARC_RUA` is **empty pending a decision** on where aggregate reports
should go (the mail gateway may provide an address). Until it is set the check
is only that every sending domain has *some* `rua=`; once set, every sending
domain's `rua=` must include it.

### 7. The PoD Log API (probe and the opt-in lane half)

A read-only probe, `cti-podprobe`, and the lane's use of the API both exist;
the lane half is off until you turn it on (below). The mail-side evidence comes from Proofpoint's *PoD
Log API*. The vendor guide is **"Proofpoint on Demand (PoD) Log API", Revision
I, August 2023** (Proofpoint Customer Success Center; the guide is
proprietary, so it is not in this repository: keep your copy beside the
fleet's other vendor documents and cite its page numbers when something here
disagrees with it). This section records what the fleet relies on; the guide
wins on any difference.

**What to arrange with the Proofpoint admin.** Only two items: the remote
syslog licence and the token. There is no console toggle for
`routeDirection`; it is a field in the log.

1. **A token for the fleet alone.** Email Protection portal, Settings > API
   Key Management > Create New (or ask Proofpoint support). The service allows
   **one session per token**: a second connection with the same token gets
   HTTP 409, so never share it with a SIEM or a hand test. Store it in
   `fleet.env` as `POD_API_TOKEN` (0600, never in the repository).
2. **The cluster ID**, shown at the top right of the management interface next
   to the release number. `fleet.env` setting `POD_CLUSTER_ID`.
3. **Remote syslog licence.** A 401 can also mean the licence for the cluster
   is missing or expired; ask that the `message` stream is enabled.
4. **Egress** from the box to `logstream.proofpoint.com` on TCP 443.

**How the service behaves (guide, "API Features" and "Connection Notes")**

- Endpoint `wss://logstream.proofpoint.com/v1/stream?cid=<cluster>&type=
  message|maillog|audit`, header `Authorization: Bearer <token>`, plain
  WebSocket (RFC 6455). `message` carries the filter data the lane needs;
  `maillog` is the MTA log; `audit` is portal audit events (not used).
- It is a **live feed, not a query API.** Polling "every 15 minutes" returns
  duplicates (the minimum is one hour of data) and can get the client locked
  out. A reconnect within an hour resumes where the last session stopped; after
  a longer gap you only get the last hour.
- **Archive reads** use `sinceTime` and `toTime` (ISO 8601 with offset such as
  `-0500`; rounded to the hour, 30 days back at most). The weekly lane is one
  archive read of the last seven days, then a disconnect.
- Compression (`permessage-deflate`, with `client_no_context_takeover` and
  `server_no_context_takeover`) is optional; the fleet asks for none.
- Events can arrive out of time order (an agent that finishes a slow message
  later logs it later). Count, do not rely on order.
- Errors: 400 malformed query, 401 bad token, cluster ID or licence, 404 bad
  URL or protocol, 405 not a GET, 409 token already in use.

**Fields the lane reads (guide, "Message Schema")**

| Need | Field |
| --- | --- |
| Direction | `filter.routeDirection` (inbound, outbound, internal, external) |
| Header From | `msg.header.from` |
| Envelope sender | `envelope.from` |
| DKIM signer and selector | `filter.modules.dkimv[]` (`domain`, `selector`, `result`) |
| SPF | `filter.modules.spf.result` |
| DMARC rollup and alignment | `filter.modules.dmarc` (`filterdResult`, `alignment`, `authResults`) |
| Sending host | `connection.ip`, `connection.helo` |
| Recipients (inbound and internal) | `envelope.rcpts`; `msg.parsedAddresses.to` and `cc` when the envelope has none |

The lane keeps **aggregates only**: per domain and week, the outbound senders
(header-From domain, DKIM selector, count), the inbound messages that claim
the domain but fail DMARC (count, top sending IPs), and the domains inbound and
internal mail was delivered to (the domain part only, counted once per
message). No subjects, recipient addresses or per-message records are written
to disk or sent in any report.

**Turning on the lane half**

**Off by default, and nothing changes until you add the first line below.**
Without `DOMAINS_MAIL_GATEWAY=pod` the weekly never touches the Log API: the
run prints no `gateway:` lines and the report has no gateway findings. With
`POD_CLUSTER_ID` and `POD_API_TOKEN` already in `fleet.env` (the same pair
`cti-podprobe` uses), add:

```bash
DOMAINS_MAIL_GATEWAY=pod      # off (or unset) is the default
DOMAINS_GATEWAY_DAYS=7        # whole days to read, 1 to 28, default 7
```

then rehearse with `sudo cti-agent run-domains --to-dev` (a test send to
`FLEET_DEV_EMAIL`; it reads the log, writes nothing to Jira and does not
advance the baseline) and look for the `[domains] gateway:` lines in the output:
`gateway: Proofpoint on Demand log, last 7 day(s), reading in the background`,
then `gateway: N events read, ...` (or `NO USABLE EVIDENCE (reason)`). If
neither appears, the setting is not being read. The read takes roughly 15 to 20
minutes for 7 days, so the run is slow. The weekly reads
the archive for the last N whole days (the window ends at the last full hour
more than an hour ago) in the background while the DNS and web probes run, and
keeps counts only. What changes in the report, when the evidence is usable:

- A domain the inventory says sends nothing (`receive`, `legacy`, or no mail)
  that has outbound mail in the window gets a **High** finding and **no
  lock-down action**: IT is not asked to publish `-all` and `p=reject` for a
  domain that sends. Find the sender, then correct the inventory (`send`) or
  stop the mail. The same applies to such a domain that only has inbound mail
  *passing DMARC* as it: some service is authorised to send as the domain
  (High, "find the service"). While any domain is left out this way, an open
  lock-down ticket is not told it is finished (`skipped` in the actions file).
- A sending domain with no outbound mail in the window gets an **Info**. A
  domain that sends only through some other path (not this gateway) shows as
  "no outbound seen"; that line is expected for it.
- An outbound header-From domain that is not in the inventory gets a
  **Medium** (the first 10 alphabetically; the rest are counted, since
  forwarded mail keeps other people's From domains). Gateway bounces and
  unparsable names are counted in the summary line, not attributed.
- Inbound mail using our domains in the From address gets an **Info** with the
  passed and not-passed DMARC counts: the evidence for `p=reject`. It is a
  finding line, not a ticket action.
- **A null MX is checked against mail received.** A "no mail" domain is asked
  to replace its MX with a null MX (`0 .`), which bounces every message sent
  to it. If the gateway delivered mail to the domain in the window, that change
  moves to **To review** with the count, and the report has a **High** ("find
  who uses it, then mark it `receive` or retire those addresses"). The other
  lock-down changes (SPF, DMARC, DKIM) stay exact. A domain whose MX is not on
  Proofpoint cannot be checked, because its mail never passes the gateway: its
  null MX stays exact and says "not checked against the mail gateway". If the
  log carried no recipient data at all (or more recipient domains than it can
  name), the report has a Medium and **every** null MX goes to To review. The
  run prints `gateway: mail delivered to N recipient domain(s)` and, when any
  moved, `gateway: N null MX change(s) moved to review`.

**The hold rule.** If the gateway is configured but the read failed or was
incomplete (token in use, HTTP 409; network error; the byte cap; the stream
went idle; **the connection dropped without a close frame**; messages that
could not be decoded; more distinct sender domains than the aggregate can
name; an empty window; or events that do not cover the start and end of the
window to within 3 hours), the run
cannot prove a "sends nothing" domain sends nothing. So it produces **no
lock-down actions**, the actions file carries `held: true`, and `cti-jira`
files, comments on and resolves nothing that run (the ticket reference action
is `held`). Without that, an empty action list on an open lock-down ticket
would be read as "nothing is left to change" and the ticket resolved. The
report still goes out, with a **Medium** "(mail gateway)" finding saying why;
the next good run catches up.

**One session per token.** Do not run `cti-podprobe` (or anything else on the
token) while the weekly runs: the second connection gets HTTP 409 and the
weekly holds its tickets for the week.

**Running the probe**

```bash
sudo cti-agent cti-podprobe --since 2026-11-02T10:00:00-0500 --to 2026-11-02T11:00:00-0500
```

It needs `POD_CLUSTER_ID` and `POD_API_TOKEN` in `fleet.env` (there is no
token flag) and a window that began more than an hour ago. It prints **counts
only**: events per direction, route names, DMARC and SPF results, outbound
header-From domains and DKIM data, and inbound mail using our domains. It
never prints or stores a message, address or subject. `--json` gives the same
counts as JSON; `--max-bytes` (default 200 MB) stops a large read and says the
counts are partial. **One session per token:** if a SIEM or a hand test holds
the token, the probe gets HTTP 409, and while it runs nothing else may use it.

**What a real read of this tenant showed**

- `routeDirection` is present on events, with values `inbound` and `outbound`.
- Outbound events carry routes such as `allow_relay`, and a tenant rule
  `mydomains_from_hdr` that also appears on inbound mail using our domains in
  the header From, so that rule alone does not mean "outbound".
- Our own phishing-simulation mail carries KnowBe4 routes and must be excluded
  from spoof counts.
- `dkimv` is DKIM verification, and it is **absent on outbound mail** (a full
  business hour: 1,015 outbound events, none with it). The stream cannot say
  which DKIM selector our outbound mail was signed with, so that stays a DNS
  check (`DOMAINS_DKIM_SELECTORS`). Outbound evidence from the stream is the
  header-From domain and the sender IP.
- A full business hour (a Monday, 10:00 local) was about 5,300 events and 73 MB
  (about 14 KB each, the largest 450 KB): roughly 70% inbound, 19% outbound,
  1% internal. Plan on several GB for a week read, so the weekly lane must ask
  for compression (permessage-deflate, see the guide's request examples) or
  read incrementally; measure `time` on the box before choosing.
- Inbound mail that uses our domains in the header From is mostly *our own
  cloud senders passing DMARC*. Counting it as spoofing would be wrong; the
  signal is the part that does not pass (fail, quarantine, reject), and the
  probe lists sender IPs for those only.
- The outbound header-From domains of one hour already name every domain that
  sends through the gateway, plus a few bounce/NDR identities from the gateway
  itself (a `127.0.0.1` sender, the gateway's own host name) that the lane must
  not mistake for domains of ours.

The field paths in the table above are confirmed against this tenant for
direction, header From, sender IP, route names, DMARC and SPF results.
