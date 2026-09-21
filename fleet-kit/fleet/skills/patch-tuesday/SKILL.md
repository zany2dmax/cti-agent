---
name: patch-tuesday
description: Build and send the monthly Microsoft Patch Tuesday synopsis — two public wrap-ups, correlated against what Qualys actually finds here.
---

# /patch-tuesday [--month YYYY-MM] [--dry-run]

Once a month Microsoft ships a defined set of fixes, and the patching team
needs one email: how big was it, what of it is on our machines, and what do I
paste into Qualys to see it myself.

## You do not normally run this

`cti-agent-patchtuesday.timer` runs `bin/run-patchtuesday` on the morning after
Patch Tuesday, without involving you. Same reason the digest is a timer: the
deliverable must not depend on a model being available, and the team expects
this email on a known morning.

What you owe it is a check, on the beat after it should have run:

```
$FLEET_CODE/bin/fleet-db was-sent <YYYY-MM> patchtuesday
```

If it did not go out, look for a `cti-alert` line first — the cause is
probably already on the board — then run it by hand.

## Running it by hand

```
$FLEET_CODE/bin/run-patchtuesday --dry-run     # render, send nothing
$FLEET_CODE/bin/run-patchtuesday               # send to $DIGEST_TO
$FLEET_CODE/bin/run-patchtuesday --month 2026-08   # replay, never sends
```

A replay is how the lane gets checked against an email a human already sent.
It renders and stops: re-mailing August's synopsis in September to the whole
distribution list is not a test.

## What the email has to contain

In this order, because this is the shape the team already reads:

1. **Microsoft's numbers** — total, critical, important. From the sources.
2. **Our exposure** — "The Exposure for <org> is ~N new vulnerabilities across
   M hosts." From Qualys Host Detection, never from the articles.
3. **The QQL.** The single most-used thing in the email. Someone pastes it into
   the console to see the same set themselves. Two blocks: the query Qualys
   published for this release, verbatim, then ours narrowed to the QIDs with
   assets here.
4. **The patches present here, one row per QID** — host count, QDS, last-seen
   date, and the CVEs each fixes. Not one row per CVE: a cumulative update
   carries hundreds, and keyed by CVE the table states one fact hundreds of
   times.
5. Zero-days, Edge, products, the category table, Adobe.
6. Both source links.

## Four things not to get wrong

**The QQL is published verbatim or built from our own QIDs — never
paraphrased.** A query someone pastes into a console has to be exactly right;
a reworded one silently returns a different set and they will act on it. The
review's own QQL leads, because run in the console it returns every QID in the
release with assets against it; a query built from the QIDs this lane
correlated is a subset and is labelled as one. If you are asked to "tidy up" a
QQL, do not.

**There is no severity band in this email, and adding one back is a
regression.** It could only be filled from the daily enrich lane's output, and
the daily never sees Patch Tuesday CVEs — so the column printed "severity
bands for 0 of 353". QDS, from the same Host Detection response as the host
count, is the per-QID risk signal here. Do not print a severity *word* beside
it unless you have checked Qualys' banding thresholds against their
documentation.

**The QQL Qualys publishes is also an input, not just output.** The review
lists the release's QIDs in its own QQL, and the lane parses them back out and
queries Host Detection for them *in addition to* whatever the KnowledgeBase
CVE→QID mapping resolves. The two routes are unioned because neither contains
the other: the mapping covers CVEs Qualys left out of the QQL, and the QQL
covers detections the mapping has not caught up with. This matters most on the
morning the email goes out, which is exactly when the mapping is least
complete. The stderr log says how many QIDs came from each route.

**An unmapped CVE is not an absent one, and "we did not look" is not either.**
There are four distinct exposure states and the email must print the right one:

| State | What the line says |
|---|---|
| Correlation failed — no credentials, no network, API error | "Exposure … was **NOT MEASURED** in this run: <reason>" |
| Queried, but no QID from either route | "not yet measurable … not a clean result" |
| Queried N QIDs, nothing open | "no open detections across the N QID(s) checked … check the last scan date" |
| Detections found | "~N new vulnerabilities across M hosts" |

The first state is the one that was missing, and its absence was not
theoretical: a run with no Qualys credentials printed *"the Qualys
KnowledgeBase has no QID mapping for any CVE in this release"* — a confident
diagnosis of a system that had never been contacted — directly above a QQL
listing fifteen usable QIDs. Never say anything about the KnowledgeBase, the
scanner, or the estate unless the scanner was actually queried.

**Count patches, not CVEs, when describing the work.** Qualys maps every CVE
in a monthly cumulative update to a single QID, so "353 of this release's CVEs
are present" is usually a dozen missing updates. Both numbers go in the
exposure line, and the QQL is built from the detecting QIDs, because that list
is the actual work. If you are asked how much there is to patch, answer with
the QID count and mention the CVE count second.

Related: a host figure prefixed `>=`, or an exposure line saying "at least N
hosts", means the scanner truncated its host lists and the number is a lower
bound. Do not restate it as a count.

**A synopsis from one source is still worth sending, labelled.** If
BleepingComputer is unreachable the counts may be missing and the banner says
so. If *both* fail the lane exits non-zero and sends nothing — a synopsis
assembled from nothing is worse than a missing email, because it looks like a
quiet month.

## Re-sending a past month

`--month` renders; `--for-real` sends. Together they send a past month to the
live distribution list, dated today, which is almost never what anyone means.

That nearly happened: `run-patchtuesday --for-real --month 2026-08` in
September reached the mailer, which refused it because two CC addresses were
not yet on `FLEET_ALLOW_TO`. The error advised adding them - and doing so would
have mailed August's synopsis to the team.

So a back-dated send now needs the month named in the environment as well:

```
sudo FLEET_CONFIRM_RESEND=2026-08 cti-agent run-patchtuesday --for-real --month 2026-08
```

It confirms rather than refuses, because re-sending a month whose original send
failed is legitimate. Without the variable it exits 1 and posts a WARN to the
board. **You never set this.** If a month needs re-sending, say so on the board
and let the operator run it.

## The manifest, and why you must not mark it sent yourself

After the synopsis is written, the lane records the release's CVEs in
`$FLEET_HOME/state/patchtuesday-YYYY-MM.json` with `"sent": false`. The daily
digest reads that file and holds those CVEs back — but **only** once the flag
is true, which `run-patchtuesday` sets by calling `cti-patchtuesday
--mark-sent` after the mailer reports success.

Do not run `--mark-sent` to "tidy up" a month, and do not set the flag by
editing the JSON. The flag means *this email reached people*. Setting it for a
synopsis that never went out makes the daily go quiet about hundreds of CVEs
that then appear in no email at all — the exact failure mode this fleet is
built to avoid, and one nothing in the output would report.

If the daily is flooding with Microsoft CVEs, the answer is to find out why the
monthly did not send, not to mark the manifest.

## If the sources move

The URL patterns are computable but not guaranteed. The Qualys review path
uses the Patch Tuesday date; BleepingComputer's slug carries the flaw count, so
the lane discovers it from the tag listing. When either changes:

```
$FLEET_CODE/bin/cti-patchtuesday --month 2026-09 \
  --url-qualys <URL> --url-bleeping <URL> --dry-run
```

Post the working URLs to the board so the operator can decide whether the
pattern needs updating in code, and do not guess at a URL that 404s twice.
