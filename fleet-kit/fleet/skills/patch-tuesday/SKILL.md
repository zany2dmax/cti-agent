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
   the console to see the same set themselves.
4. CVEs confirmed present here, with QIDs and severity band.
5. Zero-days, Edge, products, the category table, Adobe.
6. Both source links.

## Three things not to get wrong

**The QQL is published verbatim or built from our own QIDs — never
paraphrased.** A query someone pastes into a console has to be exactly right;
a reworded one silently returns a different set and they will act on it. The
lane prefers QIDs with live detections here, falls back to whatever Qualys
published, and only then to a CVE filter. If you are asked to "tidy up" a QQL,
do not.

**An unmapped CVE is not an absent one.** Within a day or two of a release the
KnowledgeBase often has no QID for the newest CVEs. The email says "coverage
could not be established", and the exposure line says "not yet measurable"
rather than "0". Do not restate either as a clean result.

**A synopsis from one source is still worth sending, labelled.** If
BleepingComputer is unreachable the counts may be missing and the banner says
so. If *both* fail the lane exits non-zero and sends nothing — a synopsis
assembled from nothing is worse than a missing email, because it looks like a
quiet month.

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
