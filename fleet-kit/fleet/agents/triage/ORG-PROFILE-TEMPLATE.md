PROFILE-STATUS: TEMPLATE

<!--
  THE LINE ABOVE IS A SENTINEL. DELETE IT WHEN YOU HAVE FILLED THIS IN.

  While it is present, the triage lane treats this profile as absent and
  answers "unknown" for every item rather than reasoning from blank headings.

  That matters because placeholder prose fails SILENTLY in a way placeholder
  credentials do not. A fleet.env full of PLACEHOLDER secrets cannot
  authenticate and stops; a profile full of empty headings reads perfectly
  well to an agent, which then concludes "we do not appear to run anything
  like that" and returns a confident "unlikely" for a campaign aimed straight
  at you. Wrong and quiet is worse than missing and loud.
-->

# Organisation profile — TEMPLATE

**This file is the template. It is NOT the one the agent reads.**

The real profile lives outside the repository, at:

```
/etc/cti-agent/ORG-PROFILE.md          (root:ctiagent, 0640)
```

The installer puts a copy there for you. Fill that copy in and **delete its
`PROFILE-STATUS: TEMPLATE` line**; leave this one as it is.

The `@triage` agent reads the deployed copy to answer one question: **does this
piece of threat intelligence plausibly matter to us?**

It is the highest-leverage input the agent gets. Without it, every item comes
back `unknown`, which is honest but not useful.

---

## Why it lives in /etc and not here

This repository is public. A filled-in profile describes what an organisation
runs, which is reconnaissance somebody would otherwise have to do themselves —
and the whole point of this lane is reading threat intel about people who do
exactly that.

So `ORG-PROFILE.md` is gitignored. Committing one is the mistake this split
exists to prevent, and it is not recoverable: a push publishes it, and deleting
the file later does not remove it from the history.

`install-fedora.sh` creates it from this template if it is absent, and never
overwrites one that exists. So the normal path is:

```bash
sudo $EDITOR /etc/cti-agent/ORG-PROFILE.md    # fill in, DELETE the sentinel
```

`0640 root:ctiagent` matches `fleet.env`: the service account reads it, and
only root can change what the agent believes about the estate.

Check before every push that you have not committed one:

```bash
git status --short | grep -i org-profile      # expect no output
```

---

## Write this by hand

Do not generate it, and do not let an agent maintain it. It is short enough to
write in twenty minutes and wrong answers here propagate into every triage
decision for months.

## Keep it non-sensitive even in /etc

Being outside the repository is not a licence to put an asset inventory in it.
Write **categories, not inventory**:

- ✅ "Identity: Microsoft Entra ID, M365"
- ✅ "Commerce: a customer portal; card payments are handled by a third party"
- ❌ hostnames, IP ranges, URLs, product versions, counts of anything
- ❌ vendor names under NDA, security-tool coverage gaps, staff names

The agent needs to know *what kind of organisation this is and what it runs*.
It does not need — and must never be given — anything that would help someone
attack it. Assume this file is public, because the repository is.

Two reasons that hold even now it is not public. An inventory goes stale within
a fortnight and then produces confidently wrong `unlikely` verdicts, which is
worse than no profile at all. And the agent reads attacker-written text with
this file in its context — the less it holds that would help an attacker, the
less an injection can extract.

If a category is genuinely sensitive, leave it out. A missing category yields
`unknown`, which is a safe answer. A leaked one is not recoverable.

---

## Template

Replace everything below.

### What we are

> Sector, rough size, what the business actually does, and who our customers
> are. Two or three sentences. This drives sector-targeting judgments — a
> campaign against online retailers lands differently on a distributor with a
> portal than on a merchant taking cards.

### Identity and productivity

> Identity provider, mail platform, SSO, MFA approach at a category level.
> The rogue-MFA-provider technique mattered to us only because this line says
> Entra ID.

### Internet-facing footprint

> What we expose: a portal, marketing sites, APIs, file transfer. Say who
> handles payments if anyone does. Say whether there is custom-written code
> facing the internet — cheap autonomous attack tooling specifically targets
> bespoke code, because it is nobody's patch cycle.

### Core platforms

> ERP, commerce, CMS, collaboration, remote access, virtualisation. Category
> and vendor, no versions.

### Cloud and hosting

> Which providers, roughly what runs there, and whether secrets management is
> centralised. One documented chain turned a single web compromise into a card
> breach purely through an over-scoped secrets role.

### Endpoint, network and detection

> EDR, SIEM, email security, network filtering — vendors only. This tells the
> agent which suggested checks are even possible for us.

### Vulnerability management

> Scanner, cadence, who acts on findings, and roughly what the SLA is.

### Third parties that matter

> Categories of supplier whose compromise would reach us: payment processing,
> logistics, managed services, EDI partners. No names if that is sensitive.
> This is what makes supply-chain items scoreable instead of `unknown`.

### What we do not have

> As useful as what we do. "No Linux desktop estate", "no Kubernetes", "no
> public mobile app" each let the agent answer `unlikely` with a real reason
> instead of hedging.

### Current concerns

> Anything the team is already worried about or working on. An item touching a
> known concern deserves to be surfaced even if it scores `possible`.

---

## Maintenance

Review it when the estate changes materially, and at least twice a year. A
stale profile does not fail loudly: it quietly produces confident judgments
about an organisation that no longer exists. Put the date of the last review
at the top when you fill it in.
