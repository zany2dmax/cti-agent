# Organisation profile — TEMPLATE, fill this in

The `@triage` agent reads this to answer one question: **does this piece of
threat intelligence plausibly matter to us?**

It is the highest-leverage input the agent gets. Without it, every item comes
back `unknown`, which is honest but not useful.

---

## Write this by hand

Do not generate it, and do not let an agent maintain it. It is short enough to
write in twenty minutes and wrong answers here propagate into every triage
decision for months.

## Keep it non-sensitive

This file sits in a repository. Write **categories, not inventory**:

- ✅ "Identity: Microsoft Entra ID, M365"
- ✅ "Commerce: a customer portal; card payments are handled by a third party"
- ❌ hostnames, IP ranges, URLs, product versions, counts of anything
- ❌ vendor names under NDA, security-tool coverage gaps, staff names

The agent needs to know *what kind of organisation this is and what it runs*.
It does not need — and must never be given — anything that would help someone
attack it. Assume this file is public, because the repository is.

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
