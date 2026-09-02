# Exposure remediation — public disclosure of `cti-vuln-report.md`

**Status:** open · **Found:** 2026-09-02 · **Owner:** jleggett@crhomeusa.com

Internal working notes. Keep this file in the repo only until the scrub is
done; it names no hosts, but it does describe what was exposed.

---

## What happened

`cti-vuln-report.md` was committed to `github.com/zany2dmax/cti-qualys-agent`,
a **public** repository, across four commits. The file is generated output from
the CTI agent: it pairs CVEs with their Qualys detection status, host counts,
and sample hostnames.

It was retrievable anonymously over `raw.githubusercontent.com` — no
authentication, no rate-limit obstacle. That is how it was found.

Two `fleet-kit` fixtures derived from it (`sample-report.md`,
`sample-digest.html`) were also committed, in `ca678fb`, and two kit docs
(`fleet-kit/README.md`, `fleet-kit/fleet/CLAUDE.md`) referenced hostnames in
prose.

## What was exposed

| | |
|---|---|
| Unique host identifiers | **65** — FQDNs across two internal domains, plus one RFC1918 address and several `.local` Macs |
| CVEs marked `PRESENT` | **16** |
| Largest single exposure | one CVE on **379** hosts; others at 305, 243 (×4), 186, 57, 56, 40 |
| CVEs marked `UNKNOWN` | 8 — no Qualys QID mapping, i.e. coverage unverified |
| Credentials | **none** — no `.env`, client secret, or Qualys password was ever committed (verified against all history) |

Beyond hostnames, several machine names identify individual employees, and the
naming convention itself discloses site structure and which subnets are the CAD
estate versus servers.

**The material risk is not any single CVE.** It is that the pairing removes an
attacker's reconnaissance step: it says which specific machines are unpatched
against which specific exploitable vulnerabilities, including one internet-famous
domain-controller vulnerability on four hosts.

## Fixes applied (this branch, not yet pushed)

- `internal/report/markdown.go` — hostnames redacted to stable salted
  pseudonyms unless `REPORT_HOSTNAMES=full`; report written `0600`; banner added
  when running in `full`
- `.gitignore` — generated reports excluded by name and pattern; also fixed an
  unanchored `bin/` rule that had been silently excluding the fleet executables
- `.env.example`, `README.md` — document `REPORT_HOSTNAMES` and
  `REPORT_REDACTION_SALT`
- `fleet-kit/README.md`, `fleet-kit/fleet/CLAUDE.md` — hostname references
  removed from prose; CLAUDE.md now instructs the fleet never to write a real
  hostname into a committable file
- `scripts/scrub-history.sh` — backs up, rewrites history, verifies, then stops

## Remaining steps

- [ ] **Install git-filter-repo** — `brew install git-filter-repo`
- [ ] **Commit the fixes above** on a clean tree
- [ ] **Run `scripts/scrub-history.sh`** — it backs up first and will not push
- [ ] **Force-push** `--all` and `--tags` once verification passes
- [ ] **Open a GitHub Support ticket** asking them to purge cached blob views
      and stale refs, citing the removed SHAs. Rewriting history does not
      evict GitHub's caches; blobs stay reachable by SHA until Support clears
      them.
- [ ] **Check the fork network** — `/network/members`. A fork retains
      everything and is outside your control.
- [ ] **Decide on repo visibility.** Private is the durable fix. The project
      being public bought little and cost this.
- [ ] **Rotate the Qualys API credential and Entra client secret** as
      precaution. Neither was exposed, but the repo describes exactly what they
      access, and rotation is cheap.

## Patch priority, given these were public

Treat the 65 hostnames as **disclosed, not recalled** — anyone who cloned
before the rewrite still has them. Assume the pairing is known and prioritize
accordingly:

1. **CVE-2020-1472** (Zerologon, 4 hosts) — domain-controller privilege
   escalation, on CISA KEV, EPSS ~99%, known ransomware use. Highest priority
   regardless of the disclosure; the disclosure just removes the excuse.
2. **The high-host-count items** — 379, 305, and the four 243-host CVEs. Broad
   footprint means any one compromised host is a foothold.
3. **CVE-2016-8740, CVE-2025-33073** and the remaining `PRESENT` set.
4. **The 8 `UNKNOWN` CVEs** — resolve why Qualys has no QID mapping. "We
   didn't look" is not "we're clean," and the public report says so plainly.

## Process fix

The root cause is that generated output lived in the repo root next to source,
where `git add -A` catches it. The report is now gitignored and redacted by
default, and the fleet writes everything under `~/fleet/` — outside any git
working tree — but the durable lesson is that **scanner output is production
data, not project artifacts.** It belongs somewhere access-controlled, with a
retention policy, not in version control.
