# Developing and releasing

Running the agent alone, the local loop, the Mac-to-box workflow, man pages,
and cutting a release. [CONTRIBUTING.md](../../CONTRIBUTING.md) has the rules
a change is held to.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [5. The agent alone](#5-the-agent-alone)
- [6. Local development loop](#6-local-development-loop)
- [7. The two-box workflow: Mac to Fedora](#7-the-two-box-workflow-mac-to-fedora)
- [11h. Man pages](#11h-man-pages)
- [11i. Cutting a release](#11i-cutting-a-release)

---

## 5. The agent alone

The threat-intel lane's ingest binary on its own: build it, point it at a
mailbox, get a markdown report. No fleet, no systemd.

```bash
cp .env.example .env
vi .env                  # real values

set -a; source .env; set +a
go run ./cmd/cti-agent
```

Or with Task:

```bash
task build               # all fourteen binaries into bin/
task run
```

The report lands at `REPORT_PATH`, mode `0600`, gitignored. Read
[section 13](operations.md#13-report-sensitivity) before moving it anywhere.

---

## 6. Local development loop

Once per checkout:

```bash
./scripts/dev-setup.sh            # install the git hooks
./scripts/dev-setup.sh --status   # check they are installed and current
```

That installs a `pre-commit` hook which runs `gofmt` over staged Go files and
re-stages them, so `task ship` has nothing left to complain about. Git does not
version `.git/hooks`, so a fresh clone silently has none — hence `--status`.

The hook formats; `task ship` only *checks*. That asymmetry is deliberate:
`ship` ends in `git push`, so reformatting there would rewrite files and then
push without them, which is how `v1.0` got stamped `-DIRTY`. A commit hook is
the opposite case — nothing is published yet, and the fix lands before the
commit it would otherwise invalidate exists.

It skips any file with unstaged changes rather than rewriting it, because
`gofmt -w` rewrites the whole working-tree file and re-staging it would commit
edits you had deliberately held back.

`fleet-kit/bin/dev-run` executes the whole pipeline from a checkout with no
root, no service account and no systemd. It sends nothing unless asked.

```bash
./fleet-kit/bin/dev-run doctor                  # config + Graph token + granted roles
./fleet-kit/bin/dev-run ingest --provider none  # mailbox + CVE extraction only
./fleet-kit/bin/dev-run all                     # full pipeline, opens the digest
```

Start with `--provider none`. It needs only the Entra credentials, so it
separates "can we read the mailbox" from "does the scanner answer".

Tests:

```bash
task test               # Go tests + Python lane tests
task test:kev           # deadline bands, sign convention, present-only filtering
task test:budget        # quota ceilings, backoff growth, rate-limit classification
task test:patchtuesday  # release dates, source parsing, exposure, QQL, the QID table
task test:mailbox       # the processed-message gate and the cleanup decision table
task test:env           # fleet.env parsing, and which credentials each command needs
task test:safelog       # the log sanitiser: control characters, rune-safe truncation
task test:graph         # URL construction, sendMail, error diagnosis
task test:report        # hostname redaction and file permissions
```

---

## 7. The two-box workflow: Mac to Fedora

The development box and the fleet box have different jobs and different gates.

```bash
# --- on the Mac: write, prove, push ---
task test           # while changing one thing
task ship           # fmt, build, test, lint, scan, gosec, govulncheck, ruff, bandit, shellcheck, THEN push

# --- on the Fedora box: deploy, verify, then enable ---
# KIT = wherever the kit checkout lives. Not ~, because the deploy runs
# under sudo and $HOME is then root's.
sudo "$KIT/fleet-kit/update-fedora.sh" --for-real   # pull the kit, then install (= sudo cti-agent-update --for-real)
sudo vi /etc/cti-agent/fleet.env            # any new settings
sudo cti-agent cti-mailer --check           # token + granted roles
sudo cti-agent run-digest daily --dry-run   # read it before enabling anything
sudo systemctl enable --now cti-agent-digest.timer
```

**`task ship` is the only thing that pushes.** It stops at the first failing
gate, so a push cannot outrun a red test — which it did once, when `task test`
and `git push` were separate lines in the same paste.

**Every update can be undone.** `cti-agent-update --for-real` snapshots the
code, config, units and `memory.db` first, in `/var/lib/cti-agent-update/`. If
the installer fails, it puts all of it back. Afterwards it runs
`cti-agent-doctor`, one line per health check. If a release misbehaves later:

```bash
sudo cti-agent-update --rollback --dry-run
```

```bash
sudo cti-agent-update --rollback --for-real
```

That restores everything but `memory.db`, which the lanes have written to
since. In a fork, the `/update-fleet` Claude Code skill walks through an
update, including reading the CHANGELOG for what it asks of the box.

**A deploy never enables a timer before a dry run has been read.** The dry run
is the only place a wrong recipient, a broken parser or an empty report is
cheap.

The longer version, including what runs where and why, is
[fleet-kit/README.md → The two-box workflow](../../fleet-kit/README.md#the-two-box-workflow).

---

## 11h. Man pages

Every operator command has a page:
- every Go binary, the `run-*` runners, the `fleet-*` tools, the `cti-agent`
  wrapper, the Python lanes and `dev-run`;
- the root tools run with plain `sudo`: `cti-agent-update`,
  `cti-agent-secrets` and `cti-agent-settings`.

The installer puts them in `/usr/local/share/man/man1`. The wrapper and the
three root tools also have bash and zsh tab completion:

```bash
man cti-domains
man run-digest
man -k cti        # list them all (after mandb has indexed them)
```

They are written from the source. `fleet-kit/tests/test_lanes.py` fails if a
command gains a flag, argument or subcommand its page does not document, and
`task man:lint` checks they render cleanly. Conventions are in `man/STYLE.md`.

---

## 11i. Cutting a release

A **tag** and a **release** are different things. The tag is git's: a name for
one commit, pushed with `git push origin 1.6.7`. The release is GitHub's page
on top of a tag, with a title and notes, and pushing a tag never makes one. Until
1.6.6 nothing made them, so the Releases page said 1.6.1 was "Latest" while
1.6.6 was tagged and deployed.

`.github/workflows/release.yml` makes them now. When a release tag (`1.6.7`,
`v1.7`) reaches GitHub, it creates the release for it, titled with the tag, and
the notes are that version's section of `CHANGELOG.md` with a link to the
whole file, and the release carries the version's **SBOM**
(`cti-agent-1.6.7.cdx.json`, CycloneDX 1.5) as a downloadable file. Only the
highest version is marked **Latest**.

A **release candidate** is the version with `-rcN`, lowercase (`2.0-rc1`),
with its own CHANGELOG heading (`## 2.0-rc1 — YYYY-MM-DD`). Its release is
marked **Pre-release** and never takes Latest. The final version gets its
own heading and tag.

### The steps

On the Mac, in `~/code/cti-agent`, clean and on `main`:

1. In `CHANGELOG.md`, rename `## Unreleased` to `## 1.6.7 — YYYY-MM-DD`
   (today), and put the release in the cheat sheet's stamp line
   (`**This copy is for release 1.6.7 (YYYY-MM-DD).**`). Commit both as
   `Release 1.6.7`.
2. Check the notes the release will get:
   ```bash
   scripts/release-notes.sh 1.6.7
   ```
   It prints the section, or fails if the heading is missing or misspelt.
3. Tag the release commit, then push the branch and the tag:
   ```bash
   git tag -a 1.6.7 -m "Release 1.6.7"
   task ship
   git push origin 1.6.7
   ```
   `task ship` runs every check and pushes `main`; it does not push tags, so
   the second push is not optional. `release:check` (inside `task ship`)
   reads the files as committed at the tag: it fails if the tag's CHANGELOG
   has no section for it, or the stamp line at the tag or at HEAD names
   another release. So a tag made before the `Release 1.6.7` commit, or a
   stamp left uncommitted, stops the ship before anything is pushed. Since
   the tag has not left the Mac yet, the fix is to move it onto the release
   commit: `git tag -d 1.6.7 && git tag -a 1.6.7 -m "Release 1.6.7"`. Once a
   tag is pushed it never moves (below).
4. About a minute later the release is on the Releases page, with its SBOM under
   Assets. If not, look at **Actions → Release**.
5. Update the box: `sudo cti-agent-update --for-real`.

### A pushed tag never moves

A box's `cti-agent-update` pulls tags, and a tag that moved under it stops the
update with "would clobber existing tag" (`moved_tag_help` prints the fix for
that box). So a tag that is wrong once pushed is never moved or deleted: cut
the next version instead (`2.0-rc4` after a bad `2.0-rc3`), with its own
CHANGELOG heading. The old tag and its release stay as they are.

GitHub can enforce this with a tag ruleset that refuses updating or deleting
any tag. It changes the repository's settings, so the repository's owner
creates it once, by hand (a fork's owner does the same for the fork):

```bash
gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
{"name": "release tags never move", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "update"}]}
JSON
```

Check it with `gh api repos/OWNER/REPO/rulesets`. New tags are still
allowed; only moving or deleting one is refused, for everyone including the
owner. `scripts/scrub-history.sh` ends with `git push --force origin --tags`,
which the ruleset refuses: set the ruleset's enforcement to **Disabled**
(Settings → Rules → Rulesets) for the force-push, then back to **Active**.

### When it fails

The run fails, visibly, and makes nothing, when:

| Message | Cause | Fix |
|---|---|---|
| `CHANGELOG.md has no section for 1.6.7` | the heading was not renamed, or is spelt differently from the tag | fix the heading, commit, push `main`, then make it by hand (below) |
| `could not read CHANGELOG.md at ...` | the run started from a commit older than this workflow's notes script | make it by hand (below), which reads `main` |
| `tag 1.6.7 is not on GitHub` | a backfill was asked for before the tag was pushed | `git push origin 1.6.7` |
| `'x' is not a release tag` | a backfill typed something other than `1.6.7` or `v1.7` | type the tag |
| `the SBOM for 1.6.7 could not be made` | the tag breaks the no-dependency rule (a Go module or a third-party Python import), or its tree cannot be read; the message above it says which | `task sbom` on that commit shows the same message; fix it, tag again |

A release that already exists is left as it is, so running it again is safe,
and notes edited by hand on GitHub are never overwritten. The one exception is
a manual run for a release that has no SBOM: it adds the SBOM and touches
nothing else (see below). **Do not use "Re-run
jobs"** on a failed run: it reuses the tag's commit, so it reads the same
CHANGELOG and fails the same way.

### Making one by hand (backfill, or after a failed run)

**Actions → Release → Run workflow**, type the tag (`1.6.5`). A run started
this way reads `CHANGELOG.md` from `main`, which has every section, so it
works for old tags too and does not take the Latest badge from a newer
release. Or from the Mac:

```bash
gh workflow run release.yml --repo zany2dmax/cti-agent -f tag=1.6.5
```

The same run adds the SBOM to a release that exists without one, so the
releases made before this existed can be given theirs one at a time. It reads
the tag's own tree; for a tag from before `scripts/sbom.py` existed it uses the
script from `main` on that tree. It changes nothing else about the release.

One tag per run. Push release tags one at a time too, never with
`git push --tags`: GitHub sends no push event at all when more than three
tags arrive in one push, so none of them would get a release.

### What it does not do

- **Run in the company repo.** That repo merges these tags into its `main`, so
  it gets this file too, but `sync-upstream.yml` there already makes its
  releases. The job is skipped unless the repository is
  `zany2dmax/cti-agent`.
- **Create or move a tag.** It refuses a tag that is not already on GitHub.
- **Attach binaries.** The box builds from source (`cti-agent-update`), so a
  release is notes and the SBOM only. The SBOM is made on GitHub's runner, so its
  Go version is the runner's, not the box's; it lists what the code is made of.
- **Put the SBOM on the company copy.** That release is made by the company
  repo's `sync-upstream.yml`, which this repository does not control. Download
  `cti-agent-1.6.7.cdx.json` from the personal release if the company copy needs
  it, or ask for that workflow to copy the release's assets.
- **Use third-party actions.** It reads two files through the GitHub API at the
  run's commit, clones the public repository with `git` for the SBOM, and uses
  the `gh` CLI the runner already has, with the workflow's own token, limited to
  `contents: write`. The SBOM script runs with a scrubbed environment, so the
  token is not visible to it.
