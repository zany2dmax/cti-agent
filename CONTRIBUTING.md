# Contributing

For anyone sending a change upstream, or working in a fork of this
repository. To adapt the fleet to your organization without changing core
code (your notes, your lanes, your install paths), read
[FORKING.md](FORKING.md) first: most of that belongs in a fork's own files,
not here.

To report a vulnerability, don't open an issue or a pull request. Use private
vulnerability reporting, as [SECURITY.md](SECURITY.md#reporting-a-vulnerability)
describes.

## Set up a checkout

Once per clone, install the git hooks:

```bash
./scripts/dev-setup.sh
```

The `pre-commit` hook runs `gofmt` over staged Go files. `--status` checks
that it is installed and current ([RUNBOOK.md §6](docs/guides/development.md#6-local-development-loop)).
[Developing and releasing](docs/guides/development.md) has the local loop,
the Mac-to-box workflow, the man pages and the release steps.

You need Go and [Task](https://taskfile.dev), plus the tools the gates run:
`golangci-lint`, `staticcheck`, `gosec`, `govulncheck`, `ruff`, `bandit` and
`shellcheck`. They are dev-machine tools; nothing is installed on the box.

## The ship gates

`task ship` is the only way a change is pushed. It runs these in order and
stops at the first failure:

| Step | What it checks |
|---|---|
| `fmt:check` | every Go file is `gofmt`-clean. It never reformats: run `task fmt` and commit |
| `build` | `go build ./...` |
| `test` | `go test ./...` and every Python test in `fleet-kit/tests` |
| `lint` | `golangci-lint` (`.golangci.yml`) |
| `scan` | `staticcheck` (correctness, not security) |
| `gosec` | insecure Go patterns |
| `govulncheck` | known vulnerabilities in the code paths used, standard library included |
| `lint:py` | `ruff` on the Python |
| `bandit` | insecure Python patterns |
| `lint:shell` | `shellcheck` on the runners, installers and scripts |
| `sbom` | the no-dependency rule (below), then the SBOM in `dist/sbom/` |
| `lane:check` | generated units are current, and the beat's grant matches the lanes' `beat_grants` |
| `release:check` | the latest tag's own commit has its CHANGELOG section and cheat-sheet stamp |
| `push` | `git push` |

Each step prints one `ok` line; a failing step prints all of its output.
`task check` runs most of them without pushing, and prints everything: it
adds `go vet` and the syntax tests, and leaves out `build`, `lane:check` and
`release:check`. Run `task lane:check` yourself after touching a lane.

`task ship` pushes `main`. It never pushes tags. Releases are tagged by the
maintainer ([RUNBOOK.md §11i](docs/guides/development.md#11i-cutting-a-release)), and a
pushed tag never moves.

A finding is fixed, or annotated at the line with its reason
(`#nosec RULE -- reason`, `//nolint:linter // reason`). There is no blanket
exclusion list.

## The rules

Each of these is held by a test or a gate unless it says otherwise.

**Standard library only.** `go.mod` has no dependencies, and the Python is
standard library only: no `pip install`, no `requirements.txt`. The `sbom`
step fails on a module in `go.mod`, a `go.work` or `vendor/` directory, a
Python import that isn't the standard library or a sibling file, and any
dynamic import. If a change seems to need a library, say so in the pull
request before writing it. [SECURITY.md](SECURITY.md#supply-chain) says why.

**New features are built in Go.** Python is kept for the few places that
need it ([SECURITY.md](SECURITY.md#why-two-languages-and-why-that-is-the-security-decision)).

**Every command and flag is in `fleet-kit/fleet/commands.manifest`, in the
same change.** Its `about`, `runs` (`read`, `local` or `effect`), `modes`
for an effect command, every flag and subcommand, and a `risk:` line for a
flag that writes or changes something. `cti-agent`'s command list, `--help`
and the TAB completions are read from it. The manifest test fails when the
code and the file differ.

**An effect command says how to run it.** A command that sends mail, moves
mail, files tickets or changes another system takes exactly one of
`--dry-run` or `--for-real` (and `--to-dev` where there is a test send).
With neither, it prints usage and exits 2. There is no default, in either
direction. Use `cli.Resolve` (`internal/cli`) in Go and `fleet_require_mode`
(`fleet-kit/fleet/share/fleet-mode.sh`) in bash. Every unit and every
internal call passes a mode explicitly. A bare `--for-real` never also skips
a safety check; that needs its own flag.

**Man pages document every flag.** Every operator command has a page in
`man/man1/`, and a test fails when a flag or subcommand the code accepts is
missing from it.

**Lane units are generated.** Each lane is described once, in
`fleet-kit/lanes/<lane>.toml` ([docs/lane-manifest.md](docs/lane-manifest.md)).
Edit the manifest, never a generated `.service` unit, and run:

```bash
task lane:write
```

It writes the units, the orchestrator's lane table, `lanes.list`, the
`fleet.d` examples, the Go lane list and the lane reference
([docs/lanes.md](docs/lanes.md)), then the settings and credentials
blocks inside each unit, which come from `scripts/settings-manifest`. Never
edit between a `BEGIN ... generated ... do not edit` marker and its `END`.
Timers stay hand-written and are checked against the manifest. A grant
added to the check-in beat must be declared in a lane's `beat_grants`, or
`lane:check` fails. Commit the generated files: a test fails when one isn't
tracked.

**Settings come from code.** A new setting goes in
`fleet-kit/fleet/fleet.env.example` with a comment, and
`scripts/settings-manifest --write` records which programs read it. Fill in
the hand-kept fields (secret or not, when required, the default). A test
fails when the code, the example and the manifest disagree.

**A CHANGELOG entry under `## Unreleased`.** Say what changed and why, in
the subsection it belongs to (Added, Changed, Fixed, Security), and what an
operator has to do on update, if anything. Not checked by a test.

**No real data in any tracked file.** No company, site, host, tenant,
mailbox, person or scan names, in code, tests, fixtures, docs or commit
messages. Use placeholders: `example.com`, `host-a`, `192.0.2.x`, invented
tenant ids. Git history is permanent, so a leak is fixed by rotation, not by
deleting the line. A test fails if `domains.txt` is in the tree; the rest is
on review.

**Tests use fake servers.** No test in `task test` reaches a real service.
Go tests run the client against an `httptest` server with invented data, and
the Python tests fake what they call. The `eval:*` tasks, which call the
real model, are run by hand and never by `task ship`. A new vendor gets a probe flag, so its first live run
is a diagnosis ([INTERFACES.md §5](INTERFACES.md#5-how-to-put-a-new-tool-behind-an-interface)).

**Small things the tests catch.** A file starting with `#!` is committed
executable (`git update-index --chmod=+x FILE`). Runners must work with
macOS's bash 3.2: write `${A[@]+"${A[@]}"}`, never a bare `"${A[@]}"` that
may be empty.

## Adding a lane or a provider

Two Claude Code skills in `.claude/skills/` walk through each step,
including the parts no generator writes:

- **`/add-lane`**: a new recurring job, from command to timer, with the
  orchestrator's notes and checks.
- **`/add-provider`**: a new vendor behind an existing interface: the
  package, its one selection line, settings, tests against a fake server, a
  probe flag and docs.

Without Claude Code, follow [INTERFACES.md §5](INTERFACES.md#5-how-to-put-a-new-tool-behind-an-interface)
for a provider and [docs/lane-manifest.md](docs/lane-manifest.md) for a
lane. In a fork, list what you added in the org pack's `recipe.md`
([docs/org-pack.md](docs/org-pack.md)), so whoever pulls from upstream knows.

## Sending a change upstream

- Keep a change to one purpose, with its tests, man page, manifest lines and
  CHANGELOG entry in the same commit.
- Run `task check` (or `task ship` in a fork) before you open the pull
  request, and say in it what you ran.
- A change to anything that sends or moves mail, files tickets, or changes a
  gate or the beat's grant needs a sentence on why it is safe. Expect it to
  be read line by line.
- Org-specific notes, lanes and providers that only your organization needs
  stay in your fork ([FORKING.md](FORKING.md)).
