# Where the fleet is installed

By default the fleet uses the FHS layout every box has run:

| What | Where |
|---|---|
| Code: binaries, runners, the orchestrator's files | `/opt/cti-agent` |
| Config: `fleet.env` or `fleet.d/`, `domains.txt`, the org pack | `/etc/cti-agent` |
| State: `memory.db`, reports, traces | `/var/lib/cti-agent` |
| The audit trail | `/var/log/cti-agent` |
| The service account (user and group) | `ctiagent` |
| The Go source the installer builds | this kit's own git remote |

A fork that needs to install somewhere else commits a `layout.env` at the top
of its repository. Upstream never ships one, so a fork's `layout.env` never
conflicts with a pull from upstream. Every key is optional:

```
LAYOUT_CODE_DIR=/srv/fleet/code
LAYOUT_CONF_DIR=/srv/fleet/etc
LAYOUT_STATE_DIR=/srv/fleet/state
LAYOUT_LOG_DIR=/srv/fleet/log
LAYOUT_USER=fleet
LAYOUT_REPO=https://github.com/example/cti-agent
```

## The rules

The installer and the updater read the file (`fleet-kit/layout.sh`). They
never source it: it sits in a checkout, and they run as root. Any of these
stops the install before anything changes:
- a key it doesn't know, or a line that isn't `KEY=value`
- a path that isn't absolute, plain (letters, digits, `. _ - /`) and free of
  `..`, or that is `/` itself
- a directory inside another, or a new path that holds one of the default
  paths (rewriting would then change it twice)
- a path under `/home`, `/root`, `/tmp`, `/var/tmp`, `/run`, `/proc`, `/sys`,
  `/dev` or `/boot`. The units run with `ProtectHome=yes` and `PrivateTmp`,
  so most of those are hidden from every lane
- an account name that isn't lower case
- a repository that isn't an `https://`, `ssh://` or `git@` URL

**One name is both user and group.** The files say `ctiagent` for both, and
the two can't be told apart when rewriting.

**The repository defaults to the kit's own `origin`.** So a fork's box builds
the fork's Go code, not upstream's, without any setting.

## How it works

- **The repository's files keep the default paths.** That covers the units,
  runners, root tools, the orchestrator's instructions and man pages, plus
  everything generated from them, so nothing a forker generates differs.
- **The installer rewrites the installed copies** of every text file it puts
  down, in two passes: after the code and the orchestrator's files, and
  again before verification. A path is rewritten where it ends, so
  `/opt/cti-agent/bin` changes and `/var/lib/cti-agent-update` doesn't.
  Rewriting twice changes nothing, so the orchestrator's composed `CLAUDE.md`
  is rewritten before it's hashed, and an update doesn't mistake it for an
  operator's edit.
- **In the units, `StateDirectory=` and `LogsDirectory=` become
  `ReadWritePaths=`** for the layout's state and log directories. Those two
  systemd settings only ever mean `/var/lib` and `/var/log`, and
  `ProtectSystem=strict` makes everything else read-only.
- **Every Go binary is stamped with the layout at build time**
  (`internal/layout`, by `-X`, like the version). A test fails if any other
  Go file names one of these paths.
- **The updater reads the same `layout.env`,** so its snapshot and rollback
  cover the layout's directories.

## Caveats

- **SELinux.** The FHS paths were chosen so the default Fedora policy labels
  them correctly. Elsewhere it may not. The installer warns when SELinux is
  Enforcing; if a lane fails with a permission error, label the new paths like
  the defaults:

  ```bash
  sudo semanage fcontext -a -e /opt/cti-agent /srv/fleet/code
  ```

  ```bash
  sudo restorecon -R /srv/fleet/code
  ```

  Do the same for each moved directory.
- **A new box, not a move.** The layout is read at install time. Moving a box
  that already runs to another layout also means moving its config, state
  and audit trail, and is not automated.
- The secrets store (`/etc/credstore.encrypted`), the unit names
  (`cti-agent-*`) and where the root tools, man pages and completions go are
  fixed. They're systemd's and the distribution's places, not the fleet's.
