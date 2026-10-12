# Man page conventions

Every command an operator runs has a page in `man/man1/<command>.1`, written
in man(7) roff. The installer copies them to `/usr/local/share/man/man1`, so
`man cti-domains` works on the fleet box. `fleet-kit/tests/test_lanes.py`
fails if a command gains a flag its page does not document.

Read one locally with `man ./man/man1/cti-domains.1`.

## Sections, in this order

| Section | Required | Contents |
|---|---|---|
| `NAME` | yes | `command \- one line`, nothing else |
| `SYNOPSIS` | yes | Every invocation form. `\fB` for literal text, `\fI` for placeholders, `[...]` for optional |
| `DESCRIPTION` | yes | What it does, who runs it (timer, runner, operator), and what it will **not** do |
| `COMMANDS` | if it has subcommands | One `.TP` per subcommand with its own arguments |
| `OPTIONS` | if it has flags | One `.TP` per flag: type, default, and what changes when it is set. Every flag the code accepts, including dry-run and debugging flags |
| `ENVIRONMENT` | if it reads any | Every variable it reads, its default, and which `fleet.env` section it lives in |
| `FILES` | if it reads or writes any | Paths in the Fedora layout (`/etc/cti-agent`, `/var/lib/cti-agent`, `/opt/cti-agent`), modes where they matter |
| `EXIT STATUS` | yes | Every exit code and what it means, including "always 0" where that is deliberate |
| `EXAMPLES` | yes | The commands an operator actually types, through `sudo cti-agent` |
| `SEE ALSO` | yes | Related pages, then the RUNBOOK section |

## Markup

- Header: `.TH CTI-DOMAINS 1 "2026-10-12" "cti-agent 1.3" "CTI Fleet Manual"`
- Flags written `\fB\-\-name\fR \fIVALUE\fR`. Always the double-dash form and
  always `\-` (a real hyphen-minus), so they copy and paste. Go's flag package
  also accepts a single dash; say so once in OPTIONS.
- Defaults as `Default:\~\fB8\fR.` at the end of the flag's paragraph.
- Environment variables in `\fBNAME\fR`. Paths in `\fI/path\fR`.
- Examples in `.EX` / `.EE` blocks.
- No real organisation data: this repository is public. Domains are
  `example.com`, hosts `host-a`, addresses from 192.0.2.0/24.

## Accuracy

Pages are written from the source, not from memory: the flag definitions in
`cmd/*/main.go`, `add_argument` in the Python lanes, the `case` arguments in
the runners. When a flag changes, the page changes in the same commit; the
drift test makes forgetting a red build.
