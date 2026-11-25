---
name: add-provider
description: Add a vendor behind one of the fleet's interfaces (a CVE lookup provider, a web app scanner, a registrar, a mail gateway) in a fork of cti-agent - the package, the one selection line, its settings, tests with invented data, docs, and the recipe line. Use when someone wants the fleet to work with a tool it does not support yet.
---

# /add-provider: put a new tool behind an existing interface

Read `INTERFACES.md` sections 5 and 6 first: they hold the contract (one
package, one selection point, tri-state results), and this skill follows
them. If no interface fits the tool, stop. Section 5's rule is to extract an
interface only when a second implementation is real, and that is a design
conversation, not this skill.

## The rules

- **Standard library only.** The module has no dependencies, and `task sbom`
  fails the ship if one is added. Write the HTTP calls with `net/http` and
  `internal/httpx`, the way the existing vendors do.
- **Invented data in every tracked file:** `example.com`, `host-a`,
  `192.0.2.x`. Never a real tenant, host, site or application name. The
  repository may be public.
- **Never ask for, or write down, a real credential.** Tests use a fake
  server (`httptest`), and the operator stores real secrets with
  `cti-agent-secrets set`.
- **Add files, and touch core at one line.** The new package plus one case in
  the selection function. If more of the core seems to need changing, stop
  and say what and why before doing it.

## Steps

1. **Pick the registry.** Each interface has exactly one place that chooses
   the implementation:

   | Kind | Interface | Selection point |
   |---|---|---|
   | CVE exposure | `vulnlookup.LookupProvider` | `internal/vulnlookup/providers/providers.go`: `Build`, and add the name to `Names` |
   | Web app scanner | `appscan.Provider` and capabilities | `cmd/cti-appscan/wiring.go`: `providers`, `newScanner` |
   | Registrar | `domains.Registrar` | `cmd/cti-domains/main.go`: `registrarFor`, plus a value of `DOMAINS_REGISTRAR` |
   | Mail gateway | `domains.MailGateway` | `cmd/cti-domains/main.go`: `gatewayFor`, plus a value of `DOMAINS_MAIL_GATEWAY` |

2. **Write the package** beside the others (`internal/vulnlookup/<name>/`,
   `internal/appscan/<name>/`, `internal/domains/<name>/`). Implement the
   whole interface, including `UNKNOWN` when the tool can't say. Never
   report a guess as `NOT_PRESENT`.

3. **Add the one selection line,** and nothing else in core. The registry
   tests fail until you do, naming the package:
   - `internal/vulnlookup/providers`: `TestEveryProviderPackageHasAName`
   - `fleet-kit/tests/test_registries.py`

4. **Settings.**
   - Add the tool's settings to `fleet-kit/fleet/fleet.env.example`, in its
     section, with a comment saying what each is and that empty or `none`
     means off.
   - Add any secret to `settings.manifest` by hand as `secret: yes`, and a
     login as `credential: yes`.
   - Then run, and review the diff:

     ```bash
     task lane:write
     ```

     The settings and the units' credential grants come out of that.
   - Require the credentials only when this provider is selected.

5. **Tests with a fake server.** Cover:
   - a good answer
   - each error the tool's API can return
   - the `UNKNOWN` case

   Copy the shape of the existing vendor's tests.

6. **A probe for the first live run.** Field names from vendor docs are a
   hypothesis. Add a `--probe` or `--request-file` flag, as
   `cti-appreport --probe-findings` does, so the first real call is a
   diagnosis. Add any new flag to `commands.manifest` and the command's man
   page; a test fails on drift.

7. **Docs.**
   - The man page for any new setting.
   - `INTERFACES.md`: move the vendor from "where new interfaces could go" to
     "the interfaces that exist".
   - A `CHANGELOG.md` entry under Unreleased that ends with how to turn the
     vendor on.

8. **The recipe line.** Append one line to the fork's `org/recipe.md`, for
   example: "lookup provider `internal/vulnlookup/<name>`
   (LOOKUP_PROVIDER=<name>), <commit>". When the fork pulls upstream, that
   list is what to check still works.

9. **Ship it:**

   ```bash
   task ship
   ```

   Every gate has to pass. The registry tests and `lane:check` catch most
   omissions by name.

Then the operator stores the secrets on the box
(`sudo cti-agent-secrets set NAME`), sets the selecting value
(`LOOKUP_PROVIDER=<name>` or similar), runs the probe, and finally the lane's
`--dry-run`.
