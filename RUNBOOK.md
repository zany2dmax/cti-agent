# RUNBOOK

The fleet's operating guide, split by topic. Every section keeps its number
and heading here, pointing to where it now lives, so "RUNBOOK 11n" in a
message or a man page still finds it.

Read [README.md](README.md) first for *what* the fleet is, and
[INSTALL.md](INSTALL.md) for the short path from a clean box to a working one.

| Topic | Sections |
|---|---|
| [Setting up the fleet](docs/guides/setup.md) | Where it lives, Before you start, 1, 2, 3, 8, 9 |
| [Configuring the fleet](docs/guides/configuration.md) | 4, 11m, 11n, 11o, 11p |
| [Developing and releasing](docs/guides/development.md) | 5, 6, 7, 11h, 11i |
| [Operating the fleet](docs/guides/operations.md) | 11b, 11c, 11d, 11e, 11l, 12, 13, 14, 15 |
| [The mailbox cleanup lane](docs/lanes/mailbox.md) | 10 |
| [The Patch Tuesday lane](docs/lanes/patchtuesday.md) | 11, 11a |
| [The application-security lanes](docs/lanes/appscan.md) | 11f |
| [The domains lane](docs/lanes/domains.md) | 11g |
| [Advisory triage](docs/lanes/triage.md) | 11j, 11k |

## Where it lives

Moved to [Setting up the fleet](docs/guides/setup.md#where-it-lives).

## Before you start

Moved to [Setting up the fleet](docs/guides/setup.md#before-you-start).

## 1. Microsoft Entra app registration

Moved to [Setting up the fleet](docs/guides/setup.md#1-microsoft-entra-app-registration).

## 2. Qualys API access

Moved to [Setting up the fleet](docs/guides/setup.md#2-qualys-api-access).

## 3. The NVD API key

Moved to [Setting up the fleet](docs/guides/setup.md#3-the-nvd-api-key).

## 4. Configuration

Moved to [Configuring the fleet](docs/guides/configuration.md#4-configuration).

## 5. The agent alone

Moved to [Developing and releasing](docs/guides/development.md#5-the-agent-alone).

## 6. Local development loop

Moved to [Developing and releasing](docs/guides/development.md#6-local-development-loop).

## 7. The two-box workflow: Mac to Fedora

Moved to [Developing and releasing](docs/guides/development.md#7-the-two-box-workflow-mac-to-fedora).

## 8. Installing the fleet

Moved to [Setting up the fleet](docs/guides/setup.md#8-installing-the-fleet).

## 9. Enabling the timers, in order

Moved to [Setting up the fleet](docs/guides/setup.md#9-enabling-the-timers-in-order).

## 10. Rolling out mailbox cleanup

Moved to [The mailbox cleanup lane](docs/lanes/mailbox.md#10-rolling-out-mailbox-cleanup).

## 11. The monthly Patch Tuesday lane

Moved to [The Patch Tuesday lane](docs/lanes/patchtuesday.md#11-the-monthly-patch-tuesday-lane).

## 11a. Catching up after the lane was off

Moved to [The Patch Tuesday lane](docs/lanes/patchtuesday.md#11a-catching-up-after-the-lane-was-off).

## 11b. The mailer

Moved to [Operating the fleet](docs/guides/operations.md#11b-the-mailer).

## 11c. Verifying the Jira connection

Moved to [Operating the fleet](docs/guides/operations.md#11c-verifying-the-jira-connection).

## 11d. What version is this box running?

Moved to [Operating the fleet](docs/guides/operations.md#11d-what-version-is-this-box-running).

## 11e. Taking a host off the schedule

Moved to [Operating the fleet](docs/guides/operations.md#11e-taking-a-host-off-the-schedule).

## 11f. The weekly application-security lane

Moved to [The application-security lanes](docs/lanes/appscan.md#11f-the-weekly-application-security-lane).

## 11g. The weekly domains lane

Moved to [The domains lane](docs/lanes/domains.md#11g-the-weekly-domains-lane).

## 11h. Man pages

Moved to [Developing and releasing](docs/guides/development.md#11h-man-pages).

## 11i. Cutting a release

Moved to [Developing and releasing](docs/guides/development.md#11i-cutting-a-release).

## 11j. The CrowdStrike API client

Moved to [Advisory triage](docs/lanes/triage.md#11j-the-crowdstrike-api-client).

## 11k. Advisory triage by hand

Moved to [Advisory triage](docs/lanes/triage.md#11k-advisory-triage-by-hand).

## 11l. The audit trail

Moved to [Operating the fleet](docs/guides/operations.md#11l-the-audit-trail).

## 11m. What is in fleet.env

Moved to [Configuring the fleet](docs/guides/configuration.md#11m-what-is-in-fleetenv).

## 11n. Moving secrets into systemd credentials

Moved to [Configuring the fleet](docs/guides/configuration.md#11n-moving-secrets-into-systemd-credentials).

## 11o. Settings per lane

Moved to [Configuring the fleet](docs/guides/configuration.md#11o-settings-per-lane).

## 11p. The org pack

Moved to [Configuring the fleet](docs/guides/configuration.md#11p-the-org-pack).

## 12. Verifying a run

Moved to [Operating the fleet](docs/guides/operations.md#12-verifying-a-run).

## 13. Report sensitivity

Moved to [Operating the fleet](docs/guides/operations.md#13-report-sensitivity).

## 14. Scanner KB cache freshness

Moved to [Operating the fleet](docs/guides/operations.md#14-scanner-kb-cache-freshness).

## 15. When something breaks

Moved to [Operating the fleet](docs/guides/operations.md#15-when-something-breaks).
