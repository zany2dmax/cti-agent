package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

type Config struct {
	TenantID          string
	ClientID          string
	ClientSecret      string
	GraphMailbox      string
	GraphFolder       string
	GraphLookback     time.Duration
	LookupProvider    string
	QualysBaseURL     string
	QualysUsername    string
	QualysPassword    string
	QualysKBCachePath string
	QualysKBMaxAge    time.Duration
	ReportPath        string

	// MailboxLookback is how far back the CLEANUP lane looks, and it is
	// deliberately NOT GraphLookback.
	//
	// It used to share it, and 24h for both meant the window equalled the
	// interval between runs: a message arriving in the hour before the
	// cleanup fires is processed later that day, and by the next run it has
	// already fallen out of a 24h window. Never archived, ever. Four
	// advisories a day quietly accumulating in a shared inbox, looking like
	// the lane "sometimes misses some".
	//
	// This must exceed the time between runs with room for a missed one.
	MailboxLookback time.Duration
	// MailboxMinAge is how long a processed advisory stays in the inbox
	// before being filed away, so that behaviour does not depend on what time
	// the lane happens to run and a colleague reading this morning's roundup
	// still finds it where they left it.
	MailboxMinAge time.Duration

	JiraBaseURL    string
	JiraEmail      string
	JiraAPIToken   string
	JiraProjectKey string
	JiraIssueType  string
	// JiraAllowCreate is the project-key allowlist, and it is deliberately the
	// same shape as FLEET_ALLOW_TO: a comma-separated list the fleet may write
	// to, with no default. A ticket filed into the wrong project is the same
	// class of mistake as mail sent to the wrong distribution list, and both
	// are mistakes you cannot take back - a Jira issue, once created, has been
	// seen by whatever automation watches that project.
	JiraAllowCreate string
}

// Load returns the full configuration, Graph included. For commands that read
// the mailbox or send mail.
func Load() (Config, error) { return load(true, true, false) }

// LoadVulnLookup returns the configuration for a command that only queries the
// vulnerability scanner.
//
// cti-patchtuesday correlates against Host Detection but never touches a
// mailbox - mailer.py is the single outbound channel and the runner hands this
// command's output to it. Requiring Graph credentials to do a Qualys lookup
// meant a replay on a workstation failed with
//
//	missing required environment variables: [TENANT_ID CLIENT_ID
//	CLIENT_SECRET GRAPH_MAILBOX QUALYS_USERNAME QUALYS_PASSWORD QUALYS_BASE_URL]
//
// naming four variables it had no use for, and it meant a Graph credential
// rotation would take the monthly exposure figures down with it and report
// them as "NOT MEASURED". A command should only be able to fail on the
// credentials it actually needs.
func LoadVulnLookup() (Config, error) { return load(false, true, false) }

// LoadGraphOnly returns the configuration for a command that only talks to
// the mailbox.
//
// cti-mailbox reads the inbox and moves messages. It never asks the scanner
// anything, and it failed on a box with a complete fleet.env with:
//
//	missing required environment variables: [CLIENT_ID CLIENT_SECRET
//	GRAPH_MAILBOX QUALYS_BASE_URL QUALYS_PASSWORD QUALYS_USERNAME TENANT_ID]
//
// Three of those seven it has no use for. This is the same mistake as
// cti-patchtuesday demanding Graph credentials to do a Qualys lookup, in the
// opposite direction: a command should be able to fail on the credentials it
// needs and no others, because a list that includes irrelevant names sends
// the reader looking in the wrong file.
func LoadGraphOnly() (Config, error) { return load(true, false, false) }

// MaxLookback is the largest window a catch-up run may ask for.
//
// Ninety days. Not a performance limit - a typo limit. The failure this
// guards against is `--lookback 168000h` meaning "168000 hours" when the
// operator meant 168: nineteen years of mailbox, one Graph page at a time,
// and an enrich pass against NVD for every CVE in it. A window nobody
// intended is indistinguishable from a hung lane while it runs.
const MaxLookback = 90 * 24 * time.Hour

// ValidateLookback checks an operator-supplied catch-up window.
//
// Separate from the flag parsing so it can be tested without a process. Zero
// is rejected rather than treated as "use the default": a flag that was
// passed and then ignored is the kind of silence this codebase keeps finding,
// and `--lookback 0` almost certainly means the value came from an empty
// shell variable.
func ValidateLookback(d time.Duration) error {
	switch {
	case d <= 0:
		return fmt.Errorf("lookback must be positive, got %s "+
			"(an empty shell variable expands to this)", d)
	case d > MaxLookback:
		return fmt.Errorf("lookback %s is longer than the %s maximum; "+
			"if that was deliberate, raise config.MaxLookback deliberately too",
			d, MaxLookback)
	}
	return nil
}

// LoadJira returns the configuration for the ticketing lane: Jira plus the
// scanner it reads host counts from, and no Graph.
//
// Split for the same reason LoadVulnLookup is: cti-jira does not send mail -
// the digest runner does that - so demanding TENANT_ID to file a ticket would
// make a replay on a workstation fail on credentials it never uses.
func LoadJira() (Config, error) { return load(false, true, true) }

func load(needGraph, needQualys, needJira bool) (Config, error) {
	lookbackHours, err := strconv.Atoi(getenvDefault("GRAPH_LOOKBACK_HOURS", "24"))
	if err != nil || lookbackHours <= 0 {
		return Config{}, fmt.Errorf("GRAPH_LOOKBACK_HOURS must be a positive integer")
	}

	// How long a CVE->QID cache stays trustworthy. Past this the agent
	// refreshes it, because an expired mapping silently turns every newer CVE
	// into UNKNOWN, which reads like "not affected".
	kbMaxAgeHours, err := strconv.Atoi(getenvDefault("QUALYS_KB_MAX_AGE_HOURS", "168"))
	if err != nil || kbMaxAgeHours <= 0 {
		return Config{}, fmt.Errorf("QUALYS_KB_MAX_AGE_HOURS must be a positive integer")
	}

	mailboxLookbackHours, err := strconv.Atoi(getenvDefault("MAILBOX_LOOKBACK_HOURS", "72"))
	if err != nil || mailboxLookbackHours <= 0 {
		return Config{}, fmt.Errorf("MAILBOX_LOOKBACK_HOURS must be a positive integer")
	}
	mailboxMinAgeHours, err := strconv.Atoi(getenvDefault("MAILBOX_MIN_AGE_HOURS", "48"))
	if err != nil || mailboxMinAgeHours < 0 {
		return Config{}, fmt.Errorf("MAILBOX_MIN_AGE_HOURS must be zero or a positive integer")
	}
	// THE CLEANUP MUST NOT ARCHIVE MAIL THE DIGEST STILL NEEDS.
	//
	// cti-agent ingests from the INBOX over GRAPH_LOOKBACK_HOURS and rebuilds
	// its report from scratch every run. Archiving a message that is still
	// inside that window removes it from the next ingest, so any CVE reported
	// only by that message vanishes from tomorrow's digest - not because the
	// exposure changed, but because the mail was filed. The digest becomes a
	// function of mailbox tidiness rather than of the estate.
	//
	// This is not hypothetical. On 1 October a manual --for-real cleanup
	// archived three advisories hours after they arrived, and the next
	// morning's digest was missing what only they had reported.
	//
	// So the grace must be at least as long as the ingest window, with margin
	// - the two lanes run on independent timers and nothing synchronises them.
	if mailboxMinAgeHours > 0 && time.Duration(mailboxMinAgeHours)*time.Hour < cfg0GraphLookback(lookbackHours) {
		return Config{}, fmt.Errorf(
			"MAILBOX_MIN_AGE_HOURS (%d) must be at least GRAPH_LOOKBACK_HOURS (%d); "+
				"otherwise the cleanup lane archives advisories the digest has not "+
				"finished reading, and CVEs reported only by those messages drop out "+
				"of the next digest",
			mailboxMinAgeHours, lookbackHours)
	}
	// The trap this guards: a grace period at least as long as the window
	// means nothing is ever old enough AND still visible, so the lane
	// silently archives nothing and reports a clean run forever.
	if mailboxMinAgeHours >= mailboxLookbackHours {
		return Config{}, fmt.Errorf(
			"MAILBOX_MIN_AGE_HOURS (%d) must be less than MAILBOX_LOOKBACK_HOURS (%d); "+
				"otherwise a message is never both old enough to archive and still "+
				"inside the window, and the cleanup lane does nothing at all",
			mailboxMinAgeHours, mailboxLookbackHours)
	}

	cfg := Config{
		TenantID:     os.Getenv("TENANT_ID"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		// No default. A hardcoded address here shipped one organisation's
		// internal distribution list as the fallback for everyone else's
		// deployment, and an unconfigured install read that mailbox instead
		// of refusing to start. Same rule as the mailer: never guess an
		// address, fail and say which variable is missing.
		GraphMailbox:      os.Getenv("GRAPH_MAILBOX"),
		GraphFolder:       getenvDefault("GRAPH_FOLDER", "inbox"),
		GraphLookback:     time.Duration(lookbackHours) * time.Hour,
		LookupProvider:    getenvDefault("LOOKUP_PROVIDER", "qualys"),
		QualysBaseURL:     os.Getenv("QUALYS_BASE_URL"),
		QualysUsername:    os.Getenv("QUALYS_USERNAME"),
		QualysPassword:    os.Getenv("QUALYS_PASSWORD"),
		QualysKBCachePath: getenvDefault("QUALYS_KB_CACHE", "./qualys_kb_cache.json"),
		QualysKBMaxAge:    time.Duration(kbMaxAgeHours) * time.Hour,
		ReportPath:        getenvDefault("REPORT_PATH", "./cti-agent-report.md"),
		MailboxLookback:   time.Duration(mailboxLookbackHours) * time.Hour,
		MailboxMinAge:     time.Duration(mailboxMinAgeHours) * time.Hour,

		JiraBaseURL:  os.Getenv("JIRA_BASE_URL"),
		JiraEmail:    os.Getenv("JIRA_EMAIL"),
		JiraAPIToken: os.Getenv("JIRA_API_TOKEN"),
		// No defaults, on purpose. "Task" would have been the obvious one and
		// it is WRONG here: the CR project is a Service Management desk whose
		// issue types are IT Support, Off-Boarding, New-Hire IT Request and so
		// on - there is no Task at all, so a default would have failed at the
		// first create with a field error instead of at startup with a clear
		// one. Destinations get named explicitly in this codebase.
		JiraProjectKey:  os.Getenv("JIRA_PROJECT_KEY"),
		JiraIssueType:   os.Getenv("JIRA_ISSUE_TYPE"),
		JiraAllowCreate: os.Getenv("JIRA_ALLOW_CREATE"),
	}

	missing := []string{}
	if needGraph {
		for name, value := range map[string]string{
			"TENANT_ID":     cfg.TenantID,
			"CLIENT_ID":     cfg.ClientID,
			"CLIENT_SECRET": cfg.ClientSecret,
			"GRAPH_MAILBOX": cfg.GraphMailbox,
		} {
			if value == "" {
				missing = append(missing, name)
			}
		}
	}

	if needQualys && cfg.LookupProvider == "qualys" {
		for name, value := range map[string]string{
			"QUALYS_BASE_URL": cfg.QualysBaseURL,
			"QUALYS_USERNAME": cfg.QualysUsername,
			"QUALYS_PASSWORD": cfg.QualysPassword,
		} {
			if value == "" {
				missing = append(missing, name)
			}
		}
	}
	if needJira {
		for name, value := range map[string]string{
			"JIRA_BASE_URL":    cfg.JiraBaseURL,
			"JIRA_EMAIL":       cfg.JiraEmail,
			"JIRA_API_TOKEN":   cfg.JiraAPIToken,
			"JIRA_PROJECT_KEY": cfg.JiraProjectKey,
			"JIRA_ISSUE_TYPE":  cfg.JiraIssueType,
		} {
			if value == "" {
				missing = append(missing, name)
			}
		}
		// JIRA_ALLOW_CREATE is NOT in that list, because an empty allowlist is
		// a valid and meaningful state: it means "create nothing". Requiring
		// it here would make the error "you forgot a variable" when the honest
		// answer is "this install is configured to read Jira, not write it".
	}

	if len(missing) > 0 {
		// Sorted because the names come out of a map: the same misconfiguration
		// printed a differently-ordered list on each run, which makes two logs
		// look like two different faults.
		sort.Strings(missing)
		return Config{}, fmt.Errorf("missing required environment variables: %v", missing)
	}

	return cfg, nil
}

// cfg0GraphLookback is the ingest window as a Duration, from the already
// validated hour count. Named rather than inlined so the comparison above
// reads as the question it is asking.
func cfg0GraphLookback(hours int) time.Duration {
	return time.Duration(hours) * time.Hour
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
