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
}

// Load returns the full configuration, Graph included. For commands that read
// the mailbox or send mail.
func Load() (Config, error) { return load(true) }

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
func LoadVulnLookup() (Config, error) { return load(false) }

func load(needGraph bool) (Config, error) {
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

	if cfg.LookupProvider == "qualys" {
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
	if len(missing) > 0 {
		// Sorted because the names come out of a map: the same misconfiguration
		// printed a differently-ordered list on each run, which makes two logs
		// look like two different faults.
		sort.Strings(missing)
		return Config{}, fmt.Errorf("missing required environment variables: %v", missing)
	}

	return cfg, nil
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
