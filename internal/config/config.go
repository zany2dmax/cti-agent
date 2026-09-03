package config

import (
	"fmt"
	"os"
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

func Load() (Config, error) {
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
		TenantID:          os.Getenv("TENANT_ID"),
		ClientID:          os.Getenv("CLIENT_ID"),
		ClientSecret:      os.Getenv("CLIENT_SECRET"),
		GraphMailbox:      getenvDefault("GRAPH_MAILBOX", "cybersecurity@crhomeusa.com"),
		GraphFolder:       getenvDefault("GRAPH_FOLDER", "inbox"),
		GraphLookback:     time.Duration(lookbackHours) * time.Hour,
		LookupProvider:    getenvDefault("LOOKUP_PROVIDER", "qualys"),
		QualysBaseURL:     os.Getenv("QUALYS_BASE_URL"),
		QualysUsername:    os.Getenv("QUALYS_USERNAME"),
		QualysPassword:    os.Getenv("QUALYS_PASSWORD"),
		QualysKBCachePath: getenvDefault("QUALYS_KB_CACHE", "./qualys_kb_cache.json"),
		QualysKBMaxAge:    time.Duration(kbMaxAgeHours) * time.Hour,
		ReportPath:        getenvDefault("REPORT_PATH", "./cti-qualys-report.md"),
	}

	missing := []string{}
	for name, value := range map[string]string{
		"TENANT_ID":     cfg.TenantID,
		"CLIENT_ID":     cfg.ClientID,
		"CLIENT_SECRET": cfg.ClientSecret,
	} {
		if value == "" {
			missing = append(missing, name)
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
