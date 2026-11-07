package main

// wiring.go is the only file in this command that names a scanner vendor.
// Adding Invicti or Wiz is a package that implements appscan.Provider and the
// appscan capabilities it has, plus a line in each of the two places below.
// TestOnlyWiringNamesAVendor fails the build if that stops being true.

import (
	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/appscan/qualys"
	"github.com/zany2dmax/cti-agent/internal/config"
)

// providers parse each vendor's completion notifications.
var providers = []appscan.Provider{qualys.Provider{}}

// newScanner is the scanner API, or nil when no credentials are set.
func newScanner(cfg config.Config) appscan.Scanner {
	if cfg.QualysBaseURL == "" || cfg.QualysUsername == "" {
		logf("note   : no scanner credentials configured - reporting counts from the notifications only")
		return nil
	}
	return qualys.NewAPI(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword)
}
