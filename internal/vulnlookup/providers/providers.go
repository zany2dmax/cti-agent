// Package providers is the one place LOOKUP_PROVIDER is turned into a
// vulnlookup.LookupProvider, so every command that looks a CVE up honours the
// same setting.
package providers

import (
	"context"
	"fmt"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/crowdstrike"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/noop"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/qualys"
)

// Build returns the provider LOOKUP_PROVIDER names. An unknown value is an
// error, never a silent fallback.
func Build(cfg config.Config) (vulnlookup.LookupProvider, error) {
	switch cfg.LookupProvider {
	case "qualys":
		return qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword,
			cfg.QualysKBCachePath, cfg.QualysKBMaxAge), nil
	case "crowdstrike":
		return crowdstrike.New(), nil
	case "none", "noop", "":
		return noop.New(), nil
	default:
		return nil, fmt.Errorf("unsupported LOOKUP_PROVIDER %q", cfg.LookupProvider)
	}
}

// Prepare builds the provider and, for Qualys, loads or refreshes the local
// KnowledgeBase cache. Other providers have nothing to load.
func Prepare(ctx context.Context, cfg config.Config) (vulnlookup.LookupProvider, error) {
	p, err := Build(cfg)
	if err != nil {
		return nil, err
	}
	if q, ok := p.(*qualys.Client); ok {
		if _, err := q.LoadOrBuildKBCache(ctx, cfg.QualysKBCachePath); err != nil {
			return nil, err
		}
	}
	return p, nil
}
