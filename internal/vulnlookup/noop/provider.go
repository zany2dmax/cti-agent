package noop

import (
	"context"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Name() string {
	return "noop"
}

func (p *Provider) LookupCVE(ctx context.Context, cve string) (vulnlookup.Result, error) {
	return vulnlookup.Result{
		CVE: cve,
		// Source must be set even here. Without it the report's Provider
		// column comes out blank while the header claims "noop", which reads
		// like the lookup layer failed rather than being deliberately skipped.
		Source: p.Name(),
		Status: vulnlookup.StatusUnknown,
		Reason: "lookup skipped (LOOKUP_PROVIDER=none)",
	}, nil
}
