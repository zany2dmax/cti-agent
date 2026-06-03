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
		CVE:    cve,
		Status: vulnlookup.StatusUnknown,
		Reason: "lookup skipped",
	}, nil
}
