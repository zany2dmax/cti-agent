package crowdstrike

import (
	"context"
	"fmt"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

// Client is a placeholder implementation showing where a CrowdStrike Exposure
// Management / Spotlight lookup can be added later.
type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Name() string { return "crowdstrike" }

func (c *Client) LookupCVE(ctx context.Context, cve string) (vulnlookup.Result, error) {
	return vulnlookup.Result{
		CVE:    cve,
		Source: c.Name(),
		Status: vulnlookup.StatusUnknown,
		Reason: "CrowdStrike lookup provider is not implemented yet",
	}, fmt.Errorf("crowdstrike lookup provider is not implemented yet")
}
