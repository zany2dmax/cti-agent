package providers

import (
	"context"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

func TestNoneNeedsNoQualysCredentials(t *testing.T) {
	for _, v := range []string{"none", "noop", ""} {
		p, err := Prepare(context.Background(), config.Config{LookupProvider: v})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		r, err := p.LookupCVE(context.Background(), "CVE-2026-0001")
		if err != nil || r.Status != vulnlookup.StatusUnknown {
			t.Errorf("%q: %+v %v", v, r, err)
		}
	}
}

func TestUnsupportedValueIsAnError(t *testing.T) {
	if _, err := Build(config.Config{LookupProvider: "nessus"}); err == nil {
		t.Fatal("want an error")
	}
	if _, err := Prepare(context.Background(), config.Config{LookupProvider: "nessus"}); err == nil {
		t.Fatal("want an error from Prepare")
	}
}
