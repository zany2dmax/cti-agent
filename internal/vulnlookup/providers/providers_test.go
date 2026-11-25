package providers

import (
	"context"
	"os"
	"path/filepath"
	"sort"
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

func TestEveryNameBuilds(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range Names {
		p, err := Build(config.Config{LookupProvider: n})
		if err != nil || p == nil {
			t.Fatalf("%q does not build: %v", n, err)
		}
		if seen[p.Name()] {
			t.Errorf("%q builds %s, which another name already built", n, p.Name())
		}
		seen[p.Name()] = true
	}
}

// A provider package nothing selects is dead code a reader takes for a
// working option. Each one under internal/vulnlookup is reached by a name:
// its directory is the provider's Name().
func TestEveryProviderPackageHasAName(t *testing.T) {
	built := map[string]bool{}
	for _, n := range Names {
		p, _ := Build(config.Config{LookupProvider: n})
		built[p.Name()] = true
	}
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "providers" {
			continue
		}
		if files, _ := filepath.Glob(filepath.Join("..", e.Name(), "*.go")); len(files) == 0 {
			continue
		}
		if !built[e.Name()] {
			missing = append(missing, e.Name())
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("provider package(s) no LOOKUP_PROVIDER name selects: %v (add a case to Build and the name to Names)", missing)
	}
}
