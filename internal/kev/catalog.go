package kev

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CatalogFile is the CISA KEV catalog enrich.py keeps, refreshed every 12
// hours on every digest run: {"fetched": "...", "data": {"CVE-...": {...}}}.
const CatalogFile = "kev-cache.json"

// LoadCatalog returns the set of CVEs on CISA KEV, from the copy enrich.py
// keeps under $FLEET_HOME/state.
//
// The catalog only ever grows, so an old copy is still right about every
// CVE it lists; it may lack the newest additions until the next digest run
// refreshes it. A missing or unreadable file is an error, for the caller to
// report: an empty set would read as "nothing is on KEV".
func LoadCatalog(fleetHome string) (map[string]bool, error) {
	home := strings.TrimSpace(fleetHome)
	if home == "" {
		return nil, fmt.Errorf("FLEET_HOME is not set, so the KEV catalog cannot be found")
	}
	path := filepath.Join(home, "state", CatalogFile)
	// #nosec G304 -- FLEET_HOME from the service configuration plus a fixed name.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var blob struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(blob.Data) == 0 {
		return nil, fmt.Errorf("%s lists no CVEs", path)
	}
	out := make(map[string]bool, len(blob.Data))
	for cve := range blob.Data {
		out[strings.ToUpper(strings.TrimSpace(cve))] = true
	}
	return out, nil
}
