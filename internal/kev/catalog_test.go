package kev

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCatalog(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		if err := os.WriteFile(filepath.Join(home, "state", CatalogFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestTheCatalogIsReadFromEnrichsCache(t *testing.T) {
	home := writeCatalog(t, `{"fetched":"2026-11-11T00:00:00+00:00","data":{"CVE-2026-0001":{"kev_due":"2026-12-01"}," cve-2026-0002 ":{}}}`)
	got, err := LoadCatalog(home)
	if err != nil {
		t.Fatal(err)
	}
	if !got["CVE-2026-0001"] || !got["CVE-2026-0002"] || len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

// Missing, empty or broken is an error, never an empty set that reads as
// "nothing is on KEV".
func TestAnUnusableCatalogIsAnError(t *testing.T) {
	for name, body := range map[string]string{
		"missing": "", "empty": `{"data":{}}`, "broken": `{"data":`,
	} {
		if _, err := LoadCatalog(writeCatalog(t, body)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := LoadCatalog(""); err == nil {
		t.Error("no FLEET_HOME: no error")
	}
}
