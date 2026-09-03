package qualys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const kbXML = `<?xml version="1.0" encoding="UTF-8"?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <VULN_LIST>
      <VULN>
        <QID>92272</QID>
        <CVE_LIST>
          <CVE><ID>CVE-2026-83549</ID></CVE>
          <CVE><ID>cve-2026-83548</ID></CVE>
        </CVE_LIST>
      </VULN>
      <VULN>
        <QID>92275</QID>
        <CVE_LIST>
          <CVE><ID>CVE-2026-83549</ID></CVE>
        </CVE_LIST>
      </VULN>
      <VULN>
        <QID>0</QID>
        <CVE_LIST><CVE><ID>CVE-2026-00001</ID></CVE></CVE_LIST>
      </VULN>
      <VULN>
        <QID>555</QID>
        <CVE_LIST><CVE><ID>  </ID></CVE></CVE_LIST>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`

func TestParseKB(t *testing.T) {
	got, err := parseKB([]byte(kbXML))
	if err != nil {
		t.Fatalf("parseKB: %v", err)
	}
	// Two QIDs map to the same CVE, and they must be merged, sorted, deduped.
	if q := got["CVE-2026-83549"]; len(q) != 2 || q[0] != 92272 || q[1] != 92275 {
		t.Errorf("CVE-2026-83549 -> %v, want [92272 92275]", q)
	}
	// Lowercase IDs in the feed must normalize.
	if q := got["CVE-2026-83548"]; len(q) != 1 || q[0] != 92272 {
		t.Errorf("lowercase CVE was not normalized: %v", q)
	}
	// QID 0 and blank CVE IDs are junk and must be dropped.
	if _, ok := got["CVE-2026-00001"]; ok {
		t.Error("a vuln with QID 0 should not produce a mapping")
	}
	if len(got) != 2 {
		t.Errorf("got %d CVE keys, want 2: %v", len(got), got)
	}
}

func TestParseKBRejectsGarbage(t *testing.T) {
	if _, err := parseKB([]byte("<html>not xml at all")); err == nil {
		t.Error("expected an error on unparseable XML")
	}
}

func TestFormatAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0h"},
		{-time.Hour, "0h"},
		{90 * time.Minute, "2h"},
		{47 * time.Hour, "47h"},
		{72 * time.Hour, "3d"},
		{24 * 90 * time.Hour, "90d"},
	}
	for _, tc := range cases {
		if got := formatAge(tc.d); got != tc.want {
			t.Errorf("formatAge(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// writeCache puts a cache on disk and backdates its mtime.
func writeCache(t *testing.T, dir string, cache KBCache, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, "kb.json")
	b, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFreshCacheIsUsedWithoutAnyNetworkCall(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := writeCache(t, dir, KBCache{"CVE-2026-1": {111}}, 2*time.Hour)
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	cache, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrBuildKBCache: %v", err)
	}
	if called {
		t.Error("a fresh cache must not trigger any Qualys request")
	}
	if len(cache["CVE-2026-1"]) != 1 {
		t.Errorf("cache not loaded: %v", cache)
	}
	if c.kbStale {
		t.Error("a fresh cache must not be marked stale")
	}
}

func TestCacheIsMemoizedAcrossLookups(t *testing.T) {
	dir := t.TempDir()
	path := writeCache(t, dir, KBCache{"CVE-2026-1": {111}}, time.Hour)
	c := New("http://127.0.0.1:1", "u", "p", path, 168*time.Hour)

	first, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	// Delete the file: a second call must not re-read it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("second call should have used the memoized cache: %v", err)
	}
	if len(second) != len(first) {
		t.Error("memoized cache differs from the first load")
	}
}

func TestStaleCacheRefreshesFromQualys(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Query().Get("last_modified_after"))
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(kbXML))
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Old cache that knows nothing about the CVEs in kbXML - exactly the
	// situation that produced false UNKNOWNs.
	path := writeCache(t, dir, KBCache{"CVE-2020-1": {1}}, 30*24*time.Hour)
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	cache, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrBuildKBCache: %v", err)
	}
	if len(paths) == 0 || paths[0] == "" {
		t.Error("incremental refresh should send last_modified_after")
	}
	if _, ok := cache["CVE-2026-83549"]; !ok {
		t.Error("refresh did not merge in the newer CVE mapping")
	}
	if _, ok := cache["CVE-2020-1"]; !ok {
		t.Error("refresh dropped an existing mapping instead of merging")
	}
	if c.kbStale {
		t.Error("a successfully refreshed cache must not be marked stale")
	}

	// The refreshed cache must be persisted, or every run re-downloads.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk KBCache
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("cache on disk is not valid JSON: %v", err)
	}
	if _, ok := onDisk["CVE-2026-83549"]; !ok {
		t.Error("refreshed mapping was not written to disk")
	}
}

func TestStaleCacheWithQualysDownIsMarkedUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := writeCache(t, dir, KBCache{"CVE-2020-1": {1}}, 60*24*time.Hour)
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	// The run must continue rather than fail outright...
	cache, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("a stale cache with Qualys down should still return: %v", err)
	}
	if len(cache) != 1 {
		t.Errorf("expected the stale cache to be returned, got %v", cache)
	}
	// ...but it must be flagged, so results are not read as clean.
	if !c.kbStale {
		t.Fatal("cache should be marked stale when refresh and rebuild both fail")
	}

	// And that flag must reach the human-readable Reason.
	res, err := c.LookupCVE(context.Background(), "CVE-2026-83549")
	if err != nil {
		t.Fatalf("LookupCVE: %v", err)
	}
	if res.Status != "UNKNOWN" {
		t.Errorf("status = %q, want UNKNOWN", res.Status)
	}
	for _, want := range []string{"UNVERIFIED", "not confirmed absent"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("Reason should contain %q, got: %s", want, res.Reason)
		}
	}
	if res.Source != "qualys" {
		t.Errorf("Source = %q, want qualys", res.Source)
	}
}

func TestFreshCacheMissSaysNoMappingNotUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := writeCache(t, dir, KBCache{"CVE-2020-1": {1}}, time.Hour)
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	res, err := c.LookupCVE(context.Background(), "CVE-2026-99999")
	if err != nil {
		t.Fatalf("LookupCVE: %v", err)
	}
	// A genuinely absent mapping in a current cache is a real finding and
	// must NOT be dressed up as a coverage gap.
	if strings.Contains(res.Reason, "UNVERIFIED") {
		t.Errorf("a fresh cache miss should not claim unverified coverage: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, "No Qualys KnowledgeBase") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestMissingCacheIsBuilt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kbXML))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "kb.json")
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	cache, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrBuildKBCache: %v", err)
	}
	if _, ok := cache["CVE-2026-83549"]; !ok {
		t.Error("built cache is missing an expected mapping")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cache was not written: %v", err)
	}
}

func TestWriteKBCacheIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kb.json")
	if err := writeKBCache(path, KBCache{"CVE-2026-1": {1}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache mode is %#o, want 0600", perm)
	}
	// The temp file used for the atomic rename must not be left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file was not cleaned up by the rename")
	}
}

func TestUnreadableCacheTriggersRebuild(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kbXML))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "kb.json")
	// A truncated cache must not be trusted as "no mappings for anything".
	if err := os.WriteFile(path, []byte(`{"CVE-2026-1": [1`), 0600); err != nil {
		t.Fatal(err)
	}
	c := New(srv.URL, "u", "p", path, 168*time.Hour)

	cache, err := c.LoadOrBuildKBCache(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrBuildKBCache: %v", err)
	}
	if _, ok := cache["CVE-2026-83549"]; !ok {
		t.Error("a corrupt cache should have been rebuilt from Qualys")
	}
}
