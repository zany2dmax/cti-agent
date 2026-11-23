package enrich

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/httpx"
)

type feed struct {
	mu    sync.Mutex
	hits  map[string]int
	reply func(w http.ResponseWriter, r *http.Request, n int)
}

func newFeed(t *testing.T, reply func(w http.ResponseWriter, r *http.Request, n int)) (*Live, *feed, *[]time.Duration) {
	t.Helper()
	f := &feed{hits: map[string]int{}, reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		key := r.URL.Path + "?" + r.URL.RawQuery
		f.hits[key]++
		n := f.hits[key]
		f.mu.Unlock()
		f.reply(w, r, n)
	}))
	t.Cleanup(srv.Close)
	var slept []time.Duration
	l := &Live{
		Client: httpx.New(5 * time.Second), StateDir: t.TempDir(), Agent: "test-agent",
		Logf: func(string, ...any) {}, Sleep: func(d time.Duration) { slept = append(slept, d) },
		Now:    func() time.Time { return time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC) },
		NVDURL: srv.URL + "/nvd", EPSSURL: srv.URL + "/epss", KEVURL: srv.URL + "/kev",
	}
	return l, f, &slept
}

const nvdAnswer = `{"vulnerabilities":[{"cve":{
 "id":"CVE-2026-1111","vulnStatus":"Analyzed","published":"2026-01-02T03:04:05.000","cisaExploitAdd":"2026-01-05",
 "descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"%s"}],
 "metrics":{"cvssMetricV31":[
   {"source":"cna@vendor.example","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}},
   {"source":"nvd@nist.gov","cvssData":{"baseScore":7.0}, "baseSeverity":"HIGH"}],
  "cvssMetricV2":[{"source":"nvd@nist.gov","cvssData":{"baseScore":5.0}}]},
 "configurations":[{"nodes":[{"cpeMatch":[
   {"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
   {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:a:nodejs:node\\.js:*:*:*:*:*:*:*:*"}]}]}]}}]}`

func TestNVDReadsTheRecordTheWayTheDigestNeedsIt(t *testing.T) {
	long := strings.Repeat("é", 450)
	l, _, _ := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Header.Get("apiKey") != "k" || r.Header.Get("User-Agent") != "test-agent" {
			http.Error(w, "headers", 400)
			return
		}
		_, _ = fmt.Fprintf(w, nvdAnswer, long)
	})
	l.NVDKey = "k"
	got := l.NVD([]string{"CVE-2026-1111"})["CVE-2026-1111"]
	if got.CVSS == nil || string(*got.CVSS) != "7.0" {
		t.Fatalf("cvss = %v: the NVD-authored v3.1 score, as NVD wrote it", got.CVSS)
	}
	if got.CVSSSeverity == nil || *got.CVSSSeverity != "HIGH" {
		t.Errorf("severity = %v: the metric's own when cvssData has none", got.CVSSSeverity)
	}
	if !got.KEVNVD || deref(got.VulnStatus) != "Analyzed" || deref(got.Published) == "" {
		t.Errorf("entry = %+v", got)
	}
	if d := deref(got.Description); len([]rune(d)) != 400 || !strings.HasPrefix(d, "é") {
		t.Errorf("description is %d characters, want 400 (cut by character)", len([]rune(d)))
	}
	if got.CPEProducts == nil || fmt.Sprint(*got.CPEProducts) != "[[google chrome] [nodejs node.js]]" {
		t.Errorf("cpe_products = %v", got.CPEProducts)
	}
}

func TestNVDCachesAWeekAndRefetchesAnOldEntry(t *testing.T) {
	l, f, slept := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {
		_, _ = fmt.Fprintf(w, nvdAnswer, "d")
	})
	// A cache the Python wrote: microseconds, +00:00, and one entry from
	// before cpe_products existed.
	cache := `{"fetched": "2026-11-20T06:00:00.123456+00:00", "data": {
	  "CVE-2026-0001": {"cvss": 10.0, "cvss_severity": "CRITICAL", "description": null, "kev_nvd": false,
	                    "vuln_status": null, "published": null, "cpe_products": []},
	  "CVE-2026-0002": {"cvss": 5.0, "cvss_severity": "MEDIUM", "description": null, "kev_nvd": false,
	                    "vuln_status": null, "published": null}}}`
	path := filepath.Join(l.StateDir, NVDCacheFile)
	if err := os.WriteFile(path, []byte(cache), 0o600); err != nil {
		t.Fatal(err)
	}
	got := l.NVD([]string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"})
	if f.hits["/nvd?cveId=CVE-2026-0001"] != 0 || f.hits["/nvd?cveId=CVE-2026-0002"] != 1 || f.hits["/nvd?cveId=CVE-2026-0003"] != 1 {
		t.Fatalf("hits = %v: fresh entries come from the cache, old-shape and missing ones are fetched", f.hits)
	}
	if string(*got["CVE-2026-0001"].CVSS) != "10.0" {
		t.Errorf("a cached 10.0 became %s", *got["CVE-2026-0001"].CVSS)
	}
	if len(*slept) != 1 || (*slept)[0] != 6500*time.Millisecond {
		t.Errorf("slept %v: one pause between two requests, 6.5s without a key", *slept)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"cvss":10.0`) {
		t.Errorf("the rewritten cache lost NVD's 10.0: %s", raw)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("cache mode %v, want 0600", st.Mode().Perm())
	}
	// Eight days later the whole cache has expired.
	l.Now = func() time.Time { return time.Date(2026, 11, 30, 7, 0, 0, 0, time.UTC) }
	l.NVD([]string{"CVE-2026-0001"})
	if f.hits["/nvd?cveId=CVE-2026-0001"] != 1 {
		t.Errorf("an expired cache was used")
	}
}

func TestTheFeedsBackOffThenGiveUp(t *testing.T) {
	l, f, slept := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/kev") && n == 1:
			http.Error(w, "slow down", http.StatusTooManyRequests)
		case strings.HasPrefix(r.URL.Path, "/kev"):
			_, _ = w.Write([]byte(`{"catalogVersion":"2026.11.21","vulnerabilities":[
			  {"cveID":"cve-2026-0009","dateAdded":"2026-11-01","dueDate":"2026-11-22","knownRansomwareCampaignUse":"Known",
			   "vulnerabilityName":"n","requiredAction":"a","vendorProject":"Acme","product":"Router"}]}`))
		default:
			http.Error(w, "nope", http.StatusNotFound)
		}
	})
	kev := l.KEV()
	if e, ok := kev["CVE-2026-0009"]; !ok || deref(e.Product) != "Router" || !e.hasVendor {
		t.Fatalf("kev = %v", kev)
	}
	if len(*slept) != 1 || (*slept)[0] != 15*time.Second {
		t.Errorf("slept %v: 15s after a 429", *slept)
	}
	// A 404 is not retried.
	if got := l.EPSS([]string{"CVE-2026-0009"}); len(got) != 0 || f.hits["/epss?cve=CVE-2026-0009"] != 1 {
		t.Errorf("epss = %v, hits %v", got, f.hits)
	}
	// The catalog is cached for 12 hours, and read back with its vendor.
	l.KEVURL = "https://unreachable.invalid/kev"
	if len(l.KEV()) != 1 {
		t.Error("the fresh KEV cache was not used")
	}
}

func TestAKEVCacheWithoutVendorsIsRefetched(t *testing.T) {
	l, f, _ := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"V","product":"P"}]}`))
	})
	old := `{"fetched": "2026-11-22T05:00:00+00:00", "data": {"CVE-2026-0001": {"kev_added": "x", "kev_due": null,
	  "ransomware": null, "kev_name": null, "kev_action": null}}}`
	if err := os.WriteFile(filepath.Join(l.StateDir, KEVCacheFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := l.KEV(); deref(got["CVE-2026-0001"].Vendor) != "V" || f.hits["/kev?"] != 1 {
		t.Fatalf("got %v, hits %v", got, f.hits)
	}
}

func TestEPSSReadsFIRSTsStringsInChunks(t *testing.T) {
	l, f, slept := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {
		var rows []string
		for _, c := range strings.Split(r.URL.Query().Get("cve"), ",") {
			rows = append(rows, fmt.Sprintf(`{"cve":%q,"epss":"0.25","percentile":"0.9","date":"2026-11-21"}`, strings.ToLower(c)))
		}
		rows = append(rows, `{"cve":"CVE-2026-9999","epss":"bad","percentile":"0.1"}`, `{"cve":"CVE-2026-9998","epss":"NaN"}`)
		_, _ = fmt.Fprintf(w, `{"data":[%s]}`, strings.Join(rows, ","))
	})
	var cves []string
	for i := 0; i < 150; i++ {
		cves = append(cves, fmt.Sprintf("CVE-2026-%04d", 1000+i))
	}
	got := l.EPSS(cves)
	if len(got) != 150 || got["CVE-2026-1000"].EPSS != 0.25 || deref(got["CVE-2026-1000"].Date) != "2026-11-21" {
		t.Fatalf("got %d entries, %+v", len(got), got["CVE-2026-1000"])
	}
	if len(f.hits) != 2 || len(*slept) != 2 {
		t.Errorf("hits %d, slept %v: two chunks of at most 100, a second after each", len(f.hits), *slept)
	}
}

func TestOnlyHTTPSLeavesTheBox(t *testing.T) {
	l, _, _ := newFeed(t, func(w http.ResponseWriter, r *http.Request, n int) {})
	l.KEVURL = "http://example.com/kev"
	if got := l.KEV(); len(got) != 0 {
		t.Fatalf("fetched over plain http: %v", got)
	}
}

func TestSaveProductsMergesAndKeepsWhatItKnew(t *testing.T) {
	path := filepath.Join(t.TempDir(), ProductsFile)
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	php := "PHP"
	apple, safari := "Apple", "Safari"
	res := &Result{Findings: []*Finding{{CVE: "CVE-2026-1", Product: php}},
		kev: map[string]KEVEntry{"CVE-2026-2": {Vendor: &apple, Product: &safari}}}
	if err := SaveProducts(path, res, now); err != nil {
		t.Fatal(err)
	}
	if err := SaveProducts(path, &Result{Findings: []*Finding{{CVE: "CVE-2026-3", Product: "Node.js"}}}, now); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if !loadCache(path, time.Hour, now, &got) {
		t.Fatal("unreadable")
	}
	b, _ := json.Marshal(got)
	if string(b) != `{"CVE-2026-1":"PHP","CVE-2026-2":"Apple Safari","CVE-2026-3":"Node.js"}` {
		t.Fatalf("products = %s", b)
	}
	// Nothing new: the file is not rewritten.
	st1, _ := os.Stat(path)
	if err := SaveProducts(path, &Result{Findings: []*Finding{{CVE: "CVE-2026-3", Product: "Node.js"}}}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("an unchanged map was rewritten")
	}
}
