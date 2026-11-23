package enrich

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/httpx"
	"github.com/zany2dmax/cti-agent/internal/useragent"
)

// Sources answers for the three enrichment feeds. Live is the real one; the
// tests use fixtures.
type Sources interface {
	// NVD returns the whole NVD cache after fetching what is missing or stale
	// for cves, so an entry for an older CVE still counts as NVD answering.
	NVD(cves []string) map[string]NVDEntry
	EPSS(cves []string) map[string]EPSSEntry
	KEV() map[string]KEVEntry
}

// The feeds. Fixed https constants; the tests point a Live at a loopback
// server instead, which is the only non-https address httpx allows.
const (
	NVDAPI  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	EPSSAPI = "https://api.first.org/data/v1/epss"
	KEVFeed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Cache files under $FLEET_HOME/state.
const (
	NVDCacheFile = "nvd-cache.json"
	KEVCacheFile = "kev-cache.json"
	// ProductsFile sits beside the enriched file, where brief.py looks for it.
	ProductsFile = "products.json"

	nvdTTL = 7 * 24 * time.Hour // CVSS scores rarely move once assigned
	kevTTL = 12 * time.Hour
)

// UserAgent is the product token every feed sees, with the fleet's contact.
const UserAgent = "cti-agent-enrich/1.0"

// Live fetches from NVD, FIRST and CISA, through the state caches.
type Live struct {
	Client   *http.Client
	StateDir string
	NVDKey   string // NVD_API_KEY; ten times the rate limit with it
	Agent    string
	Logf     func(string, ...any)
	Sleep    func(time.Duration)
	Now      func() time.Time

	NVDURL, EPSSURL, KEVURL string
}

// NewLive is a Live with the fleet's HTTP client and the real feeds.
func NewLive(stateDir, nvdKey string, logf func(string, ...any)) *Live {
	return &Live{
		Client: httpx.New(90 * time.Second), StateDir: stateDir, NVDKey: nvdKey,
		Agent: useragent.String(UserAgent), Logf: logf, Sleep: time.Sleep, Now: time.Now,
		NVDURL: NVDAPI, EPSSURL: EPSSAPI, KEVURL: KEVFeed,
	}
}

// nvdDelay keeps under NVD's limits: 5 requests per 30s without a key, 50
// with one.
func (l *Live) nvdDelay() time.Duration {
	if l.NVDKey != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

type httpStatusError int

func (e httpStatusError) Error() string { return "HTTP " + strconv.Itoa(int(e)) }

func short(u string) string {
	if utf8.RuneCountInString(u) > 70 {
		return string([]rune(u)[:70])
	}
	return u
}

// getJSON GETs JSON with backoff, decoding numbers as json.Number. It
// returns nil rather than an error: a missing enrichment source degrades the
// report, it does not stop the run.
func (l *Live) getJSON(u string, headers map[string]string, timeout time.Duration) map[string]any {
	const retries = 3
	for attempt := 0; attempt < retries; attempt++ {
		v, err := l.fetch(u, headers, timeout)
		if err == nil {
			return v
		}
		var code httpStatusError
		if errors.As(err, &code) {
			if (code == 403 || code == 429 || code == 503) && attempt < retries-1 {
				wait := (attempt + 1) * 15
				l.Logf("HTTP %d on %s - backing off %ds", int(code), short(u), wait)
				l.Sleep(time.Duration(wait) * time.Second)
				continue
			}
			l.Logf("HTTP %d giving up on %s", int(code), short(u))
			return nil
		}
		if attempt < retries-1 {
			l.Sleep(time.Duration(attempt+1) * 5 * time.Second)
			continue
		}
		l.Logf("error on %s: %v", short(u), err)
		return nil
	}
	return nil
}

func (l *Live) fetch(u string, headers map[string]string, timeout time.Duration) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", l.Agent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c := *l.Client
	c.Timeout = timeout
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, httpStatusError(resp.StatusCode)
	}
	// The KEV catalog is a few MB; nothing legitimate is near this.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.ToValidUTF8(body, []byte("�"))))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// cacheBlob is a state cache file: when it was fetched, and the data.
type cacheBlob struct {
	Fetched string          `json:"fetched"`
	Data    json.RawMessage `json:"data"`
}

// parseISO reads a cache's fetched time. A time without a zone is not
// usable, as it never was: the cache is fetched fresh.
func parseISO(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// loadCache decodes a cache's data into v when the file is younger than
// ttl. false means there is no usable cache and it should be fetched.
func loadCache(path string, ttl time.Duration, now time.Time, v any) bool {
	// #nosec G304 -- a fixed name under the fleet's own state directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var blob cacheBlob
	if json.Unmarshal(raw, &blob) != nil {
		return false
	}
	if blob.Fetched == "" {
		blob.Fetched = "1970-01-01T00:00:00+00:00"
	}
	t, ok := parseISO(blob.Fetched)
	if !ok || now.Sub(t) >= ttl {
		return false
	}
	if len(blob.Data) == 0 {
		return true // no data key: an empty cache, still a cache
	}
	dec := json.NewDecoder(bytes.NewReader(blob.Data))
	dec.UseNumber()
	return dec.Decode(v) == nil
}

// saveCache writes {"fetched": now, "data": data} atomically, 0600 like the
// rest of the fleet's state.
func saveCache(path string, data any, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Fetched string `json:"fetched"`
		Data    any    `json:"data"`
	}{now.UTC().Format("2006-01-02T15:04:05.000000-07:00"), data})
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// NVD fetches one CVE per request (NVD has no bulk-by-id endpoint), through
// a cache kept seven days.
func (l *Live) NVD(cves []string) map[string]NVDEntry {
	path := filepath.Join(l.StateDir, NVDCacheFile)
	cache := map[string]NVDEntry{}
	if !loadCache(path, nvdTTL, l.Now(), &cache) || cache == nil {
		cache = map[string]NVDEntry{}
	}
	// An entry cached before cpe_products existed is stale: without it the
	// product would read "not identified" for up to a week.
	var stale []string
	for _, c := range cves {
		if e, ok := cache[c]; !ok || e.CPEProducts == nil {
			stale = append(stale, c)
		}
	}
	if len(stale) > 0 {
		hint := ""
		if l.nvdDelay() > time.Second {
			hint = " - set NVD_API_KEY to go 10x faster"
		}
		l.Logf("NVD: %d cached, fetching %d (~%ds%s)", len(cache), len(stale),
			int(float64(len(stale))*l.nvdDelay().Seconds()), hint)
	}
	headers := map[string]string{}
	if l.NVDKey != "" {
		headers["apiKey"] = l.NVDKey
	}
	for i, cve := range stale {
		if i > 0 {
			l.Sleep(l.nvdDelay())
		}
		data := l.getJSON(l.NVDURL+"?cveId="+url.QueryEscape(cve), headers, 45*time.Second)
		cache[cve] = nvdEntry(data)
	}
	if len(stale) > 0 {
		if err := saveCache(path, cache, l.Now()); err != nil {
			l.Logf("WARNING: could not save %s (%v)", path, err)
		}
	}
	return cache
}

// nvdEntry reads one NVD API answer. Anything missing stays empty.
func nvdEntry(data map[string]any) NVDEntry {
	e := NVDEntry{CPEProducts: &[][]string{}}
	vulns, _ := data["vulnerabilities"].([]any)
	if len(vulns) == 0 {
		return e
	}
	first, _ := vulns[0].(map[string]any)
	cve, _ := first["cve"].(map[string]any)
	// Through JSON again for the typed parts: the configurations and metrics.
	raw, _ := json.Marshal(cve)
	var rec struct {
		Configurations nvdConfigurations `json:"configurations"`
		VulnStatus     *string           `json:"vulnStatus"`
		Published      *string           `json:"published"`
		Descriptions   []struct {
			Lang  string  `json:"lang"`
			Value *string `json:"value"`
		} `json:"descriptions"`
		Metrics map[string][]struct {
			Source       string  `json:"source"`
			BaseSeverity *string `json:"baseSeverity"`
			CVSSData     struct {
				BaseScore    *json.Number `json:"baseScore"`
				BaseSeverity *string      `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"metrics"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&rec) != nil {
		return e
	}
	products := CPEProducts(rec.Configurations)
	e.CPEProducts = &products
	e.VulnStatus, e.Published = rec.VulnStatus, rec.Published
	e.KEVNVD = truthy(cve["cisaExploitAdd"])
	for _, d := range rec.Descriptions {
		if d.Lang == "en" {
			v := ""
			if d.Value != nil {
				v = *d.Value
			}
			if r := []rune(v); len(r) > 400 {
				v = string(r[:400])
			}
			e.Description = &v
			break
		}
	}
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		ms := rec.Metrics[key]
		if len(ms) == 0 {
			continue
		}
		// Prefer the NVD-authored score over a CNA self-assessment.
		chosen := ms[0]
		for _, m := range ms {
			if strings.HasSuffix(m.Source, "nist.gov") {
				chosen = m
				break
			}
		}
		e.CVSS = chosen.CVSSData.BaseScore
		e.CVSSSeverity = chosen.CVSSData.BaseSeverity
		if e.CVSSSeverity == nil || *e.CVSSSeverity == "" {
			e.CVSSSeverity = chosen.BaseSeverity
		}
		break
	}
	return e
}

// truthy is a JSON value's truth as the digest always read it: null, false,
// "", 0 and empty containers are false.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return numberValue(x) != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// floatOf reads an EPSS value, which FIRST sends as a string. Empty or null
// is 0; anything that is not a number is an error and the row is skipped.
func floatOf(v any) (float64, error) {
	if !truthy(v) {
		return 0, nil
	}
	switch x := v.(type) {
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	case json.Number:
		return strconv.ParseFloat(string(x), 64)
	case bool:
		return 1, nil
	}
	return 0, fmt.Errorf("not a number")
}

// bad is a value JSON cannot carry.
func bad(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

// EPSS asks FIRST for the CVEs a hundred at a time.
func (l *Live) EPSS(cves []string) map[string]EPSSEntry {
	out := map[string]EPSSEntry{}
	for i := 0; i < len(cves); i += 100 {
		chunk := cves[i:min(i+100, len(cves))]
		data := l.getJSON(l.EPSSURL+"?cve="+strings.Join(chunk, ","), nil, 45*time.Second)
		if len(data) == 0 {
			continue
		}
		rows, _ := data["data"].([]any)
		for _, r := range rows {
			row, ok := r.(map[string]any)
			if !ok {
				continue
			}
			cve, ok := row["cve"].(string)
			if !ok {
				continue
			}
			epss, err1 := floatOf(row["epss"])
			pct, err2 := floatOf(row["percentile"])
			if err1 != nil || err2 != nil || bad(epss) || bad(pct) {
				continue
			}
			e := EPSSEntry{EPSS: epss, Pct: pct}
			if d, ok := row["date"].(string); ok {
				e.Date = &d
			}
			out[strings.ToUpper(cve)] = e
		}
		l.Sleep(time.Second)
	}
	l.Logf("EPSS: scored %d/%d", len(out), len(cves))
	return out
}

// KEV is the bulk catalog. NVD already flags KEV membership, but the catalog
// is the only place with the remediation due date and ransomware use.
func (l *Live) KEV() map[string]KEVEntry {
	path := filepath.Join(l.StateDir, KEVCacheFile)
	var cache map[string]KEVEntry
	if loadCache(path, kevTTL, l.Now(), &cache) && len(cache) > 0 {
		for _, v := range cache {
			if v.hasVendor {
				l.Logf("KEV: %d entries (cached)", len(cache))
				return cache
			}
		}
	}
	data := l.getJSON(l.KEVURL, nil, 90*time.Second)
	if len(data) == 0 {
		l.Logf("KEV: feed unavailable - falling back to the NVD cisaExploitAdd flag")
		return map[string]KEVEntry{}
	}
	kev := map[string]KEVEntry{}
	vulns, _ := data["vulnerabilities"].([]any)
	str := func(m map[string]any, k string) *string {
		if s, ok := m[k].(string); ok {
			return &s
		}
		return nil
	}
	for _, x := range vulns {
		v, ok := x.(map[string]any)
		if !ok {
			continue
		}
		id := strings.ToUpper(deref(str(v, "cveID")))
		if id == "" {
			continue
		}
		kev[id] = KEVEntry{
			Added: str(v, "dateAdded"), Due: str(v, "dueDate"), Ransomware: str(v, "knownRansomwareCampaignUse"),
			Name: str(v, "vulnerabilityName"), Action: str(v, "requiredAction"),
			Vendor: str(v, "vendorProject"), Product: str(v, "product"), hasVendor: true,
		}
	}
	l.Logf("KEV: %d entries (catalog %v)", len(kev), pyValue(data["catalogVersion"]))
	if err := saveCache(path, kev, l.Now()); err != nil {
		l.Logf("WARNING: could not save %s (%v)", path, err)
	}
	return kev
}

// pyValue is a JSON value as the log line always showed it.
func pyValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case json.Number:
		return pyNumber(x)
	}
	return fmt.Sprint(v)
}
