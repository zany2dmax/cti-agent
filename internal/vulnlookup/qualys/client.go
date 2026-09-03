package qualys

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

type Client struct {
	baseURL     string
	username    string
	password    string
	kbCachePath string
	kbMaxAge    time.Duration
	http        *http.Client

	// Populated by LoadOrBuildKBCache so LookupCVE can tell the difference
	// between "Qualys has no QID for this CVE" and "our mapping is too old to
	// know about this CVE". Those look identical in the output otherwise, and
	// only one of them means you are actually covered.
	kbCache KBCache
	kbAge   time.Duration
	kbStale bool
}

type DetectionSummary struct {
	QID       int
	HostCount int
	MaxQDS    int
	LastSeen  string
	Hosts     []string
}

type KBCache map[string][]int

func New(baseURL, username, password, kbCachePath string, kbMaxAge time.Duration) *Client {
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		username:    username,
		password:    password,
		kbCachePath: kbCachePath,
		kbMaxAge:    kbMaxAge,
		http:        &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) Name() string { return "qualys" }

func (c *Client) LookupCVE(ctx context.Context, cve string) (vulnlookup.Result, error) {
	cache, err := c.LoadOrBuildKBCache(ctx, c.kbCachePath)
	if err != nil {
		return vulnlookup.Result{CVE: cve, Source: c.Name(), Status: vulnlookup.StatusUnknown, Reason: err.Error()}, err
	}

	normalizedCVE := strings.ToUpper(strings.TrimSpace(cve))
	qids := cache[normalizedCVE]
	if len(qids) == 0 {
		// Say WHY there is no mapping. A stale cache and a genuinely
		// unmapped CVE both produce UNKNOWN, but only the second one means
		// Qualys has nothing - the first means we did not look properly.
		reason := "No Qualys KnowledgeBase CVE-to-QID mapping found"
		if c.kbStale {
			reason = fmt.Sprintf(
				"KB cache is %s old and has no mapping for this CVE - coverage "+
					"UNVERIFIED, not confirmed absent. Refresh the cache: "+
					"delete %s and rerun.",
				formatAge(c.kbAge), c.kbCachePath)
			log.Printf("Qualys KB mapping: %s -> not in a %s-old cache (STALE, coverage unverified)",
				normalizedCVE, formatAge(c.kbAge))
		} else {
			log.Printf("Qualys KB mapping: %s -> no QIDs found (cache %s old)",
				normalizedCVE, formatAge(c.kbAge))
		}
		return vulnlookup.Result{
			CVE:    cve,
			Source: c.Name(),
			Status: vulnlookup.StatusUnknown,
			Reason: reason,
		}, nil
	}
	log.Printf("Qualys KB mapping: %s -> QIDs %s", normalizedCVE, strings.Join(qidStrings(qids), ","))

	detections, err := c.HostDetections(ctx, qids)
	if err != nil {
		return vulnlookup.Result{
			CVE:         cve,
			Source:      c.Name(),
			ExternalIDs: qidStrings(qids),
			Status:      vulnlookup.StatusUnknown,
			Reason:      fmt.Sprintf("Qualys detection lookup failed: %v", err),
		}, err
	}

	res := vulnlookup.Result{
		CVE:         cve,
		Source:      c.Name(),
		ExternalIDs: qidStrings(qids),
		Status:      vulnlookup.StatusNotPresent,
	}
	for _, qid := range qids {
		if d, ok := detections[qid]; ok && d.HostCount > 0 {
			res.Status = vulnlookup.StatusPresent
			res.HostCount += d.HostCount
			if d.MaxQDS > res.MaxScore {
				res.MaxScore = d.MaxQDS
			}
			if d.LastSeen > res.LastSeen {
				res.LastSeen = d.LastSeen
			}
			res.SampleHosts = append(res.SampleHosts, d.Hosts...)
		}
	}
	return res, nil
}

// LoadOrBuildKBCache returns the CVE->QID map, refreshing it when it has aged
// past kbMaxAge.
//
// The original version returned any parseable cache forever, with no expiry.
// A cache built once was then trusted indefinitely, so every CVE published
// after that build reported UNKNOWN - indistinguishable from "Qualys has no
// QID for it". That turns the whole point of the tool, telling you whether you
// are exposed, into a silent false negative.
func (c *Client) LoadOrBuildKBCache(ctx context.Context, cachePath string) (KBCache, error) {
	// Memoize: LookupCVE is called once per CVE and this is a 16MB+ file.
	if c.kbCache != nil {
		return c.kbCache, nil
	}

	var existing KBCache
	var age time.Duration
	haveCache := false

	if info, err := os.Stat(cachePath); err == nil {
		if b, err := os.ReadFile(cachePath); err == nil && len(b) > 0 {
			if err := json.Unmarshal(b, &existing); err == nil && len(existing) > 0 {
				haveCache = true
				age = time.Since(info.ModTime())
			} else {
				log.Printf("Qualys KB cache at %s is unreadable, rebuilding", cachePath)
			}
		}
	}

	switch {
	case haveCache && age <= c.kbMaxAge:
		log.Printf("Qualys KB cache: %d CVEs, %s old (fresh)", len(existing), formatAge(age))
		c.kbCache, c.kbAge, c.kbStale = existing, age, false
		return existing, nil

	case haveCache:
		// Try an incremental top-up before falling back to a full rebuild:
		// the full KnowledgeBase is a large download and most of it has not
		// changed.
		log.Printf("Qualys KB cache: %d CVEs, %s old (older than %s) - refreshing",
			len(existing), formatAge(age), formatAge(c.kbMaxAge))
		added, err := c.refreshKBCacheSince(ctx, existing, time.Now().Add(-age))
		if err == nil {
			log.Printf("Qualys KB cache: merged %d new CVE mappings", added)
			if err := writeKBCache(cachePath, existing); err != nil {
				log.Printf("Qualys KB cache: could not write %s: %v", cachePath, err)
			}
			c.kbCache, c.kbAge, c.kbStale = existing, 0, false
			return existing, nil
		}
		log.Printf("Qualys KB incremental refresh failed (%v) - attempting full rebuild", err)
		fresh, ferr := c.BuildKBCache(ctx)
		if ferr != nil {
			// Use the stale cache rather than failing the whole run, but mark
			// it so every UNKNOWN says its coverage is unverified.
			log.Printf("Qualys KB full rebuild also failed (%v) - continuing with the "+
				"STALE cache; UNKNOWN results are unverified, not clean", ferr)
			c.kbCache, c.kbAge, c.kbStale = existing, age, true
			return existing, nil
		}
		if err := writeKBCache(cachePath, fresh); err != nil {
			log.Printf("Qualys KB cache: could not write %s: %v", cachePath, err)
		}
		c.kbCache, c.kbAge, c.kbStale = fresh, 0, false
		return fresh, nil

	default:
		log.Printf("Qualys KB cache: not found at %s - building (this is a large "+
			"download and takes a few minutes)", cachePath)
		fresh, err := c.BuildKBCache(ctx)
		if err != nil {
			return nil, err
		}
		if err := writeKBCache(cachePath, fresh); err != nil {
			return nil, err
		}
		log.Printf("Qualys KB cache: built %d CVE mappings", len(fresh))
		c.kbCache, c.kbAge, c.kbStale = fresh, 0, false
		return fresh, nil
	}
}

// refreshKBCacheSince merges in only the vulnerabilities Qualys has modified
// since the given time, mutating cache in place and returning how many CVE
// keys were added or changed.
func (c *Client) refreshKBCacheSince(ctx context.Context, cache KBCache, since time.Time) (int, error) {
	params := url.Values{}
	params.Set("action", "list")
	params.Set("details", "Basic")
	params.Set("last_modified_after", since.UTC().Format("2006-01-02"))
	endpoint := c.baseURL + "/api/2.0/fo/knowledge_base/vuln/?" + params.Encode()

	body, err := c.doQualysGET(ctx, endpoint)
	if err != nil {
		return 0, err
	}
	partial, err := parseKB(body)
	if err != nil {
		return 0, err
	}
	if len(partial) == 0 {
		return 0, fmt.Errorf("incremental refresh returned no vulnerabilities")
	}
	changed := 0
	for cve, qids := range partial {
		merged := append(append([]int(nil), cache[cve]...), qids...)
		sort.Ints(merged)
		merged = dedupeInts(merged)
		if len(merged) != len(cache[cve]) {
			changed++
		}
		cache[cve] = merged
	}
	return changed, nil
}

func writeKBCache(path string, cache KBCache) error {
	b, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	// Write via a temp file so an interrupted run cannot leave a truncated
	// cache that later parses as "no mappings for anything".
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func formatAge(d time.Duration) string {
	if d <= 0 {
		return "0h"
	}
	if h := d.Hours(); h < 48 {
		return fmt.Sprintf("%.0fh", h)
	}
	return fmt.Sprintf("%.0fd", d.Hours()/24)
}

func (c *Client) BuildKBCache(ctx context.Context) (KBCache, error) {
	params := url.Values{}
	params.Set("action", "list")
	params.Set("details", "Basic")
	endpoint := c.baseURL + "/api/2.0/fo/knowledge_base/vuln/?" + params.Encode()

	body, err := c.doQualysGET(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return parseKB(body)
}

// parseKB turns a KnowledgeBase XML response into a CVE->QID map.
func parseKB(body []byte) (KBCache, error) {
	type kb struct {
		Vulns []struct {
			QID     int `xml:"QID"`
			CVEList struct {
				CVEs []struct {
					ID string `xml:"ID"`
				} `xml:"CVE"`
			} `xml:"CVE_LIST"`
		} `xml:"RESPONSE>VULN_LIST>VULN"`
	}
	var parsed kb
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse Qualys KB XML: %w", err)
	}

	cache := KBCache{}
	for _, vuln := range parsed.Vulns {
		for _, cve := range vuln.CVEList.CVEs {
			id := strings.ToUpper(strings.TrimSpace(cve.ID))
			if id == "" || vuln.QID == 0 {
				continue
			}
			cache[id] = append(cache[id], vuln.QID)
		}
	}
	for cve := range cache {
		sort.Ints(cache[cve])
		cache[cve] = dedupeInts(cache[cve])
	}
	return cache, nil
}

func (c *Client) HostDetections(ctx context.Context, qids []int) (map[int]DetectionSummary, error) {
	if len(qids) == 0 {
		return map[int]DetectionSummary{}, nil
	}
	params := url.Values{}
	params.Set("action", "list")
	params.Set("show_qds", "1")
	params.Set("status", "New,Active,Re-Opened")
	params.Set("qids", joinInts(qids))
	endpoint := c.baseURL + "/api/4.0/fo/asset/host/vm/detection/?" + params.Encode()

	body, err := c.doQualysGET(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return parseHostDetections(body)
}

func (c *Client) doQualysGET(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("X-Requested-With", "cti-qualys-agent")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Qualys response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("qualys request failed: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func parseHostDetections(b []byte) (map[int]DetectionSummary, error) {
	type detection struct {
		QID      int    `xml:"QID"`
		QDS      string `xml:"QDS"`
		LastSeen string `xml:"LAST_FOUND_DATETIME"`
	}
	type host struct {
		IP         string      `xml:"IP"`
		DNS        string      `xml:"DNS"`
		NetBIOS    string      `xml:"NETBIOS"`
		Detections []detection `xml:"DETECTION_LIST>DETECTION"`
	}
	type root struct {
		Hosts []host `xml:"RESPONSE>HOST_LIST>HOST"`
	}
	var parsed root
	if err := xml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse host detection XML: %w", err)
	}

	out := map[int]DetectionSummary{}
	seenHostPerQID := map[int]map[string]bool{}
	for _, h := range parsed.Hosts {
		name := firstNonEmpty(h.DNS, h.NetBIOS, h.IP)
		for _, d := range h.Detections {
			if d.QID == 0 {
				continue
			}
			s := out[d.QID]
			s.QID = d.QID
			if seenHostPerQID[d.QID] == nil {
				seenHostPerQID[d.QID] = map[string]bool{}
			}
			if !seenHostPerQID[d.QID][name] {
				seenHostPerQID[d.QID][name] = true
				s.HostCount++
				if len(s.Hosts) < 10 {
					s.Hosts = append(s.Hosts, name)
				}
			}
			if qds, err := strconv.Atoi(strings.TrimSpace(d.QDS)); err == nil && qds > s.MaxQDS {
				s.MaxQDS = qds
			}
			if d.LastSeen > s.LastSeen {
				s.LastSeen = d.LastSeen
			}
			out[d.QID] = s
		}
	}
	return out, nil
}

func qidStrings(vals []int) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, strconv.Itoa(v))
	}
	return out
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func dedupeInts(vals []int) []int {
	if len(vals) == 0 {
		return vals
	}
	out := vals[:1]
	for _, v := range vals[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}
