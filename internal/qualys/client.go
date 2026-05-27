package qualys

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

type DetectionSummary struct {
	QID       int
	HostCount int
	MaxQDS    int
	LastSeen  string
	Hosts     []string
}

type KBCache map[string][]int

func New(baseURL, username, password string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) LoadOrBuildKBCache(ctx context.Context, cachePath string) (KBCache, error) {
	if b, err := os.ReadFile(cachePath); err == nil && len(b) > 0 {
		var cache KBCache
		if err := json.Unmarshal(b, &cache); err == nil {
			return cache, nil
		}
	}

	cache, err := c.BuildKBCache(ctx)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cachePath, b, 0600); err != nil {
		return nil, err
	}
	return cache, nil
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
	params.Set("qid", joinInts(qids))
	endpoint := c.baseURL + "/api/2.0/fo/asset/host/vm/detection/?" + params.Encode()

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
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
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
