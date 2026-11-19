package vmscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/httpx"
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
)

// # THE SCAN LIST COMES FROM QUALYS, THE NOTICES ARE DETAIL
//
// Which scans ran is read from Qualys's own scan list (VM API, read-only), not
// from the mailbox. Twice the mail lost a week: a renamed scan whose notice no
// longer matched, and a results notice that never arrived during a Microsoft
// outage. Either way the report said a scan was missing and the coverage check
// compared every location against nothing, while Qualys knew exactly what had
// run and which Asset Groups it covered.
//
// So the list gives each scan's title, launch time, duration, state and Asset
// Groups; the results notice, matched by scan reference, adds what only the
// notice carries (hosts scanned and alive, the vulnerability tables, the
// report link) and is what the mailbox cleanup files away. A scan in the list
// with no notice is still reported and still counts for coverage, and the
// report says its notice did not arrive. If the list cannot be read, the lane
// falls back to the notices alone and says so.

type xmlScanList struct {
	XMLName xml.Name `xml:"SCAN_LIST_OUTPUT"`
	Scans   []struct {
		Ref      string   `xml:"REF"`
		Type     string   `xml:"TYPE"`
		Title    string   `xml:"TITLE"`
		User     string   `xml:"USER_LOGIN"`
		Launched string   `xml:"LAUNCH_DATETIME"`
		Duration string   `xml:"DURATION"`
		State    string   `xml:"STATUS>STATE"`
		Groups   []string `xml:"ASSET_GROUP_TITLE_LIST>ASSET_GROUP_TITLE"`
	} `xml:"RESPONSE>SCAN_LIST>SCAN"`
	Warning string `xml:"RESPONSE>WARNING>TEXT"`
	Error   string `xml:"RESPONSE>TEXT"`
	Code    string `xml:"RESPONSE>CODE"`
}

// ParseScanList reads the scan list API's XML. A truncation warning is an
// error: a list that stopped part-way would read as "these were all the scans"
// and report the rest as missing.
func ParseScanList(body []byte) ([]Scan, error) {
	var x xmlScanList
	if err := xml.Unmarshal(body, &x); err != nil {
		return nil, fmt.Errorf("the scan list did not parse: %w", err)
	}
	if x.Code != "" || x.Error != "" {
		return nil, fmt.Errorf("qualys refused the scan list (%s): %s", x.Code, strings.TrimSpace(x.Error))
	}
	if strings.TrimSpace(x.Warning) != "" {
		return nil, fmt.Errorf("qualys truncated the scan list (%s) - refusing to use a partial list",
			strings.TrimSpace(x.Warning))
	}
	var out []Scan
	for _, s := range x.Scans {
		sc := Scan{
			Title:      cleanName(s.Title),
			Ref:        strings.TrimSpace(s.Ref),
			LaunchType: strings.TrimSpace(s.Type),
			LaunchedBy: strings.TrimSpace(s.User),
			Duration:   parseDuration(s.Duration),
			Status:     strings.TrimSpace(s.State),
			FromList:   true,
		}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Launched)); err == nil {
			sc.Start = t
		}
		for _, g := range s.Groups {
			if g = cleanName(g); g != "" {
				sc.TargetGroups = append(sc.TargetGroups, g)
			}
		}
		out = append(out, sc)
	}
	return out, nil
}

// cleanName trims a title and drops the invisible characters Qualys has been
// seen to carry in them (a byte-order mark in front of a group name).
func cleanName(s string) string {
	s = strings.NewReplacer("\ufeff", "", "\u200b", "", "\u00a0", " ").Replace(s)
	return strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
}

// FetchScans lists the VM scans launched since a time, with the Asset Groups
// each targeted. Read-only; the same credential the other Qualys lanes use.
func FetchScans(ctx context.Context, baseURL, username, password string, since time.Time) ([]Scan, error) {
	q := url.Values{}
	q.Set("action", "list")
	q.Set("launched_after_datetime", since.UTC().Format("2006-01-02T15:04:05Z"))
	q.Set("show_ags", "1")
	q.Set("show_op", "0")
	q.Set("show_status", "1")
	body, err := qualysGet(ctx, baseURL, username, password, "/api/2.0/fo/scan/", q, "scan list")
	if err != nil {
		return nil, err
	}
	return ParseScanList(body)
}

// qualysGet makes one read-only VM API call through the shared rate limiter.
// what names the call in errors ("scan list").
func qualysGet(ctx context.Context, baseURL, username, password, path string, q url.Values, what string) ([]byte, error) {
	base := strings.TrimRight(baseURL, "/")
	l := qualysrl.Shared(base)
	if l.Logf == nil {
		l.Logf = func(f string, a ...any) { _, _ = fmt.Fprintf(os.Stderr, "[qualys] "+f+"\n", a...) }
	}
	client := &http.Client{Timeout: 120*time.Second + l.WaitBudget(), Transport: l, CheckRedirect: httpx.CheckRedirect}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("X-Requested-With", "cti-agent")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the Qualys %s request failed: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	const limit = 32 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the Qualys %s: %w", what, err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("the Qualys %s is over %d MB - not reading it", what, limit>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		trimmed := strings.TrimSpace(string(body))
		if len(trimmed) > 400 {
			trimmed = trimmed[:400] + "..."
		}
		return nil, fmt.Errorf("qualys refused the %s (HTTP %d): %s", what, resp.StatusCode, trimmed)
	}
	return body, nil
}

// WithNotices joins the scan list with the results notices, by scan
// reference. A listed scan with a notice takes the notice's detail (hosts,
// vulnerability tables, report link, message) and keeps the list's Asset
// Groups, launch time and state; one without is kept as it is, marked
// NoNotice. A notice for a scan the list does not have (launched before the
// window) is kept too: Combine still takes only the newest run of each scan.
func WithNotices(list, notices []Scan) []Scan {
	byRef := map[string]Scan{}
	for _, n := range notices {
		if n.Ref != "" {
			byRef[n.Ref] = n
		}
	}
	used := map[string]bool{}
	var out []Scan
	for _, s := range list {
		n, ok := byRef[s.Ref]
		if !ok || s.Ref == "" {
			s.NoNotice = true
			out = append(out, s)
			continue
		}
		used[s.Ref] = true
		n.FromList = true
		if len(s.TargetGroups) > 0 {
			n.TargetGroups = s.TargetGroups
		}
		if !s.Start.IsZero() {
			n.Start = s.Start
		}
		if s.Status != "" {
			n.Status = s.Status
		}
		if s.LaunchType != "" {
			n.LaunchType = s.LaunchType
		}
		if s.Title != "" {
			n.Title = s.Title
		}
		out = append(out, n)
	}
	for _, n := range notices {
		if n.Ref == "" || !used[n.Ref] {
			out = append(out, n)
		}
	}
	return out
}
