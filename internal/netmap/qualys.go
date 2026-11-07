package netmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/qualysrl"
)

type xmlGroupList struct {
	XMLName xml.Name `xml:"ASSET_GROUP_LIST_OUTPUT"`
	Groups  []struct {
		ID    string   `xml:"ID"`
		Title string   `xml:"TITLE"`
		IPs   []string `xml:"IP_SET>IP"`
		Rng   []string `xml:"IP_SET>IP_RANGE"`
	} `xml:"RESPONSE>ASSET_GROUP_LIST>ASSET_GROUP"`
	Warning string `xml:"RESPONSE>WARNING>TEXT"`
	Error   string `xml:"RESPONSE>TEXT"`
	Code    string `xml:"RESPONSE>CODE"`
}

// ParseGroups reads the asset-group list API's XML into Groups. A truncation
// warning is an error: a list of groups that stopped part-way would read as the
// complete picture and report locations as missing that merely were not
// returned.
func ParseGroups(body []byte) ([]Group, error) {
	var x xmlGroupList
	if err := xml.Unmarshal(body, &x); err != nil {
		return nil, fmt.Errorf("the asset group list did not parse: %w", err)
	}
	if x.Code != "" || x.Error != "" {
		return nil, fmt.Errorf("qualys refused the asset group list (%s): %s", x.Code, strings.TrimSpace(x.Error))
	}
	if strings.TrimSpace(x.Warning) != "" {
		return nil, fmt.Errorf("qualys truncated the asset group list (%s) - refusing to use a partial list",
			strings.TrimSpace(x.Warning))
	}
	var out []Group
	for _, g := range x.Groups {
		grp := Group{ID: strings.TrimSpace(g.ID), Title: strings.TrimSpace(g.Title)}
		for _, s := range append(append([]string(nil), g.IPs...), g.Rng...) {
			// An entry can itself be comma separated.
			for _, part := range strings.Split(s, ",") {
				if strings.TrimSpace(part) == "" {
					continue
				}
				r, err := ParseRange(part)
				if err != nil {
					// IPv6 or something odd: skip it, the group still counts.
					continue
				}
				grp.Ranges = append(grp.Ranges, r)
			}
		}
		out = append(out, grp)
	}
	return out, nil
}

// FetchGroups lists every Asset Group with its addresses, read-only, through
// the VM API. The account needs to be allowed to see asset groups (any role
// with the VM module can); it is the same credential the other Qualys lanes use.
func FetchGroups(ctx context.Context, baseURL, username, password string) ([]Group, error) {
	l := qualysrl.Shared(strings.TrimRight(baseURL, "/"))
	if l.Logf == nil {
		l.Logf = func(f string, a ...any) { _, _ = fmt.Fprintf(os.Stderr, "[qualys] "+f+"\n", a...) }
	}
	client := &http.Client{Timeout: 120*time.Second + l.WaitBudget(), Transport: l}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/2.0/fo/asset/group/?action=list&show_attributes=ALL&truncation_limit=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("X-Requested-With", "cti-agent")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the Qualys asset group request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	const limit = 64 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the Qualys asset group response: %w", err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("the Qualys asset group response is over %d MB - not reading it", limit>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		trimmed := strings.TrimSpace(string(body))
		if len(trimmed) > 400 {
			trimmed = trimmed[:400] + "..."
		}
		return nil, fmt.Errorf("qualys refused the asset group list (HTTP %d): %s", resp.StatusCode, trimmed)
	}
	return ParseGroups(body)
}
