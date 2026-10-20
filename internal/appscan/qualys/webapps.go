package qualys

import (
	"context"
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// WebApp is one application defined in Qualys WAS: what app-owners.txt is
// keyed on.
type WebApp struct {
	ID   string
	Name string
	URL  string
}

const (
	webAppPageSize = 500
	webAppMaxPages = 20
)

// WebApps returns every web application defined in WAS, by name. Read-only,
// one search endpoint, paged by id like the scan and finding searches; a
// runaway is an error, never a short list that reads as complete.
func (a *API) WebApps(ctx context.Context) ([]WebApp, error) {
	var out []WebApp
	lastID := 0
	for page := 0; ; page++ {
		if page >= webAppMaxPages {
			return nil, fmt.Errorf("qualys WAS: web app list stopped after %d pages - "+
				"refusing to return a partial list", webAppMaxPages)
		}
		body, err := a.post(ctx, "/qps/rest/3.0/search/was/webapp", webAppQuery(lastID))
		if err != nil {
			return nil, err
		}
		got, more, err := parseWebApps(body)
		if err != nil {
			return nil, err
		}
		for _, w := range got {
			out = append(out, w)
			if n, err := strconv.Atoi(w.ID); err == nil && n > lastID {
				lastID = n
			}
		}
		if !more {
			break
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("qualys WAS: web app list reported more records but returned none")
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// webAppQuery is one page. No <filters> at all on the first page: an empty
// element is not something the strict schema is promised to accept.
func webAppQuery(afterID int) string {
	filters := ""
	if afterID > 0 {
		filters = fmt.Sprintf(`<filters><Criteria field="id" operator="GREATER">%d</Criteria></filters>`, afterID)
	}
	return fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences>%s</ServiceRequest>`,
		webAppPageSize, filters)
}

func parseWebApps(body []byte) ([]WebApp, bool, error) {
	var resp struct {
		XMLName              xml.Name `xml:"ServiceResponse"`
		ResponseCode         string   `xml:"responseCode"`
		HasMoreRecords       bool     `xml:"hasMoreRecords"`
		ResponseErrorDetails struct {
			ErrorMessage string `xml:"errorMessage"`
		} `xml:"responseErrorDetails"`
		Data struct {
			Apps []struct {
				ID   int    `xml:"id"`
				Name string `xml:"name"`
				URL  string `xml:"url"`
			} `xml:"WebApp"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, false, fmt.Errorf("qualys WAS: web app list is not the expected XML: %w", err)
	}
	if resp.ResponseCode != "SUCCESS" {
		return nil, false, fmt.Errorf("qualys WAS: %s: %s", resp.ResponseCode,
			strings.TrimSpace(resp.ResponseErrorDetails.ErrorMessage))
	}
	var out []WebApp
	for _, w := range resp.Data.Apps {
		if w.ID == 0 {
			continue
		}
		out = append(out, WebApp{ID: strconv.Itoa(w.ID), Name: strings.TrimSpace(w.Name), URL: strings.TrimSpace(w.URL)})
	}
	return out, resp.HasMoreRecords, nil
}
