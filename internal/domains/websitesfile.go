package domains

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"
)

// THE LIVE WEBSITES, FOR THE APPSEC LANE
//
// The domains lane knows which of our domains serve a working website. The
// AppSec lane knows which websites Qualys WAS scans. A live website that no
// web application scan covers is a coverage gap, and neither lane can see it
// alone - so this lane writes the list, and cti-appscan compares.
//
// Only "Live website": a registrar lander, a parked or for-sale page and a
// redirect to another domain have nothing to scan, and a domain marked
// "landing" in domains.txt is a landing page by the owner's say-so.

// Website is one domain with a working site of its own.
type Website struct {
	Domain string `json:"domain"`
	// Host is where the site ended up (after a same-site redirect, e.g. to
	// www.), URL the final URL, for matching against scanner targets.
	Host   string `json:"host"`
	URL    string `json:"url,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status,omitempty"`
}

// WebsitesFile is cti-domains --websites-out.
type WebsitesFile struct {
	Generated time.Time `json:"generated"`
	Sites     []Website `json:"sites"`
}

// LiveWebsites lists the domains whose site is live and not a landing page.
func LiveWebsites(results []Result, now time.Time) WebsitesFile {
	wf := WebsitesFile{Generated: now.UTC()}
	for _, r := range results {
		if r.Entry.Landing || classifySite(r).class != siteLive {
			continue
		}
		site := Website{Domain: r.Entry.Name, Host: r.Entry.Name}
		for _, w := range r.Web {
			if !w.Live() || w.ParkedBy() != "" {
				continue
			}
			b := w.Best()
			site.Status, site.Title = b.Status, strings.Join(strings.Fields(b.Title), " ")
			site.Host = w.Host
			if u, err := url.Parse(b.FinalURL); err == nil && u.Hostname() != "" {
				site.Host, site.URL = strings.ToLower(u.Hostname()), b.FinalURL
			}
			break
		}
		wf.Sites = append(wf.Sites, site)
	}
	sort.Slice(wf.Sites, func(i, j int) bool { return wf.Sites[i].Domain < wf.Sites[j].Domain })
	return wf
}

// JSON is the file body.
func (wf WebsitesFile) JSON() []byte {
	b, _ := json.MarshalIndent(wf, "", "  ")
	return append(b, '\n')
}
