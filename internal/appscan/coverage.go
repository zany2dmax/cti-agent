package appscan

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LIVE WEBSITES WITH NO WEB APPLICATION SCAN
//
// The domains lane writes the domains that serve a live website of their own
// (cti-domains --websites-out; landers, parked pages, redirects and domains
// marked "landing" are left out). A live website no Qualys WAS web app's URL
// points at is not being scanned at all - the gap this lane's own reports
// cannot show, because they only describe what IS scanned.

// Site is one live website from the domains lane.
type Site struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
	URL    string `json:"url,omitempty"`
	Title  string `json:"title,omitempty"`
}

// DefaultSitesFile is where run-domains writes the list.
func DefaultSitesFile() string {
	if p := strings.TrimSpace(os.Getenv("APPSCAN_WEBSITES_FILE")); p != "" {
		return p
	}
	home := strings.TrimSpace(os.Getenv("FLEET_HOME"))
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state", "domains-websites.json")
}

// LoadSites reads the domains lane's list and when it was written.
func LoadSites(path string) ([]Site, time.Time, error) {
	// #nosec G304 -- APPSCAN_WEBSITES_FILE or the fleet's own state file.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var f struct {
		Generated time.Time `json:"generated"`
		Sites     []Site    `json:"sites"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, time.Time{}, err
	}
	return f.Sites, f.Generated, nil
}

// HostOf is hostOf, for callers outside the package.
func HostOf(s string) string { return hostOf(s) }

// hostOf is a comparable host: lower case, no port, no leading "www.".
func hostOf(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimPrefix(strings.TrimSuffix(s, "."), "www.")
}

// Proxied is a live website covered only by a stand-in web app (covers=).
type Proxied struct {
	Site Site
	App  App
}

// Coverage splits the live websites into the ones nothing scans and the ones
// covered only through a stand-in. A site a web app scans directly is in
// neither: direct beats a proxy.
func Coverage(sites []Site, apps []App, o Owners) (unscanned []Site, proxied []Proxied) {
	stand := map[string]App{}
	for _, a := range apps {
		for _, h := range o.CoversFor(a.ID, a.Name) {
			if _, ok := stand[h]; !ok {
				stand[h] = a
			}
		}
	}
	for _, s := range Unscanned(sites, apps) {
		a, ok := stand[hostOf(s.Domain)]
		if !ok {
			a, ok = stand[hostOf(s.Host)]
		}
		if ok {
			proxied = append(proxied, Proxied{Site: s, App: a})
			continue
		}
		unscanned = append(unscanned, s)
	}
	return unscanned, proxied
}

// Unscanned are the live websites no web application's URL points at,
// matched on host (www. ignored): the domain itself, or where its site ends
// up after a same-site redirect.
func Unscanned(sites []Site, apps []App) []Site {
	scanned := map[string]bool{}
	for _, a := range apps {
		if h := hostOf(a.URL); h != "" {
			scanned[h] = true
		}
	}
	var out []Site
	for _, s := range sites {
		if scanned[hostOf(s.Domain)] || scanned[hostOf(s.Host)] {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
