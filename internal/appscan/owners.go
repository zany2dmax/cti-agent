package appscan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// WHO OWNS EACH APPLICATION
//
// An application ticket nobody is assigned is a ticket nobody works. The
// scanner knows the application, not who writes its code, so that mapping is
// an operator file beside domains.txt - /etc/cti-agent/app-owners.txt,
// never in the repository, which is public:
//
//	# application                 | owner                | Jira component (optional)
//	id:123456                     | dev.lead@example.com | Web Portal
//	Customer Portal               | dev.lead@example.com
//	id:777777                     | dev.lead@example.com | Web | covers=www.example.com
//	site:brochure.example.com     | web.team@example.com
//
// Two more kinds of line, both for the coverage check:
//
//   - covers=<host>[,<host>...] on a web app's line says that web app stands
//     in for those production sites - typically a staging copy (a WP Engine
//     *.wpenginepowered.com install, say) scanned instead of the live site.
//     The production site is then reported "covered via staging", not "not
//     scanned", and the web app's ticket says the fix goes into the code and
//     then gets deployed. It is a proxy, not a scan of production, and the
//     report never says otherwise.
//   - site:<domain> names who should get a scan set up for a live website no
//     web app covers yet (written by --list-apps from the domains lane).
//
// The application is the scanner's own web-app id ("id:" + digits, which
// survives a rename) or its exact name, case-insensitive. The owner is an
// email address, looked up in Jira when the ticket is filed. An application
// with no line - or a line the parser could not read - gets an unassigned
// ticket, and the weekly report says so: silently routing it nowhere is how
// an Urgent finding sits for a quarter.

// Owner is one application's owner.
type Owner struct {
	Email     string
	Component string
	Line      int    // in the owners file, for messages
	App       string // the application as the file wrote it ("id:123" or a name)
	// Covers are production hosts this web app stands in for (covers=),
	// compared without "www.".
	Covers []string
}

// PlaceholderOwner is what --list-apps writes for an application with no
// owner yet. The parser refuses it, so an unedited line is "no owner", not an
// assignment to a mailbox that does not exist.
const PlaceholderOwner = "OWNER@example.com"

// Owners maps applications to owners.
type Owners struct {
	byID   map[string]Owner
	byName map[string]Owner
	// bySite are "site:<domain>" lines: live websites with no web app scan
	// yet, recorded so the gap has an owner to set the scan up.
	bySite map[string]Owner
	// coversOnly keeps covers= from a line whose owner is still the
	// placeholder: the stand-in relationship is a fact about the web app,
	// not about who owns it, and must survive --list-apps regenerating.
	coversOnly map[string][]string // by "id:N" or lower-case name
}

// DefaultOwnersFile is where the file lives unless APPSCAN_OWNERS_FILE says.
const DefaultOwnersFile = "/etc/cti-agent/app-owners.txt"

// OwnersPath is APPSCAN_OWNERS_FILE or the default.
func OwnersPath() string {
	if p := strings.TrimSpace(os.Getenv("APPSCAN_OWNERS_FILE")); p != "" {
		return p
	}
	return DefaultOwnersFile
}

var (
	ownerEmailRE = regexp.MustCompile(`^[^@\s|]+@[^@\s|]+\.[^@\s|]+$`)
	ownerIDRE    = regexp.MustCompile(`^id:\s*([0-9]{1,20})$`)
)

// ParseOwners reads the file. Problems are lines it could not use, worded for
// the report; they never stop the lane.
func ParseOwners(r io.Reader) (Owners, []string, error) {
	o := Owners{byID: map[string]Owner{}, byName: map[string]Owner{}, bySite: map[string]Owner{},
		coversOnly: map[string][]string{}}
	var problems []string
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) < 2 || f[0] == "" || f[1] == "" {
			problems = append(problems, fmt.Sprintf("app-owners line %d: want \"application | owner email [| component]\"", n))
			continue
		}
		if !ownerEmailRE.MatchString(f[1]) {
			problems = append(problems, fmt.Sprintf("app-owners line %d: %q is not an email address", n, f[1]))
			continue
		}
		component, covers, bad := extraFields(f[2:])
		for _, b := range bad {
			problems = append(problems, fmt.Sprintf("app-owners line %d: %s", n, b))
		}
		if strings.EqualFold(f[1], PlaceholderOwner) {
			problems = append(problems, fmt.Sprintf("app-owners line %d: %s has no owner yet (still %s)", n, f[0], PlaceholderOwner))
			if len(covers) > 0 {
				o.coversOnly[appRef(f[0])] = covers
			}
			continue
		}
		own := Owner{Email: strings.ToLower(f[1]), Line: n, App: f[0], Component: component, Covers: covers}
		if len(covers) > 0 && strings.HasPrefix(strings.ToLower(f[0]), "site:") {
			problems = append(problems, fmt.Sprintf("app-owners line %d: covers= belongs on a web app's line, not a site: line - ignored", n))
			own.Covers = nil
		}
		if d, ok := strings.CutPrefix(strings.ToLower(f[0]), "site:"); ok {
			d = hostOf(d)
			if d == "" {
				problems = append(problems, fmt.Sprintf("app-owners line %d: site: needs a domain", n))
				continue
			}
			o.bySite[d] = own
			continue
		}
		if m := ownerIDRE.FindStringSubmatch(strings.ToLower(f[0])); m != nil {
			if prev, dup := o.byID[m[1]]; dup {
				problems = append(problems, fmt.Sprintf("app-owners line %d: id %s already listed on line %d; the later line wins", n, m[1], prev.Line))
			}
			o.byID[m[1]] = own
			continue
		}
		key := strings.ToLower(f[0])
		if prev, dup := o.byName[key]; dup {
			problems = append(problems, fmt.Sprintf("app-owners line %d: %q already listed on line %d; the later line wins", n, f[0], prev.Line))
		}
		o.byName[key] = own
	}
	return o, problems, sc.Err()
}

// LoadOwners reads the file at path. A missing file is no owners and one
// problem, not an error: the lane still reports and still files tickets,
// unassigned.
func LoadOwners(path string) (Owners, []string) {
	f, err := os.Open(path) // #nosec G304 -- operator config path from fleet.env or the default
	if err != nil {
		return Owners{}, []string{fmt.Sprintf("no application owners file at %s (%v) - every ticket is unassigned", path, err)}
	}
	defer func() { _ = f.Close() }()
	o, problems, err := ParseOwners(f)
	if err != nil {
		problems = append(problems, fmt.Sprintf("reading %s: %v", path, err))
	}
	return o, problems
}

// For returns the owner for an application: by scanner id first, then by
// name. ok is false when the file does not list it.
func (o Owners) For(appID, app string) (Owner, bool) {
	if appID != "" {
		if w, ok := o.byID[strings.TrimSpace(appID)]; ok {
			return w, true
		}
	}
	w, ok := o.byName[strings.ToLower(strings.TrimSpace(app))]
	return w, ok
}

// App is an application as the scanner defines it.
type App struct {
	ID   string
	Name string
	URL  string
}

// OwnersSkeleton is a complete app-owners.txt for these applications: the
// owner already on file where there is one, PlaceholderOwner where there is
// not. unowned are the applications with no owner; stale are owners-file
// entries that match no application (renamed, or deleted from the scanner).
// extraFields reads the optional fields after the owner: at most one Jira
// component, and any number of covers=host[,host] entries.
func extraFields(f []string) (component string, covers []string, bad []string) {
	seen := map[string]bool{}
	for _, x := range f {
		if x == "" {
			continue
		}
		if v, ok := strings.CutPrefix(strings.ToLower(x), "covers="); ok {
			for _, h := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				h = hostOf(h)
				if h == "" || !strings.Contains(h, ".") {
					bad = append(bad, fmt.Sprintf("covers=%s is not a host name", h))
					continue
				}
				if !seen[h] {
					seen[h] = true
					covers = append(covers, h)
				}
			}
			continue
		}
		if component == "" {
			component = x
			continue
		}
		bad = append(bad, fmt.Sprintf("extra field %q ignored (one component per line)", x))
	}
	return component, covers, bad
}

// appRef is how a line's application is keyed: "id:N" or the lower-case name.
func appRef(app string) string {
	if m := ownerIDRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(app))); m != nil {
		return "id:" + m[1]
	}
	return strings.ToLower(strings.TrimSpace(app))
}

// CoversFor is the production hosts a web app stands in for, from its
// owner line or from a placeholder line that still records covers=.
func (o Owners) CoversFor(appID, app string) []string {
	if w, ok := o.For(appID, app); ok && len(w.Covers) > 0 {
		return w.Covers
	}
	if appID != "" {
		if c := o.coversOnly["id:"+strings.TrimSpace(appID)]; len(c) > 0 {
			return c
		}
	}
	return o.coversOnly[strings.ToLower(strings.TrimSpace(app))]
}

// stagingHint reports whether a web app's URL looks like a staging or test
// copy, so --list-apps can ask what production site it stands in for.
func stagingHint(rawURL string) bool {
	h := hostOf(rawURL)
	for _, suf := range []string{".wpengine.com", ".wpenginepowered.com", ".kinsta.cloud", ".pantheonsite.io",
		".flywheelstaging.com", ".cloudwaysapps.com"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	first := h
	if i := strings.Index(h, "."); i > 0 {
		first = h[:i]
	}
	for _, p := range []string{"staging", "stage", "stg", "dev", "test", "uat", "qa", "preprod", "sandbox"} {
		if first == p || strings.HasPrefix(first, p+"-") || strings.HasSuffix(first, "-"+p) {
			return true
		}
	}
	return false
}

// ForSite is the owner recorded for a live website with no scan yet.
func (o Owners) ForSite(domain string) (Owner, bool) {
	w, ok := o.bySite[hostOf(domain)]
	return w, ok
}

func OwnersSkeleton(apps []App, sites []Site, o Owners) (text string, unowned []App, stale []string) {
	var b strings.Builder
	b.WriteString("# Application owners for the AppSec lane's Jira tickets.\n")
	b.WriteString("# application | owner email | Jira component (optional) | covers=<production host> (optional)   # name  url\n")
	b.WriteString("# Generated by cti-appscan --list-apps; replace every " + PlaceholderOwner + ".\n\n")
	used := map[int]bool{}
	for _, a := range apps {
		comment := strings.Join(strings.Fields(a.Name+"  "+a.URL), " ")
		covers := o.CoversFor(a.ID, a.Name)
		coversField := ""
		if len(covers) > 0 {
			coversField = " | covers=" + strings.Join(covers, ",")
		} else if stagingHint(a.URL) {
			comment += "  <- staging/test host? add | covers=<production host> if it stands in for a live site"
		}
		w, ok := o.For(a.ID, a.Name)
		if !ok {
			unowned = append(unowned, a)
			fmt.Fprintf(&b, "id:%s | %s%s    # %s  <- no owner\n", a.ID, PlaceholderOwner, coversField, comment)
			continue
		}
		used[w.Line] = true
		line := fmt.Sprintf("id:%s | %s", a.ID, w.Email)
		if w.Component != "" {
			line += " | " + w.Component
		}
		fmt.Fprintf(&b, "%s%s    # %s\n", line, coversField, comment)
	}
	gap, proxied := Coverage(sites, apps, o)
	if len(proxied) > 0 {
		b.WriteString("\n# Covered only through a stand-in web app (covers=) - production itself is not scanned:\n")
		for _, p := range proxied {
			fmt.Fprintf(&b, "#   %s  via id:%s (%s)\n", p.Site.Domain, p.App.ID, hostOf(p.App.URL))
		}
	}
	if len(gap) > 0 {
		b.WriteString("\n# LIVE WEBSITES WITH NO QUALYS WAS WEB APP - NOT SCANNED (from the domains check).\n")
		b.WriteString("# The owner here is who should get a web application scan set up; the line\n")
		b.WriteString("# goes away by itself once a web app in Qualys WAS points at the site.\n")
		for _, s := range gap {
			comment := strings.Join(strings.Fields(s.Title+"  "+s.URL), " ")
			owner := PlaceholderOwner
			if w, ok := o.ForSite(s.Domain); ok {
				used[w.Line] = true
				owner = w.Email
			}
			fmt.Fprintf(&b, "site:%s | %s    # %s\n", s.Domain, owner, comment)
		}
	}
	var all []Owner
	for _, w := range o.bySite {
		all = append(all, w)
	}
	for _, w := range o.byID {
		all = append(all, w)
	}
	for _, w := range o.byName {
		all = append(all, w)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Line < all[j].Line })
	for _, w := range all {
		if !used[w.Line] {
			stale = append(stale, fmt.Sprintf("line %d: %s | %s", w.Line, w.App, w.Email))
		}
	}
	if len(stale) > 0 {
		b.WriteString("\n# In the old file but matching no application in the scanner (renamed or removed):\n")
		for _, s := range stale {
			b.WriteString("#   " + s + "\n")
		}
	}
	return b.String(), unowned, stale
}
