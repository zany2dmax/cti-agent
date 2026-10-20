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
}

// PlaceholderOwner is what --list-apps writes for an application with no
// owner yet. The parser refuses it, so an unedited line is "no owner", not an
// assignment to a mailbox that does not exist.
const PlaceholderOwner = "OWNER@example.com"

// Owners maps applications to owners.
type Owners struct {
	byID   map[string]Owner
	byName map[string]Owner
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
	o := Owners{byID: map[string]Owner{}, byName: map[string]Owner{}}
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
		if strings.EqualFold(f[1], PlaceholderOwner) {
			problems = append(problems, fmt.Sprintf("app-owners line %d: %s has no owner yet (still %s)", n, f[0], PlaceholderOwner))
			continue
		}
		own := Owner{Email: strings.ToLower(f[1]), Line: n, App: f[0]}
		if len(f) > 2 {
			own.Component = f[2]
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
func OwnersSkeleton(apps []App, o Owners) (text string, unowned []App, stale []string) {
	var b strings.Builder
	b.WriteString("# Application owners for the AppSec lane's Jira tickets.\n")
	b.WriteString("# application | owner email | Jira component (optional)   # name  url\n")
	b.WriteString("# Generated by cti-appscan --list-apps; replace every " + PlaceholderOwner + ".\n\n")
	used := map[int]bool{}
	for _, a := range apps {
		comment := strings.Join(strings.Fields(a.Name+"  "+a.URL), " ")
		w, ok := o.For(a.ID, a.Name)
		if !ok {
			unowned = append(unowned, a)
			fmt.Fprintf(&b, "id:%s | %s    # %s  <- no owner\n", a.ID, PlaceholderOwner, comment)
			continue
		}
		used[w.Line] = true
		line := fmt.Sprintf("id:%s | %s", a.ID, w.Email)
		if w.Component != "" {
			line += " | " + w.Component
		}
		fmt.Fprintf(&b, "%s    # %s\n", line, comment)
	}
	var all []Owner
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
