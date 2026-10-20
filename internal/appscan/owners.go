package appscan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
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
	Line      int // in the owners file, for messages
}

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
		own := Owner{Email: strings.ToLower(f[1]), Line: n}
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
