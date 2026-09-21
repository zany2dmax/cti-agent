package patchtuesday

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manifest records which CVEs a month's synopsis covers, so the daily digest
// can leave them to it.
//
// # WHY A FILE AND NOT A HEURISTIC
//
// Patch Tuesday puts hundreds of Microsoft CVEs in the mailbox in one
// afternoon. They belong in the monthly synopsis, where they are organised by
// the update that fixes them; repeated in the daily digest they are several
// hundred rows that say "Microsoft released patches", which buries the two or
// three things the daily exists to surface.
//
// The obvious implementation - "drop Microsoft CVEs around the second Tuesday"
// - is a guess, and a guess that silently discards security mail is the worst
// kind of code in this repository. So suppression is evidence-based: the
// monthly lane writes down exactly which CVEs it covered, and the daily holds
// back only those.
//
// # THE SENT FLAG IS THE WHOLE SAFETY PROPERTY
//
// A manifest written by a run whose email never went out must not authorise
// anything. Otherwise a broken monthly lane - bad credentials, a failed fetch,
// a mailer refusal - would take the daily's Microsoft coverage down with it,
// and the result would be no email mentioning those CVEs at all, from either
// lane, with nothing in either output saying so. That is the failure this
// codebase keeps finding: a suppression that works perfectly and means
// nobody is told.
//
// So cti-patchtuesday writes Sent=false, and run-patchtuesday calls
// `cti-patchtuesday --mark-sent` only after mailer.py reports success. Held is
// the only function that decides anything, and it ignores every manifest that
// is not marked sent.
type Manifest struct {
	Month     string    `json:"month"` // YYYY-MM
	WrittenAt time.Time `json:"written_at"`

	// CVEs is every CVE attributed to the release, whether or not it is
	// present here. Presence is a fact about our estate; coverage by the
	// monthly email is a fact about the email, and it is coverage that
	// authorises the daily to stay quiet.
	CVEs []string `json:"cves"`
	// QIDs with open detections, and the machine count, kept for the record so
	// a question about last month can be answered from state without a replay.
	QIDs  []int `json:"qids,omitempty"`
	Hosts int   `json:"hosts,omitempty"`

	Sent   bool      `json:"sent"`
	SentAt time.Time `json:"sent_at,omitempty"`
}

// ManifestPath is where a month's manifest lives. Empty when there is no
// FLEET_HOME, which means "no manifest" rather than a path under the current
// directory: a state file that lands wherever the command was run from is a
// state file that gets read by accident and written twice.
func ManifestPath(home string, year int, month time.Month) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state",
		fmt.Sprintf("patchtuesday-%04d-%02d.json", year, int(month)))
}

// MonthKey is the YYYY-MM form used in the manifest and its filename.
func MonthKey(year int, month time.Month) string {
	return fmt.Sprintf("%04d-%02d", year, int(month))
}

// WriteManifest saves atomically at 0600.
//
// 0600 because the CVE list is harmless but the host count is not the kind of
// thing to leave group-readable, and every other state file here is 0600 -
// one file with looser permissions is the one an audit finds.
func WriteManifest(path string, m Manifest) error {
	if path == "" {
		return fmt.Errorf("no manifest path (FLEET_HOME is not set)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("manifest directory: %w", err)
	}
	sort.Strings(m.CVEs)
	sort.Ints(m.QIDs)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}
	tmp := path + ".tmp"
	// #nosec G306 -- 0600 is the restrictive choice being asserted here.
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	// Rename last, so a reader never sees a half-written manifest and
	// concludes the release covered three CVEs.
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("installing manifest: %w", err)
	}
	return nil
}

// LoadManifest reads one manifest. A missing file is not an error - most
// months, most days, there is nothing to read - but a corrupt one is: acting
// on half a CVE list means holding back an arbitrary subset of the release.
func LoadManifest(path string) (Manifest, bool, error) {
	if path == "" {
		return Manifest{}, false, nil
	}
	// #nosec G304 -- path is built by ManifestPath from FLEET_HOME.
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Manifest{}, false, nil
	}
	if err != nil {
		return Manifest{}, false, fmt.Errorf("reading %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, false, fmt.Errorf("%s does not parse: %w", path, err)
	}
	return m, true, nil
}

// MarkSent flips the flag after the synopsis has actually gone out.
func MarkSent(path string, when time.Time) error {
	m, ok, err := LoadManifest(path)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no manifest at %s to mark sent", path)
	}
	if m.Sent {
		return nil // idempotent: a re-run of the runner must not be an error
	}
	m.Sent, m.SentAt = true, when
	return WriteManifest(path, m)
}

// RecentManifests loads the manifests that may authorise suppression: this
// month's and last month's.
//
// Two months, not all of them. A CVE from the September release turning up in
// the mailbox in December is not an echo of the September email - something is
// re-raising it, and that is the daily's entire job. An unbounded window would
// mean the longer the fleet runs, the more it silently refuses to mention.
func RecentManifests(home string, now time.Time) ([]Manifest, error) {
	// Not now.AddDate(0, -1, 0). One month back from 31 March is 31 February,
	// which Go normalises to 2 or 3 March - so on the 29th to 31st of a long
	// month that expression returns THIS month twice and last month never, and
	// the previous release quietly stops being suppressed for three days a
	// year. The first of this month, minus one day, is the last day of the
	// previous month for every month there has ever been.
	firstOfThis := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	lastOfPrev := firstOfThis.AddDate(0, 0, -1)

	var out []Manifest
	var errs []string
	for _, t := range []time.Time{now, lastOfPrev} {
		path := ManifestPath(home, t.Year(), t.Month())
		m, ok, err := LoadManifest(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if ok {
			out = append(out, m)
		}
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

// Held splits CVEs into the ones to report today and the ones a sent monthly
// synopsis has already covered.
//
// keep preserves the caller's order. held maps each withheld CVE to the month
// that covered it, so the caller can say which email to go and read instead of
// just announcing that something was removed.
func Held(cves []string, manifests []Manifest) (keep []string, held map[string]string) {
	held = map[string]string{}
	covered := map[string]string{}
	for _, m := range manifests {
		// The one rule that matters. An unsent manifest describes an email
		// nobody received.
		if !m.Sent {
			continue
		}
		for _, c := range m.CVEs {
			covered[strings.ToUpper(strings.TrimSpace(c))] = m.Month
		}
	}
	for _, c := range cves {
		if month, ok := covered[strings.ToUpper(strings.TrimSpace(c))]; ok {
			held[c] = month
			continue
		}
		keep = append(keep, c)
	}
	return keep, held
}

// HoldNote is the one line the daily digest prints in place of the CVEs it
// held back. Empty when nothing was held.
//
// Deliberately one line with a count and a month. The operator's rule for the
// digest is a quick number, not an essay: make it large and people write a
// rule that sends the whole thing to Trash.
func HoldNote(held map[string]string) string {
	if len(held) == 0 {
		return ""
	}
	months := map[string]int{}
	for _, m := range held {
		months[m]++
	}
	keys := make([]string, 0, len(months))
	for k := range months {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d from %s", months[k], k))
	}
	return fmt.Sprintf(
		"%d CVE(s) held back (%s): covered by the Patch Tuesday synopsis already sent.",
		len(held), strings.Join(parts, ", "))
}
