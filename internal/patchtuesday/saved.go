package patchtuesday

import (
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SAVED COPIES OF THE ARTICLES
//
// Both publishers put their articles behind Cloudflare's bot check, which
// refuses the fleet's Azure address outright. The articles are the part of
// the synopsis a person adds value to - which CVEs matter, the Edge count,
// the Adobe paragraph - so the operator saves the two pages in a browser and
// drops them in a folder on the box, and the lane reads them instead of
// fetching. Microsoft's own data does not depend on them.
//
// The folder is one per release: $FLEET_HOME/inbox/patchtuesday/YYYY-MM/.
// A file whose name contains "qualys" is the Qualys review; one containing
// "bleeping" is the BleepingComputer article. Either a saved web page (.html,
// .htm) or copied text (.txt).

// maxSaved bounds a saved page. A browser's "Web Page, Complete" save is a
// few hundred KB of HTML; anything far larger is the wrong file.
const maxSaved = 16 << 20

// DropDir is the release's folder under home: inbox/patchtuesday/YYYY-MM.
func DropDir(home string, year int, month time.Month) string {
	return filepath.Join(home, "inbox", "patchtuesday", MonthKey(year, month))
}

// FindSaved returns the saved copy for a source in dir, by a substring of the
// file name ("qualys", "bleeping"), or "" when there is none. Hidden files
// and anything that is not a regular file are ignored; with several matches
// the newest wins.
func FindSaved(dir, key string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	type cand struct {
		path string
		mod  int64
	}
	var found []cand
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if strings.HasPrefix(name, ".") || !strings.Contains(name, key) {
			continue
		}
		switch filepath.Ext(name) {
		case ".html", ".htm", ".txt":
		default:
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		found = append(found, cand{filepath.Join(dir, e.Name()), info.ModTime().UnixNano()})
	}
	if len(found) == 0 {
		return ""
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod > found[j].mod })
	return found[0].path
}

// LoadSaved reads a saved copy as a Source, exactly as Fetch would have
// returned the page. The URL stays the article's own, so the email links to
// it; the name says the copy was saved by hand.
func LoadSaved(path, name, url string) Source {
	s := Source{Name: name + " (saved copy)", URL: url}
	// #nosec G304 -- path is a file the operator placed in the release's
	// drop folder under $FLEET_HOME, found by FindSaved.
	f, err := os.Open(path)
	if err != nil {
		s.Err = err.Error()
		return s
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSaved+1))
	if err != nil {
		s.Err = "read failed: " + err.Error()
		return s
	}
	if len(b) > maxSaved {
		s.Err = fmt.Sprintf("%s is over %d MB - not a saved article", filepath.Base(path), maxSaved>>20)
		return s
	}
	raw := string(b)
	if strings.EqualFold(filepath.Ext(path), ".txt") {
		// Copied text has lines, not tags. Each line becomes a paragraph so
		// StripHTML keeps the block boundaries the prose patterns rely on.
		var p strings.Builder
		for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
			p.WriteString("<p>" + html.EscapeString(line) + "</p>\n")
		}
		raw = p.String()
	}
	s.RawHTML = raw
	s.Text = StripHTML(raw)
	if strings.TrimSpace(s.Text) == "" {
		s.Err = filepath.Base(path) + " is empty"
		return s
	}
	s.Fetched = true
	return s
}
