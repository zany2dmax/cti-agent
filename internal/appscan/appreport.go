package appscan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// THE SCANNER'S OWN REPORT, FOR THE TICKET
//
// A ticket carries our text: where, what, risk, fix. Developers also want the
// report the scanner itself produces - the request and response for each
// finding, laid out the way the scanner's documentation describes. That is a
// separate thing to fetch, and every DAST product does it differently:
//
//   - Qualys WAS: create a report, poll it, download it, delete it.
//   - Invicti / Acunetix: generate a report for a scan, then download it.
//   - Wiz (DAST): request an export, poll, download from a signed URL.
//
// ReportFetcher is the one shape the rest of the fleet sees. cmd/cti-appreport
// picks an implementation by APPSCAN_REPORT_PROVIDER, writes what it returns,
// and cti-jira attaches it. Adding a scanner is: a package implementing
// ReportFetcher, and one case in cti-appreport's provider switch. Nothing in
// cti-jira or the runner changes.

// ReportFetcher is implemented by providers that can produce their own
// report for one application. Optional, like DetailFetcher and
// RemedyFetcher: without it the ticket still carries every finding.
type ReportFetcher interface {
	// Name is the provider key, e.g. "qualys-was".
	Name() string
	// AppReport asks the scanner for its report on one application, waits
	// for it, and returns it zipped. An implementation removes anything it
	// created on the scanner side - success or failure - unless req.Keep.
	AppReport(ctx context.Context, req ReportRequest) (Report, error)
}

// ReportRequest is what to report on.
type ReportRequest struct {
	AppID string // the scanner's id for the application; required
	App   string // display name, for the file name and messages
	// Statuses limits the report to findings in these states. Empty means
	// OpenStatuses. Vulnerabilities only, always: information-gathered items
	// are most of a raw report and nobody fixes them.
	Statuses []string
	// Keep leaves the report on the scanner for inspection (debugging).
	Keep bool
	// Timeout bounds this one report, create to download; 0 means the
	// provider's default.
	Timeout time.Duration
}

// OpenStatuses is what a ticket tracks: findings not yet fixed.
var OpenStatuses = []string{"NEW", "ACTIVE", "REOPENED"}

// Report is one application's report, always a zip archive.
type Report struct {
	Provider  string    `json:"provider"`
	AppID     string    `json:"appId"`
	App       string    `json:"app"`
	File      string    `json:"file"` // base name within the reports directory
	Bytes     int       `json:"bytes"`
	Generated time.Time `json:"generated"`
	RemoteID  string    `json:"remoteId,omitempty"` // the scanner's report id
	Kept      bool      `json:"kept,omitempty"`     // left on the scanner
	Body      []byte    `json:"-"`
}

// RateReporter is implemented by providers that can say where the API budget
// stands, for cti-appreport to log. Optional.
type RateReporter interface {
	RateStatus() string
}

// MaxReportBytes bounds one report. A sample application's HTML report was
// 4.2 MB unzipped; this is far beyond that, and anything bigger is not
// something a developer opens from a ticket.
const MaxReportBytes = 50 << 20

// IsZip reports whether b starts like a zip archive.
func IsZip(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], []byte("PK\x03\x04"))
}

// ZipOne wraps one file in a zip archive - for a provider whose report comes
// back as bare HTML or PDF.
func ZipOne(name string, content []byte, modified time.Time) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: modified})
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(content); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReportFile is the reports directory's name for one application's report.
// Keyed by the ticket label, so cti-jira finds it from the ticket input
// alone, and safe as a file name by construction.
func ReportFile(appKey string) string { return AppLabel(appKey) + ".zip" }

// ReportsManifest is cti-appreport's reports.json: what was fetched, what was
// not and why. cti-jira attaches only what is listed here.
type ReportsManifest struct {
	Generated time.Time         `json:"generated"`
	Provider  string            `json:"provider"`
	Reports   map[string]Report `json:"reports"`          // by AppKey
	Failed    map[string]string `json:"failed,omitempty"` // AppKey -> why
}

// ManifestName is the manifest's file name inside the reports directory.
const ManifestName = "reports.json"

// WriteReport writes one report (0600) and returns its manifest entry.
func WriteReport(dir, appKey string, r Report) (Report, error) {
	if !IsZip(r.Body) {
		return r, fmt.Errorf("the %s report for %q is not a zip archive", r.Provider, r.App)
	}
	if len(r.Body) > MaxReportBytes {
		return r, fmt.Errorf("the %s report for %q is %d MB - over the %d MB limit",
			r.Provider, r.App, len(r.Body)>>20, MaxReportBytes>>20)
	}
	r.File = ReportFile(appKey)
	r.Bytes = len(r.Body)
	if err := writeNew(filepath.Join(dir, r.File), r.Body); err != nil {
		return r, err
	}
	return r, nil
}

// writeNew writes a fresh 0600 file, never through whatever is already at
// the path: an existing file or a planted symlink is removed first, and the
// create is exclusive.
func writeNew(path string, b []byte) error {
	// #nosec G703 -- dir is the operator's --out-dir; names are ours ([a-z0-9-] or reports.json)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	// #nosec G304 G703 -- as above
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteManifest writes reports.json (0600).
func WriteManifest(dir string, m ReportsManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, ManifestName), append(b, '\n'))
}

// providerRE is what a provider key may be: it becomes part of the
// attachment's name in Jira.
var providerRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// LoadReport returns one application's report from a reports directory, or
// ok=false when there is none. Only a file the manifest lists, with the name
// ReportFile gives, a zip, within the size limit - a stray or stale file in
// the directory is never attached to a ticket.
func LoadReport(dir, appKey, appID string) (Report, bool, error) {
	if strings.TrimSpace(dir) == "" {
		return Report{}, false, nil
	}
	// #nosec G304 G703 -- the runner's own reports directory
	mb, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if os.IsNotExist(err) {
		return Report{}, false, nil
	}
	if err != nil {
		return Report{}, false, err
	}
	var m ReportsManifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Report{}, false, fmt.Errorf("%s is not a reports manifest: %w", ManifestName, err)
	}
	r, ok := m.Reports[appKey]
	if !ok {
		return Report{}, false, nil
	}
	if r.AppID != appID {
		return Report{}, false, fmt.Errorf("manifest's report for %s is for web app %q, not %q", appKey, r.AppID, appID)
	}
	if !providerRE.MatchString(r.Provider) {
		return Report{}, false, fmt.Errorf("manifest names provider %q - not a provider key", r.Provider)
	}
	if r.File != ReportFile(appKey) {
		return Report{}, false, fmt.Errorf("manifest names %q for %s, expected %q", r.File, appKey, ReportFile(appKey))
	}
	path := filepath.Join(dir, r.File)
	st, err := os.Lstat(path)
	if err != nil {
		return Report{}, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxReportBytes {
		return Report{}, false, fmt.Errorf("%s is not a regular file within %d MB", r.File, MaxReportBytes>>20)
	}
	// #nosec G304 G703 -- name checked above against ReportFile
	body, err := os.ReadFile(path)
	if err != nil {
		return Report{}, false, err
	}
	if !IsZip(body) {
		return Report{}, false, fmt.Errorf("%s is not a zip archive", r.File)
	}
	r.Body = body
	return r, true, nil
}
