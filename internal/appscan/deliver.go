package appscan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/statefile"
)

// THE SCANNER'S REPORT, MAILED TO THE APPLICATION'S OWNERS
//
// Many of the people who build and watch these applications are outside the
// company and not in Jira, so a ticket does not reach them. The owners lane
// mails each application's report to the owner and watchers on its
// app-owners.txt line, the day after the scan finishes:
//
//	cti-appscan --deliveries-out D.json --delivered-log sent.json   what to send
//	cti-appreport --deliveries D.json --out-dir R                   fetch, redact, write each mail
//	cti-mailer --lane owner --app-key K --html R/<label>-mail.html  one send per application
//	cti-appscan --commit-delivered R/sent.tsv --delivered-log sent.json
//
// Who receives it is decided in cti-mailer, from app-owners.txt and
// OWNER_ALLOW_DOMAINS - never from anything in these files. A plan here can
// only name an application; it cannot name a recipient.
//
// # WHAT IS HELD BACK
//
// A scan that did not finish, whose login failed or that reached no host
// measured less than it should have, and its report would tell an owner the
// application is cleaner than it is. Those are held, and the operator is told
// instead. So is an application with no owner on file.

// Delivery is one application's report to send, or the reason it is held.
type Delivery struct {
	Key       string    `json:"key"`   // AppKey
	AppID     string    `json:"appId"` // the scanner's id; a report needs it
	App       string    `json:"app"`
	ScanTitle string    `json:"scanTitle,omitempty"`
	ScanRef   string    `json:"scanRef"`
	Finished  time.Time `json:"finished"`
	// LaunchOnly says Finished is the launch time: a scan known only from
	// the scanner's list, which gives no end time. Zero when neither is known.
	LaunchOnly bool   `json:"launchOnly,omitempty"`
	AuthLabel  string `json:"auth"`
	// Caveat is the scanner's warning about a scan that finished but may be
	// partial (Service Errors Detected). The email and the report show it.
	Caveat string `json:"caveat,omitempty"`
	// Hold is why this is not sent; empty means send. Retry says the hold
	// may clear by itself (the API was unreachable), so it is not recorded
	// as done.
	Hold  string `json:"hold,omitempty"`
	Retry bool   `json:"retry,omitempty"`
	// Counts from the notice, for the covering email. Unknown (and not
	// shown) when the scanner sent no notice.
	NoNotice bool `json:"noNotice,omitempty"`
	// OpenFromAPI says Open was counted from the scanner's API (the owner
	// report's own findings) because there was no notice. Open is then
	// known; ScanCounts and FirstScan still are not. Set by cti-appreport,
	// never read from the deliveries file.
	OpenFromAPI bool   `json:"-"`
	Open        Counts `json:"open"` // New + Reopened + Active (Lifecycle.Open)
	ScanCounts  Counts `json:"scanCounts"`
	FirstScan   bool   `json:"firstScan,omitempty"`

	// What was scanned and how the run went, for the email and the report's
	// summary. URL is the web app's address from the scanner's API record;
	// empty when the scan list was not reached.
	URL          string        `json:"url,omitempty"`
	Started      time.Time     `json:"started,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
	LinksCrawled int           `json:"linksCrawled,omitempty"`
	ScanDelta    Counts        `json:"scanDelta"`
	Launch       string        `json:"launch,omitempty"`
}

// MaxMailAttachment is the largest report the owners lane attaches. It is
// cti-mailer's inline attachment limit; a larger report goes out as the
// covering email alone, which says so.
const MaxMailAttachment = 3_000_000

// Label is the file-name stem for this delivery's files.
func (d Delivery) Label() string { return AppLabel(d.Key) }

// DeliveriesFile is cti-appscan --deliveries-out.
type DeliveriesFile struct {
	Generated  time.Time  `json:"generated"`
	Deliveries []Delivery `json:"deliveries"`
}

// DeliveredEntry is the last scan dealt with for one application.
type DeliveredEntry struct {
	Ref    string    `json:"ref"`
	At     time.Time `json:"at"`
	Status string    `json:"status"` // "sent" or "held: <why>"
}

// DeliveredLog is the owners lane's memory, keyed by AppKey: one entry per
// application, so it never grows past the number of applications.
type DeliveredLog map[string]DeliveredEntry

// ScanRef is how one scan is recognised across runs: the scanner's
// reference, or the title and finish time when it gave none.
func ScanRef(s ScanResult) string {
	if r := strings.TrimSpace(s.Reference); r != "" {
		return r
	}
	return strings.TrimSpace(s.ScanTitle) + "@" + s.Finished.UTC().Format(time.RFC3339)
}

// BuildDeliveries is what the owners lane should do about these scans: one
// entry per application, skipping a scan already sent or held.
func BuildDeliveries(scans []ScanResult, owners Owners, done DeliveredLog, now time.Time) DeliveriesFile {
	f := DeliveriesFile{Generated: now.UTC()}
	for _, s := range scans {
		key, ref := AppKey(s), ScanRef(s)
		if e, ok := done[key]; ok && e.Ref == ref {
			continue
		}
		d := Delivery{Key: key, AppID: strings.TrimSpace(s.AppID), App: s.App, ScanTitle: s.ScanTitle,
			ScanRef: ref, Finished: s.Finished, AuthLabel: s.Auth.Label(), NoNotice: s.NoNotification,
			Open: s.AppState.Open(), ScanCounts: s.ScanCounts, FirstScan: s.FirstScan,
			URL: strings.TrimSpace(s.AppURL), Started: s.Started, Duration: s.Duration,
			LinksCrawled: s.LinksCrawled, ScanDelta: s.ScanDelta, Launch: s.Launch, Caveat: s.Caveat}
		switch {
		case !s.Complete && strings.EqualFold(strings.Join(strings.Fields(s.Status), ""), "finished"):
			// The newer notice format, which needs the scan list to confirm
			// it - and the list had no matching run, or was unreachable (a
			// matched run that did not confirm it rewrites the status to say
			// what the list said, and lands in the next case). The same test
			// as qualys.BareFinished, which this package cannot import
			// (qualys imports appscan).
			d.Hold = "the notice says Finished, but no matching run was found in the Qualys scan list " +
				"(or the list was unreachable) - not counted as complete"
		case !s.Complete:
			d.Hold = "not counted as complete: " + orUnknown(s.Status)
		case s.Auth.Failed():
			d.Hold = "the scan's login failed (" + orUnknown(s.Auth.Status) + ")"
		case s.Unreachable():
			d.Hold = fmt.Sprintf("no host answered (%d scanned, 0 active)", s.HostsScanned)
		case d.AppID == "":
			d.Hold, d.Retry = "no web app id - the scanner's API was not reachable, so no report can be fetched", true
		}
		if d.Hold == "" {
			if _, ok := owners.For(s.AppID, s.App); !ok {
				d.Hold = "no owner on file"
			}
		}
		if d.Finished.IsZero() && !s.Started.IsZero() {
			d.Finished, d.LaunchOnly = s.Started, true
		}
		f.Deliveries = append(f.Deliveries, d)
	}
	sort.SliceStable(f.Deliveries, func(i, j int) bool {
		return strings.ToLower(f.Deliveries[i].App) < strings.ToLower(f.Deliveries[j].App)
	})
	return f
}

func orUnknown(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return "status not reported"
	}
	return s
}

// JSON is the file's bytes.
func (f DeliveriesFile) JSON() []byte {
	b, _ := json.MarshalIndent(f, "", "  ") // plain structs: cannot fail
	return append(b, '\n')
}

// LoadDeliveredLog reads the log; a missing file is an empty log.
func LoadDeliveredLog(p string) (DeliveredLog, error) {
	return loadDelivered(p, time.Now())
}

// loadDelivered is LoadDeliveredLog against a given clock, so that
// CommitDelivered repairs and validates against the one `now` it was handed.
func loadDelivered(p string, now time.Time) (DeliveredLog, error) {
	l := DeliveredLog{}
	// Parsing only. A log that parses is REPAIRED entry by entry, not rejected:
	// one bad old entry must not make every later commit and report fail.
	err := statefile.Read(p, &l, statefile.Options{MaxBytes: maxDeliveredBytes})
	switch {
	case err == nil:
		if notes := l.Normalize(now); len(notes) > 0 {
			fmt.Fprintf(os.Stderr, "appscan: repaired %s: %s\n", p, strings.Join(notes, "; "))
		}
		return l, nil
	case errors.Is(err, os.ErrNotExist):
		return DeliveredLog{}, nil
	case errors.Is(err, statefile.ErrInvalid):
		return nil, fmt.Errorf("%s is not a delivered log: %w", p, err)
	}
	return nil, err
}

// Bounds on the delivered log: one entry per web application, so it is as big
// as the estate and no bigger. The caps catch a damaged file or a runaway
// script, not a large legitimate one.
const (
	maxDelivered    = 100000
	maxDeliveredKey = 512
	maxDeliveredRef = 512
	maxStatus       = 500
	deliveredSkew   = 24 * time.Hour
)

func plainText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidateEntry says whether one recorded delivery is acceptable: the shape the
// runner writes ("sent", or "held: <why>"), with no control characters in any
// field, and sized sanely. Anything else is a script bug or hostile text that
// should be reported, not remembered.
func ValidateEntry(key string, e DeliveredEntry) error {
	switch {
	case key == "" || len(key) > maxDeliveredKey || !plainText(key):
		return fmt.Errorf("key must be 1 to %d printable characters", maxDeliveredKey)
	case e.Ref == "" || len(e.Ref) > maxDeliveredRef || !plainText(e.Ref):
		return fmt.Errorf("ref must be 1 to %d printable characters", maxDeliveredRef)
	case !(e.Status == "sent" || strings.HasPrefix(e.Status, "held: ")):
		return errors.New(`status must be "sent" or "held: <why>"`)
	case len(e.Status) > maxStatus || !plainText(e.Status):
		return fmt.Errorf("status must be at most %d printable characters", maxStatus)
	}
	return nil
}

// Validate says whether the log is one CommitDelivered could have written.
func (l DeliveredLog) Validate(now time.Time) error {
	if len(l) > maxDelivered {
		return fmt.Errorf("%d entries, more than the %d a delivered log holds", len(l), maxDelivered)
	}
	for k, e := range l {
		if err := ValidateEntry(k, e); err != nil {
			return fmt.Errorf("entry %q: %v", safeKey(k), err)
		}
		if e.At.After(now.Add(deliveredSkew)) {
			return fmt.Errorf("entry %q is dated %s, in the future", safeKey(k), e.At.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// safeKey is a key fit to put in an error message.
func safeKey(k string) string {
	if len(k) > 40 {
		k = k[:40] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, k)
}

func deliveredOpts(l *DeliveredLog, now func() time.Time) statefile.Options {
	return statefile.Options{MaxBytes: maxDeliveredBytes, Validate: func() error { return l.Validate(now()) }}
}

// maxDeliveredBytes is far above maxDelivered entries' worth, so the entry count
// is the limit and the byte cap is only a backstop.
const maxDeliveredBytes = 32 << 20

// Normalize drops the entries ValidateEntry refuses and pulls a delivery dated
// ahead of the clock back to now, and says what it did. After it, Validate
// passes. A dropped entry means the application is reported again next run,
// which is the safe direction.
func (l DeliveredLog) Normalize(now time.Time) []string {
	dropped, clamped := 0, 0
	for k, e := range l {
		if err := ValidateEntry(k, e); err != nil {
			delete(l, k)
			dropped++
			continue
		}
		if e.At.After(now.Add(deliveredSkew)) {
			e.At = now
			l[k] = e
			clamped++
		}
	}
	var notes []string
	if dropped > 0 {
		notes = append(notes, fmt.Sprintf("dropped %d entries that were not valid deliveries", dropped))
	}
	if clamped > 0 {
		notes = append(notes, fmt.Sprintf("pulled %d future delivery times back to now", clamped))
	}
	return notes
}

// CommitDelivered records "key<TAB>ref<TAB>status" lines in the log,
// replacing it atomically. A line it cannot read, or that fails validation, is
// reported and skipped; the rest are recorded.
func CommitDelivered(logPath string, lines io.Reader, now time.Time) (int, []string, error) {
	l, err := loadDelivered(logPath, now)
	if err != nil {
		return 0, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(lines, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	var bad []string
	n := 0
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
			bad = append(bad, fmt.Sprintf("line %d: want key, ref and status separated by tabs", i+1))
			continue
		}
		// Ref and status come from our own runner; text that merely carries a
		// control character or runs long is repaired, not refused, since a refused
		// held scan would be re-reported on every run. The key is an identity and
		// is validated as it is.
		e := DeliveredEntry{Ref: spaceControl(f[1]), At: now.UTC(), Status: spaceControl(f[2])}
		if strings.HasPrefix(e.Status, "held: ") && len(e.Status) > maxStatus {
			e.Status = clipUTF8(e.Status, maxStatus)
		}
		if err := ValidateEntry(f[0], e); err != nil {
			bad = append(bad, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		l[f[0]] = e
		n++
	}
	if err := statefile.Write(logPath, l, deliveredOpts(&l, func() time.Time { return now })); err != nil {
		return 0, bad, err
	}
	return n, bad, nil
}

// RedactReport is the scanner's zipped report made fit to mail: every text
// file in it run through Redact and RedactURL, since it was produced while
// logged in as the scan account and carries that session. A report with a
// single HTML file comes back as that file; one with images or other parts
// comes back re-zipped. An error means nothing should be sent: the archive
// could not be read, or has no HTML in it.
func RedactReport(zipped []byte) (name string, body []byte, err error) {
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		return "", nil, fmt.Errorf("the report is not a readable zip: %w", err)
	}
	type part struct {
		name string
		body []byte
	}
	var parts []part
	var total int64
	htmls := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		clean := path.Clean(strings.ReplaceAll(f.Name, `\`, "/"))
		if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean == ".." {
			return "", nil, fmt.Errorf("the report has an entry outside the archive (%q)", f.Name)
		}
		total += int64(f.UncompressedSize64) // #nosec G115 -- bounded just below
		if total > MaxReportBytes {
			return "", nil, fmt.Errorf("the report unzips to over %d MB", MaxReportBytes>>20)
		}
		rc, err := f.Open()
		if err != nil {
			return "", nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxReportBytes+1))
		_ = rc.Close()
		if err != nil {
			return "", nil, err
		}
		switch strings.ToLower(path.Ext(clean)) {
		case ".html", ".htm":
			htmls++
			b = []byte(RedactURL(Redact(string(b))))
		case ".css", ".js", ".txt", ".xml", ".json", ".csv":
			b = []byte(RedactURL(Redact(string(b))))
		case ".png", ".gif", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf":
		default:
			// Unknown content cannot be checked for a session, so it is
			// left out rather than mailed unchecked.
			continue
		}
		parts = append(parts, part{clean, b})
	}
	if htmls == 0 {
		return "", nil, fmt.Errorf("the report has no HTML file in it")
	}
	if len(parts) == 1 {
		return path.Base(parts[0].name), parts[0].body, nil
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, p := range parts {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: p.name, Method: zip.Deflate})
		if err != nil {
			return "", nil, err
		}
		if _, err := fw.Write(p.body); err != nil {
			return "", nil, err
		}
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	return "report.zip", buf.Bytes(), nil
}

// scanResultsTitle is the owner email's title, and the front of its subject:
// "<ORG> Web Application Scan Results". FLEET_ORG is the organisation plus the
// product ("CR Agent Fleet") and the header band above already says that in
// full, so the title takes the organisation alone.
func scanResultsTitle(org string) string {
	org = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(org), "Agent Fleet"))
	if org == "" {
		return "Web Application Scan Results"
	}
	return org + " Web Application Scan Results"
}

// OwnerMail is one application's covering email.
type OwnerMail struct {
	Subject string
	HTML    string
}

// RenderOwnerMail writes the email that carries the report. attached is the
// attachment's file name, or "" when the report was not attached, with why
// saying so.
//
// It is built from emailkit, like the fleet's other emails - the header band,
// a coloured lead block, the severity tiles, a credit line at the foot - so a
// recipient who has seen the daily or the weekly recognises it. The owners are
// often outside the company, and a bare paragraph from an unknown sender is
// what gets reported as phishing.
func RenderOwnerMail(d Delivery, attached, why string) OwnerMail {
	title := scanResultsTitle(orgName())
	subj := title + ": " + oneLineName(d.App)
	finished := "finished recently"
	banner := oneLineName(d.App)
	if !d.Finished.IsZero() {
		subj += " (" + d.Finished.Local().Format("2 Jan 2006") + ")"
		verb := "finished on "
		if d.LaunchOnly {
			verb = "started on "
		}
		finished = verb + d.Finished.Local().Format("Mon 2 Jan 2006")
		banner += " \u00b7 " + d.Finished.Local().Format("Monday 2 January 2006")
	}
	org := orgName()

	// The lead is red when something is Urgent, amber for Critical, blue for
	// anything lower, green for a clean scan - the colours of the tiles.
	lead := emailkit.Green
	switch {
	case d.NoNotice && !d.OpenFromAPI:
		lead = emailkit.Blue
	case d.Open.Urgent > 0:
		lead = emailkit.Red
	case d.Open.Crit > 0:
		lead = emailkit.Amber
	case d.Open.Total() > 0:
		lead = emailkit.Blue
	case d.Caveat != "":
		// Nothing found, by a scan that may not have tested everything: not
		// the green of a clean result.
		lead = emailkit.Yellow
	}

	var b strings.Builder
	emailkit.Open(&b, subj, org, title, banner)
	at := ""
	if u := strings.TrimSpace(d.URL); u != "" {
		at = fmt.Sprintf(` at <code style="font-family:%s">%s</code>`, emailkit.Mono, e(u))
	}
	emailkit.Lead(&b, lead, fmt.Sprintf(`The scheduled security scan of <b>%s</b>%s %s (%s).`,
		e(d.App), at, e(finished), e(d.AuthLabel)))

	if !d.NoNotice || d.OpenFromAPI {
		more := fmt.Sprintf(`<b>Open findings in the application:</b> %s`, e(ownerCounts(d.Open)))
		if d.NoNotice {
			// Counted from the scanner's open findings: there was no notice
			// to say what this one scan found.
			more += `<br>The scanner sent no summary of this scan, so what this scan alone found is not shown.`
		} else if d.FirstScan {
			more += `<br>This is the first scan of the application, so nothing is compared with an earlier one.`
		} else {
			more += fmt.Sprintf(`<br><b>Found by this scan:</b> %s`, e(ownerCounts(d.ScanCounts)))
		}
		emailkit.Tiles(&b, []emailkit.Tile{
			{Label: "Urgent", N: d.Open.Urgent, Tone: emailkit.Red},
			{Label: "Critical", N: d.Open.Crit, Tone: emailkit.Amber},
			{Label: "Serious", N: d.Open.Serious, Tone: emailkit.Yellow},
			{Label: "Medium", N: d.Open.Medium, Tone: emailkit.Blue},
			{Label: "Minimal", N: d.Open.Minimal, Tone: emailkit.Grey},
		}, more)
	}

	if c := strings.TrimSpace(d.Caveat); c != "" {
		emailkit.Callout(&b, emailkit.Yellow, "<b>The scan may be incomplete.</b> "+e(c)+
			" The findings below are real; there may be others the scan did not reach.")
	}
	if d.AuthLabel == "unauthenticated scan" {
		emailkit.Callout(&b, emailkit.Yellow,
			`The scan did not log in, so it covers only the parts of the application that need no login.`)
	}
	if attached != "" {
		emailkit.Callout(&b, emailkit.Grey, fmt.Sprintf(
			`The full report is attached (<code style="font-family:%s">%s</code>): every open finding, where it was found, why it matters and how to fix it, with what the scanner sent to prove it.`,
			emailkit.Mono, e(attached)))
	} else {
		emailkit.Callout(&b, emailkit.Grey, fmt.Sprintf(
			`The scanner's report is not attached: %s. The security team will send it another way.`, e(why)))
	}
	emailkit.Note(&b, `This describes unfixed weaknesses in the application. Please keep it to the people working on it and do not forward it further. Cookie values, session identifiers, tokens and login headers have been removed from the report. Questions, or to change who receives this: reply to this email.`)
	emailkit.Foot(&b, creditHTML(org))
	return OwnerMail{Subject: subj, HTML: b.String()}
}

// creditHTML is the foot of an AppSec email: the configured attribution when
// there is one, otherwise the plain line this lane has always carried.
func creditHTML(org string) string {
	return emailkit.Credit(org, "cti-appscan",
		fmt.Sprintf("Generated by the %s AppSec lane.", org))
}

func ownerCounts(c Counts) string {
	if c.Total() == 0 {
		return "none"
	}
	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{{c.Urgent, "Urgent"}, {c.Crit, "Critical"}, {c.Serious, "Serious"}, {c.Medium, "Medium"}, {c.Minimal, "Minimal"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.name))
		}
	}
	return strings.Join(parts, ", ")
}

func oneLineName(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

// WriteOwnerFile writes one of the owners lane's files (0600) into dir.
func WriteOwnerFile(dir, name string, b []byte) error {
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("%q is not a plain file name", name)
	}
	return writeNew(filepath.Join(dir, name), b)
}

// spaceControl replaces control characters with a space.
func spaceControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// clipUTF8 cuts s to at most n bytes without splitting a character.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
