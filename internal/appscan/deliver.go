package appscan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
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
	// Hold is why this is not sent; empty means send. Retry says the hold
	// may clear by itself (the API was unreachable), so it is not recorded
	// as done.
	Hold  string `json:"hold,omitempty"`
	Retry bool   `json:"retry,omitempty"`
	// Counts from the notice, for the covering email. Unknown (and not
	// shown) when the scanner sent no notice.
	NoNotice   bool   `json:"noNotice,omitempty"`
	Open       Counts `json:"open"` // New + Reopened + Active (Lifecycle.Open)
	ScanCounts Counts `json:"scanCounts"`
	FirstScan  bool   `json:"firstScan,omitempty"`
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
			Open: s.AppState.Open(), ScanCounts: s.ScanCounts, FirstScan: s.FirstScan}
		switch {
		case !s.Complete && strings.EqualFold(strings.Join(strings.Fields(s.Status), ""), "finished"):
			// The newer notice format, which needs the scan list to confirm
			// it - and the list did not (unreachable, or no matching run).
			// The same test as qualys.BareFinished, which this package cannot
			// import (qualys imports appscan).
			d.Hold = "the notice says Finished, but the Qualys scan list did not confirm the run - not counted as complete"
		case !s.Complete:
			d.Hold = "the scan did not finish (" + orUnknown(s.Status) + ")"
		case s.Auth.Failed():
			d.Hold = "the scan's login failed (" + orUnknown(s.Auth.Status) + ")"
		case s.Unreachable():
			d.Hold = fmt.Sprintf("no host answered (%d scanned, 0 active)", s.HostsScanned)
		case d.AppID == "":
			d.Hold, d.Retry = "no web app id - the scanner's API was not reachable, so no report can be fetched", true
		}
		if d.Hold == "" {
			if _, ok := owners.For(s.AppID, s.App); !ok {
				d.Hold = "no owner in app-owners.txt"
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
	// #nosec G304 -- the runner's own state file
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return DeliveredLog{}, nil
	}
	if err != nil {
		return nil, err
	}
	l := DeliveredLog{}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s is not a delivered log: %w", p, err)
	}
	return l, nil
}

// CommitDelivered records "key<TAB>ref<TAB>status" lines in the log,
// replacing it atomically. A line it cannot read is reported and skipped.
func CommitDelivered(logPath string, lines io.Reader, now time.Time) (int, []string, error) {
	l, err := LoadDeliveredLog(logPath)
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
		l[f[0]] = DeliveredEntry{Ref: f[1], At: now.UTC(), Status: f[2]}
		n++
	}
	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return 0, bad, err
	}
	tmp := logPath + ".tmp"
	if err := writeNew(tmp, append(out, '\n')); err != nil {
		return 0, bad, err
	}
	return n, bad, os.Rename(tmp, logPath)
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
	subj := "Web application scan results: " + oneLineName(d.App)
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
	case d.NoNotice:
		lead = emailkit.Blue
	case d.Open.Urgent > 0:
		lead = emailkit.Red
	case d.Open.Crit > 0:
		lead = emailkit.Amber
	case d.Open.Total() > 0:
		lead = emailkit.Blue
	}

	var b strings.Builder
	emailkit.Open(&b, subj, org, "Web application scan results", banner)
	emailkit.Lead(&b, lead, fmt.Sprintf(`The scheduled security scan of <b>%s</b> %s (%s).`,
		e(d.App), e(finished), e(d.AuthLabel)))

	if !d.NoNotice {
		more := fmt.Sprintf(`<b>Open findings in the application:</b> %s`, e(ownerCounts(d.Open)))
		if d.FirstScan {
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

	if d.AuthLabel == "unauthenticated scan" {
		emailkit.Callout(&b, emailkit.Yellow,
			`The scan did not log in, so it covers only the parts of the application that need no login.`)
	}
	if attached != "" {
		emailkit.Callout(&b, emailkit.Grey, fmt.Sprintf(
			`The scanner's report on the open findings is attached (<code style="font-family:%s">%s</code>), with the request, response and suggested fix for each.`,
			emailkit.Mono, e(attached)))
	} else {
		emailkit.Callout(&b, emailkit.Grey, fmt.Sprintf(
			`The scanner's report is not attached: %s. The security team will send it another way.`, e(why)))
	}
	emailkit.Note(&b, `This describes unfixed weaknesses in the application. Please keep it to the people working on it and do not forward it further. Session cookies and login headers from the scan have been removed from the report. Questions, or to change who receives this: reply to this email.`)
	emailkit.Foot(&b, creditHTML(org))
	return OwnerMail{Subject: subj, HTML: b.String()}
}

// creditHTML is the foot of an AppSec email: the configured attribution when
// there is one, otherwise the plain line this lane has always carried.
func creditHTML(org string) string {
	return emailkit.Credit(org, "cti-appscan",
		fmt.Sprintf("Generated by the %s Agent Fleet AppSec lane.", org))
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
