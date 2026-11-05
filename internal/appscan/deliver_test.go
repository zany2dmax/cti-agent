package appscan

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func deliverOwners(t *testing.T) Owners {
	t.Helper()
	o, _, err := ParseOwners(strings.NewReader(`
id:101 | lead@example.com | watchers=qa@example.com
Name Only App | two@example.com
`))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestBuildDeliveriesHoldsWhatWouldMislead(t *testing.T) {
	fin := time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC)
	ok := Auth{Record: "login", Status: "Successful"}
	scans := []ScanResult{
		{App: "Good App", AppID: "101", Reference: "was/1.1", Complete: true, Auth: ok, Finished: fin},
		{App: "Name Only App", AppID: "102", Reference: "was/1.2", Complete: true, Finished: fin},
		{App: "Unowned", AppID: "103", Reference: "was/1.3", Complete: true, Finished: fin},
		{App: "Cut Short", AppID: "101", Reference: "was/1.4", Complete: false, Status: "Time Limit Reached"},
		{App: "Login Broke", AppID: "104", Reference: "was/1.5", Complete: true, Auth: Auth{Record: "login", Status: "Failed"}},
		{App: "Dark", AppID: "105", Reference: "was/1.6", Complete: true, HostsScanned: 1},
		{App: "Email Only", Reference: "was/1.7", Complete: true},
		{App: "Sent Already", AppID: "106", Reference: "was/1.8", Complete: true},
		{App: "From The List", AppID: "101", Reference: "was/1.9", Complete: true, NoNotification: true, Started: fin},
	}
	done := DeliveredLog{"id:106": {Ref: "was/1.8"}}
	f := BuildDeliveries(scans, deliverOwners(t), done, fin)
	got := map[string]Delivery{}
	for _, d := range f.Deliveries {
		got[d.App] = d
	}
	if _, ok := got["Sent Already"]; ok {
		t.Error("a scan in the delivered log was planned again")
	}
	for app, want := range map[string]string{
		"Good App": "", "Name Only App": "", "Unowned": "no owner",
		"Cut Short": "did not finish", "Login Broke": "login failed", "Dark": "no host answered",
		"Email Only": "no web app id",
	} {
		d, ok := got[app]
		if !ok {
			t.Errorf("%s: not planned", app)
			continue
		}
		if (want == "") != (d.Hold == "") || !strings.Contains(d.Hold, want) {
			t.Errorf("%s: hold %q, want %q", app, d.Hold, want)
		}
	}
	if !got["Email Only"].Retry || got["Cut Short"].Retry {
		t.Error("only a hold that may clear by itself is retried")
	}
	if d := got["From The List"]; !d.LaunchOnly || !d.Finished.Equal(fin) {
		t.Errorf("a scan known only from the list has no date: %+v", d)
	}
	if got["Good App"].AuthLabel != "authenticated scan" {
		t.Errorf("auth label %q", got["Good App"].AuthLabel)
	}
}

func TestCommitDelivered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sent.json")
	now := time.Date(2026, 11, 3, 7, 15, 0, 0, time.UTC)
	n, bad, err := CommitDelivered(p, strings.NewReader("id:1\twas/1.1\tsent\nbroken line\nid:2\twas/2.1\theld: x\n"), now)
	if err != nil || n != 2 || len(bad) != 1 {
		t.Fatalf("n %d bad %v err %v", n, bad, err)
	}
	if _, _, err := CommitDelivered(p, strings.NewReader("id:1\twas/1.2\tsent\n"), now); err != nil {
		t.Fatal(err)
	}
	l, err := LoadDeliveredLog(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l["id:1"].Ref != "was/1.2" || l["id:2"].Status != "held: x" {
		t.Errorf("log %+v", l)
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const reportWithSession = `<html><body><pre>GET /account?sid=abc123 HTTP/1.1
Cookie: SESSION=live-session-value
Authorization: Bearer live-token
</pre><p>Set-Cookie: other=also-live</p></body></html>`

func TestRedactReportSingleHTML(t *testing.T) {
	name, body, err := RedactReport(zipOf(t, map[string]string{"report.html": reportWithSession}))
	if err != nil {
		t.Fatal(err)
	}
	if name != "report.html" {
		t.Errorf("name %q", name)
	}
	for _, leak := range []string{"live-session-value", "live-token", "also-live", "abc123"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("%s survived redaction:\n%s", leak, body)
		}
	}
}

func TestRedactReportRezipsAndDropsUnknown(t *testing.T) {
	name, body, err := RedactReport(zipOf(t, map[string]string{
		"report.html": reportWithSession, "img/chart.png": "\x89PNG", "evidence.bin": "Cookie: x=1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if name != "report.zip" || !IsZip(body) {
		t.Fatalf("name %q zip %v", name, IsZip(body))
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "report.html,img/chart.png" && strings.Join(names, ",") != "img/chart.png,report.html" {
		t.Errorf("entries %v - an unknown file must be left out", names)
	}
}

func TestRedactReportRefuses(t *testing.T) {
	for name, z := range map[string][]byte{
		"not a zip": []byte("<html></html>"),
		"no html":   zipOf(t, map[string]string{"a.png": "x"}),
		"zip slip":  zipOf(t, map[string]string{"../evil.html": "x"}),
		"absolute":  zipOf(t, map[string]string{"/etc/evil.html": "x"}),
	} {
		if _, _, err := RedactReport(z); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenderOwnerMail(t *testing.T) {
	d := Delivery{App: `<script>Shop</script>`, Finished: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
		AuthLabel: "unauthenticated scan", Active: Counts{Urgent: 2, Medium: 1}, ScanCounts: Counts{Crit: 1}}
	m := RenderOwnerMail(d, "shop-scan-report-2026-11-02.html", "")
	if strings.Contains(m.HTML, "<script>") {
		t.Error("application name not escaped")
	}
	for _, want := range []string{"2 Urgent, 1 Medium", "1 Critical", "need no login", "shop-scan-report-2026-11-02.html", "do not forward"} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.HasPrefix(m.Subject, "Web application scan results: <script>Shop</script>") {
		t.Errorf("subject %q", m.Subject)
	}
	m = RenderOwnerMail(Delivery{App: "Listed", NoNotice: true, LaunchOnly: true,
		Finished: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}, "r.html", "")
	if !strings.Contains(m.HTML, "started on") || !strings.Contains(m.Subject, "2026") {
		t.Errorf("launch-only date: %q\n%s", m.Subject, m.HTML)
	}
	m = RenderOwnerMail(Delivery{App: "Big", NoNotice: true}, "", "it is 4.1 MB, over the 3 MB email limit")
	if strings.Contains(m.Subject, "0001") || strings.Contains(m.HTML, "0001") || !strings.Contains(m.HTML, "finished recently") {
		t.Errorf("zero date rendered: %q\n%s", m.Subject, m.HTML)
	}
	if !strings.Contains(m.HTML, "not attached: it is 4.1 MB") || strings.Contains(m.HTML, "Open findings") {
		t.Errorf("too-large mail:\n%s", m.HTML)
	}
}

func TestTheOwnerMailLooksLikeTheFleetsOtherEmails(t *testing.T) {
	t.Setenv("FLEET_ORG", "CR")
	t.Setenv("FLEET_ATTRIBUTION", "")
	t.Setenv("FLEET_REPO_URL", "")
	d := Delivery{App: "Shop", Finished: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
		AuthLabel: "authenticated scan", Active: Counts{Urgent: 2, Medium: 1}, ScanCounts: Counts{Crit: 1}}
	h := RenderOwnerMail(d, "r.html", "").HTML
	for _, want := range []string{
		"background:#12203a", // the navy header band
		">CR</div>",          // the org label in it
		"Web application scan results",
		"max-width:640px", "background:#eef1f5", // the same card on the same page
		"border-left:4px solid #b3001b",                      // red lead: something is Urgent
		"URGENT", "CRITICAL", "SERIOUS", "MEDIUM", "MINIMAL", // the severity tiles
		"Generated by the CR Agent Fleet AppSec lane.", // the fallback credit
	} {
		if !strings.Contains(h, want) {
			t.Errorf("owner mail lacks %q", want)
		}
	}
	// Lead colour follows the worst band.
	d.Active = Counts{Crit: 1}
	if h := RenderOwnerMail(d, "r.html", "").HTML; !strings.Contains(h, "border-left:4px solid #b25000") {
		t.Error("Critical should lead amber")
	}
	d.Active = Counts{}
	if h := RenderOwnerMail(d, "r.html", "").HTML; !strings.Contains(h, "border-left:4px solid #2f855a") {
		t.Error("a clean scan should lead green")
	}
}

func TestTheOwnerMailCarriesTheFleetAttribution(t *testing.T) {
	t.Setenv("FLEET_ORG", "CR")
	t.Setenv("FLEET_ATTRIBUTION", "Sent by the CR Claude Code agent fleet <3")
	t.Setenv("FLEET_REPO_URL", "")
	h := RenderOwnerMail(Delivery{App: "Shop", NoNotice: true}, "r.html", "").HTML
	if !strings.Contains(h, "Sent by the CR Claude Code agent fleet &lt;3") {
		t.Errorf("attribution missing or unescaped:\n%s", h)
	}
	if strings.Contains(h, "Generated by the CR Agent Fleet AppSec lane.") {
		t.Error("the fallback line must give way to FLEET_ATTRIBUTION")
	}

	t.Setenv("FLEET_REPO_URL", "https://example.test/fleet")
	if h := RenderOwnerMail(Delivery{App: "Shop", NoNotice: true}, "r.html", "").HTML; !strings.Contains(h, `href="https://example.test/fleet"`) {
		t.Error("a configured FLEET_REPO_URL should link the credit")
	}
}
