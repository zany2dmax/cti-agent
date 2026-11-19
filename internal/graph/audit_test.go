package graph

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

func auditTo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	restore := audit.SetDefault(&audit.Logger{Dir: dir, Lane: "cti-mailer", Actor: "tester", Run: "run-1", Host: "host-a", Pid: 1})
	t.Cleanup(restore)
	return dir
}

func auditText(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	var b strings.Builder
	for _, f := range files {
		d, _ := os.ReadFile(f)
		b.Write(d)
	}
	return b.String()
}

func TestASentMailIsAuditedWithItsRecipientsAndNotItsContent(t *testing.T) {
	dir := auditTo(t)
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	defer srv.Close()
	req := validReq()
	req.CC = []string{"copy@example.com"}
	req.Subject = "SECRET-SUBJECT"
	req.HTML = "<p>SECRET-BODY</p>"
	req.Attachments = []Attachment{{Name: "SECRET-NAME.csv", ContentType: "text/csv", Bytes: []byte("SECRET-CONTENT")}}
	if _, err := c.SendMail(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	got := auditText(t, dir)
	for _, want := range []string{" mail.send ", `target="operator@example.com,copy@example.com"`, `outcome="success"`, "from=security@example.com", "recipients=2", "attachments=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("trail lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "SECRET") {
		t.Errorf("mail content reached the trail:\n%s", got)
	}
}

func TestAFailedSendIsAuditedAsAFailure(t *testing.T) {
	dir := auditTo(t)
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"SERVER-TEXT"}}`))
	})
	defer srv.Close()
	if _, err := c.SendMail(context.Background(), validReq()); err == nil {
		t.Fatal("want an error")
	}
	got := auditText(t, dir)
	if !strings.HasPrefix(got, "<84>") || !strings.Contains(got, `outcome="failure"`) || strings.Contains(got, "SERVER-TEXT") {
		t.Errorf("want a warning-severity failure with no server text:\n%s", got)
	}
}

func TestARefusedMoveIsAuditedToo(t *testing.T) {
	dir := auditTo(t)
	c := New("t", "c", "s")
	c.tokenEndpoint = "http://127.0.0.1:1/token"
	c.graphBase = "http://127.0.0.1:1"
	if _, err := c.MoveMessage(context.Background(), "m@example.com", "AAAA-LONG-OPAQUE-ID-0123456789", Folder("recoverableitemspurges")); err == nil {
		t.Fatal("want a refusal")
	}
	got := auditText(t, dir)
	if !strings.Contains(got, " mail.move ") || !strings.Contains(got, `outcome="failure"`) || !strings.Contains(got, `target="m@example.com"`) {
		t.Errorf("a refused move should leave a trail:\n%s", got)
	}
	if strings.Contains(got, "AAAA-LONG") {
		t.Errorf("the message id should be shortened to its tail:\n%s", got)
	}
}
