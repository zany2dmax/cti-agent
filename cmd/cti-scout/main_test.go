package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/httpx"
	"github.com/zany2dmax/cti-agent/internal/pyjson"
)

func tlsClient(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.Transport = httpx.Guard(c.Transport)
	c.CheckRedirect = httpx.CheckRedirect
	c.Timeout = 10 * time.Second
	return c
}

func TestFetch(t *testing.T) {
	var gotUA, gotAccept string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feed":
			gotUA, gotAccept = r.UserAgent(), r.Header.Get("Accept")
			_, _ = w.Write([]byte("<rss/>"))
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/huge":
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxFeedBytes+1))
		case "/exact":
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxFeedBytes))
		case "/downgrade":
			http.Redirect(w, r, "http://example.com/feed", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := tlsClient(srv)
	var log strings.Builder
	logf := func(format string, a ...any) { log.WriteString(fmt.Sprintf(format, a...) + "\n") }

	if b := fetch(c, "cti-agent-scout/1.0", srv.URL+"/feed", logf); string(b) != "<rss/>" {
		t.Fatalf("fetch = %q, log %s", b, log.String())
	}
	if gotUA != "cti-agent-scout/1.0" || !strings.HasPrefix(gotAccept, "application/rss+xml, ") {
		t.Errorf("sent agent %q, accept %q", gotUA, gotAccept)
	}
	if b := fetch(c, "x", srv.URL+"/exact", logf); len(b) != maxFeedBytes {
		t.Errorf("a feed of exactly the cap is %d bytes", len(b))
	}
	for path, want := range map[string]string{
		"/forbidden": "HTTP Error 403: Forbidden",
		"/huge":      "larger than 10 MB",
		"/downgrade": "refusing a http:// request",
	} {
		log.Reset()
		if b := fetch(c, "x", srv.URL+path, logf); b != nil {
			t.Errorf("%s: fetched %d bytes", path, len(b))
		}
		if !strings.Contains(log.String(), "FEED FAIL "+srv.URL+path+" :: ") || !strings.Contains(log.String(), want) {
			t.Errorf("%s: logged %q, want %q", path, log.String(), want)
		}
	}
	// Refused before any request: plain http (even to a test server), a
	// local file, ftp.
	for _, u := range []string{strings.Replace(srv.URL, "https://", "http://", 1) + "/feed", "file:///etc/passwd", "ftp://example.com/f", "HTTPS-ish"} {
		log.Reset()
		if b := fetch(c, "x", u, logf); b != nil {
			t.Errorf("%s: fetched", u)
		}
		if want := "FEED FAIL " + u + " :: not an https URL (plain http feeds are refused)\n"; log.String() != want {
			t.Errorf("%s: logged %q", u, log.String())
		}
	}
}

func TestUsage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FLEET_HOME", home)
	t.Setenv("FLEET_FEEDS", "")
	d := deps{fetch: func(string, func(string, ...any)) []byte { t.Fatal("fetched"); return nil },
		db: func(string) (store, error) { return nil, nil }, now: time.Now}
	for _, args := range [][]string{{}, {"--days", "x", "--out", "o"}, {"--out", "o", "extra"}, {"--bogus"}} {
		var errb bytes.Buffer
		if rc := run(args, &bytes.Buffer{}, &errb, d); rc != 2 {
			t.Errorf("%q: exit %d", args, rc)
		}
	}
	// No feed list: say where it looked, exit 1. The default is FLEET_HOME's.
	var errb bytes.Buffer
	if rc := run([]string{"--out", filepath.Join(home, "o.json")}, &bytes.Buffer{}, &errb, d); rc != 1 ||
		errb.String() != "[scout] no feed list at "+filepath.Join(home, "lanes", "feeds.txt")+"\n" {
		t.Errorf("exit %d, %q", rc, errb.String())
	}
	t.Setenv("FLEET_FEEDS", filepath.Join(home, "elsewhere.txt"))
	errb.Reset()
	if rc := run([]string{"--out", filepath.Join(home, "o.json")}, &bytes.Buffer{}, &errb, d); rc != 1 || !strings.Contains(errb.String(), "elsewhere.txt") {
		t.Errorf("FLEET_FEEDS ignored: exit %d, %q", rc, errb.String())
	}
}

func TestOutputIsPrivateAndAtomic(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FLEET_HOME", home)
	feeds := filepath.Join(home, "feeds.txt")
	if err := os.WriteFile(feeds, []byte("https://example.com/f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(home, "new", "dir", "scout.json")
	var stdout, errb bytes.Buffer
	rc := run([]string{"--out", out, "--feeds", feeds, "--print-new", "--no-db"}, &stdout, &errb, deps{
		fetch: func(string, func(string, ...any)) []byte {
			return []byte("<rss><channel><item><title>CVE-2026-0001</title></item></channel></rss>")
		},
		db:  func(string) (store, error) { t.Fatal("--no-db opened the database"); return nil, nil },
		now: time.Now,
	})
	if rc != 0 || stdout.String() != "CVE-2026-0001\n" {
		t.Fatalf("exit %d, stdout %q, %s", rc, stdout.String(), errb.String())
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("output is %v, want 0600", st.Mode().Perm())
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".scout-*"))
	if len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestNoDatabaseIsNotAnError(t *testing.T) {
	home := t.TempDir()
	if s, err := openStore(home); s != nil || err != nil {
		t.Fatalf("no memory.db: %v, %v", s, err)
	}
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state", "memory.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_CODE", filepath.Join(home, "nowhere"))
	if s, err := openStore(home); err == nil {
		// Only when no fleet-db sits beside the test binary either.
		if _, ok := s.(fleetDB); !ok || !strings.HasSuffix(s.(fleetDB).path, "fleet-db") {
			t.Errorf("memory.db without fleet-db: %v", s)
		}
	}
}

// TestFleetDB runs the real fleet-db: the two subcommands this lane uses,
// against a scratch database.
func TestFleetDB(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "fleet-kit", "fleet", "bin", "fleet-db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no /usr/bin/python3 for fleet-db")
	}
	home := t.TempDir()
	code := filepath.Join(home, "code")
	if err := os.MkdirAll(filepath.Join(code, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, filepath.Join(code, "bin", "fleet-db")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_HOME", home)
	t.Setenv("FLEET_CODE", code)
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- the repository's own fleet-db.
	if out, err := exec.Command(src, "init").CombinedOutput(); err != nil {
		t.Fatalf("fleet-db init: %v %s", err, out)
	}
	// In a beat fleet-db cleans its output for a model (and needs
	// cti-sanitize to): this lane's calls must not look like a beat's.
	t.Setenv("CHECKIN_BEAT_ID", "beat-1")
	s, err := openStore(home)
	if err != nil || s == nil {
		t.Fatalf("openStore: %v %v", s, err)
	}
	if k, err := s.known(); err != nil || len(k) != 0 {
		t.Fatalf("known on an empty database: %q %v", k, err)
	}
	row := func(cve, feed, title string, published any) any {
		o := pyjson.NewObject()
		o.Set("cve", cve)
		o.Set("feed", feed)
		o.Set("title", title)
		o.Set("link", "")
		o.Set("published", published)
		return o
	}
	if err := s.record([]any{
		row("CVE-2026-0002", "https://a/f", "two\nlines", nil),
		row("CVE-2026-0001", "https://a/f", "Café", "2026-11-22T06:00:00+00:00"),
		row("CVE-2026-0001", "https://a/f", "ignored: same CVE and feed", nil),
		row("CVE-2026-0001", "https://b/f", "a second feed", nil),
	}); err != nil {
		t.Fatal(err)
	}
	if k, err := s.known(); err != nil || strings.Join(k, ",") != "CVE-2026-0001,CVE-2026-0002" {
		t.Fatalf("known = %q %v", k, err)
	}
	// A refused row is an error the lane logs; the others are written.
	if err := s.record([]any{row("CVE-2026-0003", "https://a/f", "x", nil), row("not-a-cve", "https://a/f", "x", nil)}); err == nil {
		t.Error("a refused row was not reported")
	}
	if k, _ := s.known(); len(k) != 3 {
		t.Errorf("known after a partial batch = %q", k)
	}
	if err := s.record(nil); err != nil {
		t.Errorf("an empty record ran fleet-db: %v", err)
	}
}
