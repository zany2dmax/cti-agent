package qualys

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// detectionPage builds one Host List Detection page: each host has QID 100,
// and next, when set, is the WARNING URL of the following page.
func detectionPage(ips []string, next string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>`)
	for _, ip := range ips {
		fmt.Fprintf(&b, `<HOST><IP>%s</IP><DNS>host-%s</DNS><DETECTION_LIST>`+
			`<DETECTION><QID>100</QID><QDS>70</QDS><LAST_FOUND_DATETIME>2026-10-01T00:00:00Z</LAST_FOUND_DATETIME></DETECTION>`+
			`</DETECTION_LIST></HOST>`, ip, ip)
	}
	b.WriteString(`</HOST_LIST>`)
	if next != "" {
		fmt.Fprintf(&b, `<WARNING><CODE>1980</CODE><TEXT>1000 record limit exceeded.</TEXT><URL><![CDATA[%s]]></URL></WARNING>`, next)
	}
	b.WriteString(`</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>`)
	return b.String()
}

// pagedQualys serves page 1 from the detection path and page 2 when id_min=2.
// page2 replaces the second page's handler when set.
func pagedQualys(t *testing.T, page2 http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if u, _, ok := r.BasicAuth(); !ok || u != "u" {
			t.Errorf("page %s sent without credentials", r.URL.RawQuery)
		}
		if r.URL.Query().Get("id_min") == "2" {
			if page2 != nil {
				page2(w, r)
				return
			}
			_, _ = fmt.Fprint(w, detectionPage([]string{"192.0.2.3", "192.0.2.1"}, ""))
			return
		}
		if got := r.URL.Query().Get("truncation_limit"); got != "1000" {
			t.Errorf("truncation_limit = %q, want it set explicitly", got)
		}
		next := srv.URL + "/api/4.0/fo/asset/host/vm/detection/?action=list&id_min=2"
		_, _ = fmt.Fprint(w, detectionPage([]string{"192.0.2.1", "192.0.2.2"}, next))
	}))
	return srv, &calls
}

func TestHostDetectionsFollowsEveryPage(t *testing.T) {
	srv, calls := pagedQualys(t, nil)
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)

	got, err := c.HostDetections(context.Background(), []int{100})
	if err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(calls); n != 2 {
		t.Errorf("made %d requests, want 2 (one per page)", n)
	}
	d := got[100]
	// 192.0.2.1 is on both pages; it is one host.
	if d.HostCount != 3 {
		t.Errorf("HostCount = %d, want 3 across both pages", d.HostCount)
	}
	if d.HostsTruncated {
		t.Error("a complete read was marked truncated")
	}
}

func TestALaterPageFailingMakesTheCountAFloor(t *testing.T) {
	srv, _ := pagedQualys(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)

	got, err := c.HostDetections(context.Background(), []int{100})
	if err != nil {
		t.Fatalf("a later page failing must not lose the first: %v", err)
	}
	d := got[100]
	if d.HostCount != 2 || !d.HostsTruncated {
		t.Errorf("got HostCount=%d truncated=%v, want 2 marked as a floor", d.HostCount, d.HostsTruncated)
	}
}

func TestAGarbledLaterPageMakesTheCountAFloor(t *testing.T) {
	srv, _ := pagedQualys(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html>Service Unavailable")
	})
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)

	got, err := c.HostDetections(context.Background(), []int{100})
	if err != nil {
		t.Fatalf("a garbled later page must not lose the first: %v", err)
	}
	if d := got[100]; d.HostCount != 2 || !d.HostsTruncated {
		t.Errorf("got HostCount=%d truncated=%v, want 2 marked as a floor", d.HostCount, d.HostsTruncated)
	}
}

func TestTheFirstPageFailingIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)
	if _, err := c.HostDetections(context.Background(), []int{100}); err == nil {
		t.Error("a failed first page returned no error")
	}
}

func TestANextPageOnAnotherHostIsNotFollowed(t *testing.T) {
	var foreign int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&foreign, 1)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, detectionPage([]string{"192.0.2.1"}, other.URL+"/?id_min=2"))
	}))
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)

	got, err := c.HostDetections(context.Background(), []int{100})
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&foreign) != 0 {
		t.Error("credentials were sent to a host other than QUALYS_BASE_URL")
	}
	if !got[100].HostsTruncated {
		t.Error("an unfollowed next page must mark the count as a floor")
	}
}

func TestPagingStopsAtTheLimit(t *testing.T) {
	var calls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		next := fmt.Sprintf("%s/api/4.0/fo/asset/host/vm/detection/?id_min=%d", srv.URL, n+1)
		_, _ = fmt.Fprint(w, detectionPage([]string{fmt.Sprintf("192.0.2.%d", n%250+1)}, next))
	}))
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)

	got, err := c.HostDetections(context.Background(), []int{100})
	if err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != maxPages {
		t.Errorf("made %d requests, want the %d-page limit", n, maxPages)
	}
	if !got[100].HostsTruncated {
		t.Error("hitting the page limit must mark the count as a floor")
	}
}

func TestKBPagesAreMerged(t *testing.T) {
	page := func(qid int, cve string) string {
		return fmt.Sprintf(`<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST><VULN><QID>%d</QID>`+
			`<CVE_LIST><CVE><ID>%s</ID></CVE></CVE_LIST></VULN></VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`, qid, cve)
	}
	got, err := parseKB([]byte(page(1, "CVE-2026-1")), []byte(page(2, "CVE-2026-1")), []byte(page(3, "cve-2026-2")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got["CVE-2026-1"]) != 2 || len(got["CVE-2026-2"]) != 1 {
		t.Errorf("merged cache = %v", got)
	}
}

func TestAnIncompleteKBRebuildIsRefused(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id_min") != "" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprintf(w, `<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST><VULN><QID>1</QID>`+
			`<CVE_LIST><CVE><ID>CVE-2026-1</ID></CVE></CVE_LIST></VULN></VULN_LIST>`+
			`<WARNING><CODE>1980</CODE><URL>%s/api/4.0/fo/knowledge_base/vuln/?id_min=2</URL></WARNING>`+
			`</RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`, srv.URL)
	}))
	defer srv.Close()
	c := New(srv.URL, "u", "p", "", time.Hour)
	if _, err := c.BuildKBCache(context.Background()); err == nil {
		t.Error("half a KnowledgeBase was accepted as a rebuild")
	}
}
