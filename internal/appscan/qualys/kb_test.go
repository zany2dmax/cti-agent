package qualys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Shaped like a KnowledgeBase details=All response; texts invented.
const kbDetailXML = `<?xml version="1.0" encoding="UTF-8"?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST>
<VULN><QID>150001</QID><TITLE>Reflected Cross-Site Scripting (XSS) Vulnerabilities</TITLE>
<DIAGNOSIS><![CDATA[<P>The web application reflects user input<BR>without encoding.</P>]]></DIAGNOSIS>
<CONSEQUENCE><![CDATA[An attacker can run script in a victim&apos;s browser.]]></CONSEQUENCE>
<SOLUTION><![CDATA[<P>Encode output for its context:</P><UL><LI>HTML-encode</LI><LI>JS-encode</LI></UL>
See <A HREF="https://owasp.example.org/xss">the cheat sheet</A>. <a href="javascript:alert(1)">bad</a>]]></SOLUTION>
<CVE_LIST><CVE><ID>CVE-2026-0001</ID></CVE></CVE_LIST>
</VULN>
<VULN><QID>150002</QID><TITLE>Empty</TITLE></VULN>
</VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`

func TestRemediesComeFromTheKnowledgeBaseAsPlainText(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.URL.Path != "/api/4.0/fo/knowledge_base/vuln/" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(kbDetailXML))
	}))
	defer srv.Close()
	api := NewAPI(srv.URL, "u", "p")

	got, err := api.Remedies(context.Background(), []string{"150001", "150002", "abc-unique", "150001"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "details=All") || !strings.Contains(gotQuery, "ids=150001%2C150002") {
		t.Errorf("query %s", gotQuery)
	}
	r, ok := got["150001"]
	if !ok {
		t.Fatalf("no remedy: %+v", got)
	}
	if _, ok := got["150002"]; ok {
		t.Error("a QID with no texts must not produce an empty remedy")
	}
	if strings.ContainsAny(r.Solution, "<>") {
		t.Errorf("HTML left in the solution: %q", r.Solution)
	}
	if !strings.Contains(r.Solution, "- HTML-encode") ||
		!strings.Contains(r.Solution, "the cheat sheet (https://owasp.example.org/xss)") {
		t.Errorf("solution lost its list or link: %q", r.Solution)
	}
	if strings.Contains(r.Solution, "javascript:") {
		t.Errorf("a javascript: link survived: %q", r.Solution)
	}
	if !strings.Contains(r.Consequence, "victim's browser") {
		t.Errorf("entities not decoded: %q", r.Consequence)
	}
	if !strings.Contains(r.Diagnosis, "reflects user input\nwithout encoding") {
		t.Errorf("line break lost: %q", r.Diagnosis)
	}
	if len(r.CVEs) != 1 || r.CVEs[0] != "CVE-2026-0001" {
		t.Errorf("CVEs %v", r.CVEs)
	}
}

func TestALongKnowledgeBaseTextIsBounded(t *testing.T) {
	long := strings.Repeat("Apply the vendor patch. ", 1000)
	if got := bound(long); len(got) > maxRemedyField+10 || !strings.HasSuffix(got, "[...]") {
		t.Errorf("len %d, tail %q", len(got), got[len(got)-20:])
	}
}
