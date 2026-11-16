package mailer

import (
	"strings"
	"testing"
)

func TestAPageWithoutTheCreditGetsItBeforeTheBodyCloses(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "Example credit & co")
	got, added := WithAttribution("<html><body>hi</BODY></html>")
	if !added {
		t.Fatal("no credit line was added")
	}
	want := `hi<div style="font:400 11px/1.6 Arial,sans-serif;color:#6b7280;padding:8px 20px 14px 20px">Example credit &amp; co</div></BODY>`
	if !strings.Contains(got, want) {
		t.Fatalf("credit not placed before </body>:\n%s", got)
	}
}

func TestAPageThatCarriesTheCreditIsLeftAlone(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "Ann's fleet")
	for _, body := range []string{
		"<body>Ann's fleet</body>",
		"<body>Ann&#39;s fleet</body>",
		"<body>Ann&#x27;s fleet</body>",
	} {
		if got, added := WithAttribution(body); added || got != body {
			t.Errorf("%q was changed to %q", body, got)
		}
	}
}

func TestNoAttributionConfiguredAddsNothing(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "  ")
	if got, added := WithAttribution("<body>x</body>"); added || got != "<body>x</body>" {
		t.Fatalf("added %q with no attribution set", got)
	}
}
