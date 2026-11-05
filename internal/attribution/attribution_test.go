package attribution

import (
	"strings"
	"testing"
)

func TestNothingConfiguredRendersNothing(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "")
	t.Setenv("FLEET_REPO_URL", "")
	a := Load("CR", "test")
	if !a.Empty() || a.HTML("#000") != "" || a.Text() != "" {
		t.Errorf("a fresh install must advertise nobody: %+v", a)
	}
}

func TestTheConfiguredLineIsUsedAndEscaped(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", `Sent by the CR agent fleet <b>&</b>`)
	t.Setenv("FLEET_REPO_URL", "")
	a := Load("CR", "test")
	if a.Line != `Sent by the CR agent fleet <b>&</b>` {
		t.Errorf("Line = %q", a.Line)
	}
	h := a.HTML("#2c5282")
	if strings.Contains(h, "<b>") || !strings.Contains(h, "&lt;b&gt;") {
		t.Errorf("not escaped: %s", h)
	}
	if strings.Contains(h, "<a ") {
		t.Errorf("no URL, so no link: %s", h)
	}
}

func TestAURLAloneGivesTheDefaultWordingAndALink(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "")
	t.Setenv("FLEET_REPO_URL", "https://example.test/fleet")
	a := Load("CR", "test")
	if !strings.Contains(a.Line, "CR Claude Code Agent Fleet") || a.URL != "https://example.test/fleet" {
		t.Errorf("%+v", a)
	}
	if h := a.HTML("#2c5282"); !strings.Contains(h, `href="https://example.test/fleet"`) {
		t.Errorf("no link: %s", h)
	}
	if !strings.Contains(a.Text(), "\nhttps://example.test/fleet") {
		t.Errorf("text part lacks the URL on its own line: %q", a.Text())
	}
}

func TestOnlyHTTPLinksAreRendered(t *testing.T) {
	t.Setenv("FLEET_ATTRIBUTION", "From the fleet")
	for _, bad := range []string{"javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "not a url"} {
		t.Setenv("FLEET_REPO_URL", bad)
		if a := Load("CR", "test"); a.URL != "" || strings.Contains(a.HTML("#000"), "href") {
			t.Errorf("%q was rendered as a link: %+v", bad, a)
		}
	}
}
