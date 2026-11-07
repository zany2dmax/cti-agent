package cli

import (
	"strings"
	"testing"
)

func TestAModeIsRequired(t *testing.T) {
	_, msg := Resolve("cti-mailbox", false, false, false, false, Words{})
	for _, want := range []string{"cti-mailbox: say how to run it", "--dry-run", "--for-real", "cti-agent cti-mailbox --help"} {
		if !strings.Contains(msg, want) {
			t.Errorf("usage lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "--to-dev") {
		t.Errorf("--to-dev offered to a command that has none:\n%s", msg)
	}
}

func TestToDevIsOfferedOnlyWhereItExists(t *testing.T) {
	_, msg := Resolve("cti-alert", false, false, false, true, Words{})
	if !strings.Contains(msg, "--to-dev") {
		t.Errorf("a command with --to-dev does not offer it:\n%s", msg)
	}
	if _, msg := Resolve("cti-jira", false, false, true, false, Words{}); msg == "" {
		t.Error("--to-dev accepted by a command that has none")
	}
}

func TestLegalCombinations(t *testing.T) {
	cases := []struct {
		dry, real, dev bool
		ok             bool
	}{
		{true, false, false, true},
		{false, true, false, true},
		{false, false, true, true},
		{true, false, true, true}, // rehearse a test send
		{false, false, false, false},
		{true, true, false, false},
		{false, true, true, false},
		{true, true, true, false},
	}
	for _, c := range cases {
		m, msg := Resolve("x", c.dry, c.real, c.dev, true, Words{})
		if (msg == "") != c.ok {
			t.Errorf("dry=%v real=%v dev=%v: ok=%v, message %q", c.dry, c.real, c.dev, !c.ok, msg)
		}
		if c.ok && (m.DryRun != c.dry || m.ForReal != c.real || m.ToDev != c.dev) {
			t.Errorf("mode %+v does not echo the flags", m)
		}
	}
}

func TestPerCommandWordsReplaceTheGenericOnes(t *testing.T) {
	_, msg := Resolve("cti-mailbox", false, false, false, false,
		Words{DryRun: "show the plan and move nothing", ForReal: "move the mail"})
	if !strings.Contains(msg, "show the plan and move nothing") || !strings.Contains(msg, "move the mail") {
		t.Errorf("per-command wording missing:\n%s", msg)
	}
}
