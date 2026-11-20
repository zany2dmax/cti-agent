package triage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClaude writes a script that records its arguments and stdin, then
// prints reply.
func fakeClaude(t *testing.T, reply string, sleep string) (bin, argsFile, stdinFile string) {
	t.Helper()
	d := t.TempDir()
	argsFile, stdinFile = filepath.Join(d, "args"), filepath.Join(d, "stdin")
	bin = filepath.Join(d, "claude")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\ncat > " + stdinFile + "\n"
	if sleep != "" {
		script += "sleep " + sleep + "\n"
	}
	script += "cat <<'JSON'\n" + reply + "\nJSON\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test script
		t.Fatal(err)
	}
	return
}

func TestTheModelRunsWithNoToolsAndTheInputOnStdin(t *testing.T) {
	bin, argsFile, stdinFile := fakeClaude(t, `{"is_error":false,"result":"ANSWER","total_cost_usd":0.0123,"usage":{"input_tokens":3800,"output_tokens":400}}`, "")
	m := ModelCall{Bin: bin, Model: "test-model", Instructions: "SYSTEM"}
	out, u, err := m.Run(context.Background(), "ADVISORY")
	if err != nil || out != "ANSWER" {
		t.Fatalf("out %q err %v", out, err)
	}
	if u.InputTokens != 3800 || u.OutputTokens != 400 || u.CostUSD != 0.0123 {
		t.Errorf("usage = %+v", u)
	}
	args, _ := os.ReadFile(argsFile)
	a := string(args)
	for _, want := range []string{"-p\n", "--model=test-model\n", "--tools\n\n", "--strict-mcp-config\n", "--no-session-persistence\n", "--setting-sources\nproject\n", "--system-prompt=SYSTEM\n"} {
		if !strings.Contains(a, want) {
			t.Errorf("args missing %q:\n%s", want, a)
		}
	}
	if in, _ := os.ReadFile(stdinFile); string(in) != "ADVISORY" {
		t.Errorf("stdin = %q", in)
	}
}

func TestAnErrorAnswerIsAnErrorButItsCostIsKept(t *testing.T) {
	bin, _, _ := fakeClaude(t, `{"is_error":true,"result":"overloaded","total_cost_usd":0.001,"usage":{"input_tokens":10}}`, "")
	_, u, err := ModelCall{Bin: bin, Model: "m", Instructions: "S"}.Run(context.Background(), "x")
	if err == nil || u.InputTokens != 10 {
		t.Fatalf("err %v usage %+v", err, u)
	}
}

func TestTheModelIsGivenUpOn(t *testing.T) {
	bin, _, _ := fakeClaude(t, `{"result":"late"}`, "5")
	_, _, err := ModelCall{Bin: bin, Model: "m", Instructions: "S", Timeout: 200 * time.Millisecond}.Run(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("err = %v", err)
	}
}

func TestNoModelNoCall(t *testing.T) {
	if _, _, err := (ModelCall{Bin: "/nonexistent", Instructions: "S"}).Run(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "TRIAGE_MODEL") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := (ModelCall{Bin: "/nonexistent", Model: "m", Instructions: "S", MaxInput: 3}).Run(context.Background(), "toolong"); err == nil {
		t.Fatal("an oversized input was sent")
	}
}

func TestTheChildGetsNoFleetSecretsAndAnEmptyHome(t *testing.T) {
	env := childEnv([]string{"PATH=/bin", "FALCON_CLIENT_SECRET=x", "GRAPH_CLIENT_SECRET=y", "HOME=/var/lib/cti-agent",
		"ANTHROPIC_API_KEY=k", "CLAUDE_CONFIG_DIR=/elsewhere"}, "/tmp/empty")
	got := strings.Join(env, " ")
	for _, bad := range []string{"FALCON_CLIENT_SECRET", "GRAPH_CLIENT_SECRET", "/var/lib/cti-agent", "CLAUDE_CONFIG_DIR"} {
		if strings.Contains(got, bad) {
			t.Errorf("child env has %s: %s", bad, got)
		}
	}
	for _, want := range []string{"PATH=/bin", "HOME=/tmp/empty", "ANTHROPIC_API_KEY=k"} {
		if !strings.Contains(got, want) {
			t.Errorf("child env lacks %s: %s", want, got)
		}
	}
}

func TestHugeOutputIsCapped(t *testing.T) {
	var b bytes.Buffer
	c := &capped{b: &b, max: 10}
	n, err := c.Write([]byte("0123456789abcdef"))
	if err != nil || n != 16 || b.String() != "0123456789" {
		t.Fatalf("n %d err %v buf %q", n, err, b.String())
	}
}

// Whatever builds the input, what reaches the model has had tax ids, bank
// numbers and card numbers removed: the one egress point is the one place
// redaction is applied.
func TestTheModelNeverReceivesTaxIdsOrBankNumbers(t *testing.T) {
	bin, _, stdinFile := fakeClaude(t, `{"is_error":false,"result":"ok","total_cost_usd":0,"usage":{}}`, "")
	m := ModelCall{Bin: bin, Model: "test-model", Instructions: "SYSTEM"}
	in := "CVE-2026-1234 is exploited.\nOur EIN 12-3456789; card 4111 1111 1111 1111; IBAN GB82 WEST 1234 5698 7654 32.\n"
	if _, _, err := m.Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(stdinFile)
	for _, leak := range []string{"12-3456789", "4111 1111 1111 1111", "GB82 WEST"} {
		if strings.Contains(string(got), leak) {
			t.Errorf("%q reached the model:\n%s", leak, got)
		}
	}
	if !strings.Contains(string(got), "CVE-2026-1234") {
		t.Errorf("redaction removed the advisory's own content:\n%s", got)
	}
}
