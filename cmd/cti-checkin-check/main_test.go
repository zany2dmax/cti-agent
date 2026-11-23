package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOneModeAtATime(t *testing.T) {
	for _, args := range [][]string{{}, {"--guard-wired", "s"}, {"--guard", "g"}, {"--steering", "--tripped", "c"},
		{"--tripped", "c", "extra"}, {"--guard-wired", "s", "--guard", "g", "--steering"}, {"--bogus"}} {
		var o, e bytes.Buffer
		if rc := run(args, &o, &e); rc != 2 {
			t.Errorf("%v: exit %d", args, rc)
		}
	}
}

func TestTheModesExitAsTheRunnerExpects(t *testing.T) {
	d := t.TempDir()
	s := filepath.Join(d, "s.json")
	_ = os.WriteFile(s, []byte(`{"disableAllHooks": false, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/g"}]}]}}`), 0o600)
	var o, e bytes.Buffer
	if rc := run([]string{"--guard-wired", s, "--guard", "/g"}, &o, &e); rc != 0 {
		t.Errorf("wired: exit %d", rc)
	}
	if rc := run([]string{"--guard-wired", filepath.Join(d, "none"), "--guard", "/g"}, &o, &e); rc != 1 {
		t.Errorf("missing settings: exit %d", rc)
	}
	c := filepath.Join(d, "c.json")
	_ = os.WriteFile(c, []byte(`{"tripped": ["bash"]}`), 0o600)
	o.Reset()
	if rc := run([]string{"--tripped", c}, &o, &e); rc != 0 || o.String() != "limit reached for bash\n" {
		t.Errorf("tripped: exit %d %q", rc, o.String())
	}
	if rc := run([]string{"--tripped", filepath.Join(d, "none")}, &o, &e); rc != 1 {
		t.Errorf("unreadable counts: exit %d", rc)
	}
	o.Reset()
	if rc := run([]string{"--steering", filepath.Join(d, "none"), s}, &o, &e); rc != 0 || o.String() != s+": hooks is set\n" {
		t.Errorf("steering: exit %d %q", rc, o.String())
	}
}
