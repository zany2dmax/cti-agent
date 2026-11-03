package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func runWith(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	t.Setenv("FLEET_ENV", "/nonexistent/fleet.env")
	for _, k := range []string{"POD_CLUSTER_ID", "POD_API_TOKEN"} {
		t.Setenv(k, env[k])
	}
	now = func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, errb.String()
}

func TestRefusesWithoutSettings(t *testing.T) {
	code, msg := runWith(t, nil)
	if code != exitErr || !strings.Contains(msg, "POD_CLUSTER_ID") {
		t.Fatalf("code=%d msg=%q", code, msg)
	}
}

func TestWindowChecks(t *testing.T) {
	env := map[string]string{"POD_CLUSTER_ID": "example_hosted", "POD_API_TOKEN": "tok-secret"}
	for name, args := range map[string][]string{
		"recent start":   {"--since", "2026-11-03T11:30:00+0000"},
		"end too recent": {"--since", "2026-11-03T09:00:00+0000", "--to", "2026-11-03T11:30:00+0000"},
		"too old":        {"--since", "2026-09-01T09:00:00+0000"},
		"backwards":      {"--since", "2026-11-03T09:00:00+0000", "--to", "2026-11-03T08:00:00+0000"},
		"bad time":       {"--since", "yesterday"},
	} {
		code, msg := runWith(t, env, args...)
		if code != exitErr {
			t.Errorf("%s: code=%d msg=%q", name, code, msg)
		}
		if strings.Contains(msg, "tok-secret") {
			t.Errorf("%s: the token appeared in the output", name)
		}
	}
}
