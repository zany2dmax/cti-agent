package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWithoutCheckItPrintsUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--json"}, {"--check", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
		if !strings.Contains(errb.String(), "usage: cti-falcon --check") {
			t.Errorf("%v: no usage line: %q", args, errb.String())
		}
	}
}

func TestMissingSettingsAreNamedAndTheSecretIsNot(t *testing.T) {
	t.Setenv("FLEET_ENV", "/nonexistent/fleet.env")
	t.Setenv("FALCON_BASE_URL", "https://api.us-2.crowdstrike.com")
	t.Setenv("FALCON_CLIENT_ID", "")
	t.Setenv("FALCON_CLIENT_SECRET", "do-not-print-me")
	var out, errb bytes.Buffer
	if code := run([]string{"--check"}, &out, &errb); code != exitErr {
		t.Fatalf("exit %d, want %d", code, exitErr)
	}
	all := out.String() + errb.String()
	if !strings.Contains(all, "FALCON_CLIENT_ID") {
		t.Fatalf("does not name the missing setting: %q", all)
	}
	if strings.Contains(all, "do-not-print-me") {
		t.Fatal("printed the secret")
	}
}

func TestALookAlikeHostIsRefusedBeforeAnyRequest(t *testing.T) {
	t.Setenv("FLEET_ENV", "/nonexistent/fleet.env")
	t.Setenv("FALCON_BASE_URL", "https://api.us-2.crowdstrike.com.evil.example")
	t.Setenv("FALCON_CLIENT_ID", "id")
	t.Setenv("FALCON_CLIENT_SECRET", "x")
	var out, errb bytes.Buffer
	if code := run([]string{"--check"}, &out, &errb); code != exitErr {
		t.Fatalf("exit %d, want %d", code, exitErr)
	}
	if !strings.Contains(errb.String(), "not a CrowdStrike API host") {
		t.Fatalf("stderr = %q", errb.String())
	}
}
