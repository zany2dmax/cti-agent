package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/falcon"
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

func TestModesAreExclusiveAndFindOptionsNeedFindApp(t *testing.T) {
	for _, args := range [][]string{
		{"--check", "--find-app", "chrome"},
		{"--check", "--new-apps", "7"},
		{"--vendor", "Google", "--check"},
		{"--exact", "--new-apps", "7"},
		{"--new-apps", "-1"},
		{"--new-apps", "91"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestTopListsTheLargestFirstAndCountsTheRest(t *testing.T) {
	got := top(map[string]int{"a": 1, "b": 5, "c": 3, "d": 3}, 2)
	if got != "b (5), c (3), +2 more" {
		t.Fatalf("top = %q", got)
	}
}

func TestAHostileAppNameCannotForgeALine(t *testing.T) {
	var b bytes.Buffer
	printApp(&b, falcon.AppSummary{
		Vendor: "Evil\x1b[2J", Name: "x\nnew to the estate: 0",
		Hosts: 1, Versions: map[string]int{"1\r\nforged": 1}, Platforms: map[string]int{"Windows": 1},
	}, "")
	out := b.String()
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\r") || strings.Count(out, "\n") != 3 {
		t.Fatalf("output = %q", out)
	}
}

func TestHostFactsArePrintedOnlyWhenFalconKnowsThem(t *testing.T) {
	var b bytes.Buffer
	printApp(&b, falcon.AppSummary{
		Vendor: "Kaseya", Name: "RMM Agent.app", SoftwareType: "application", Hosts: 1, Suspicious: 1,
		Versions: map[string]int{"4.4": 1}, Platforms: map[string]int{"Mac": 1},
		HostTypes: map[string]int{"Workstation": 1}, Exposure: map[string]int{"unknown": 1},
	}, "")
	out := b.String()
	if !strings.Contains(out, "SUSPICIOUS: Falcon flags it on 1 host(s)") || !strings.Contains(out, "host type: Workstation (1)") {
		t.Fatalf("out = %q", out)
	}
	if strings.Contains(out, "exposure") || strings.Contains(out, "[application]") {
		t.Fatalf("printed an unknown line or the default type: %q", out)
	}
}
