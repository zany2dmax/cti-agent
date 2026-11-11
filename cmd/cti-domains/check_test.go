package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/domains"
)

type failingRegistrar struct{}

func (failingRegistrar) Name() string { return "godaddy" }
func (failingRegistrar) Domains(context.Context) ([]domains.Registration, error) {
	return nil, errors.New("401 unauthorized")
}

// runCheck runs `cti-domains --check` and returns its exit code and stderr.
func runCheck(t *testing.T, inventory string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	flag.CommandLine = flag.NewFlagSet("cti-domains", flag.ContinueOnError)
	os.Args = []string{"cti-domains", "--check", "--inventory", inventory}
	code := run()
	os.Stderr = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return code, string(out)
}

// --check is run by the heartbeat: it must answer without probing a domain,
// print counts and never a domain name, and fail when Tuesday's run would.
func TestCheck(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(inv, []byte("secret-brand.example send\nother.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_ENV", filepath.Join(dir, "absent.env"))
	t.Setenv("DOMAINS_MAIL_GATEWAY", "")
	t.Setenv("GODADDY_PAT", "test-pat")
	oldReg, oldRes := registrarFor, resolver
	t.Cleanup(func() {
		registrarFor, resolver = oldReg, oldRes
		flag.CommandLine = flag.NewFlagSet("cti-domains", flag.ExitOnError)
	})
	registrarFor = func(string) domains.Registrar {
		return fakeRegistrar{regs: []domains.Registration{{Domain: "secret-brand.example"}}}
	}
	resolver = nil // a probe would panic on the nil resolver; --check must not probe

	code, out := runCheck(t, inv)
	if code != exitOK || !strings.Contains(out, "2 domain(s)") || !strings.Contains(out, "1 domain(s) in the account") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "secret-brand") || strings.Contains(out, "other.example") {
		t.Errorf("--check printed a domain name:\n%s", out)
	}

	registrarFor = func(string) domains.Registrar { return failingRegistrar{} }
	if code, out := runCheck(t, inv); code != exitErr || !strings.Contains(out, "401") {
		t.Errorf("a rejected token passed: exit %d\n%s", code, out)
	}

	t.Setenv("GODADDY_PAT", "")
	if code, _ := runCheck(t, inv); code != exitErr {
		t.Error("no GoDaddy token passed the check")
	}

	t.Setenv("GODADDY_PAT", "test-pat")
	registrarFor = func(string) domains.Registrar { return fakeRegistrar{} }
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCheck(t, empty); code != exitErr {
		t.Error("an empty inventory passed the check")
	}
	if code, _ := runCheck(t, filepath.Join(dir, "missing.txt")); code != exitErr {
		t.Error("a missing inventory passed the check")
	}

	t.Setenv("DOMAINS_MAIL_GATEWAY", "pod")
	t.Setenv("POD_CLUSTER_ID", "")
	if code, _ := runCheck(t, inv); code != exitErr {
		t.Error("the pod gateway with no credentials passed the check")
	}
}
