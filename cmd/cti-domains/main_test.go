package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
)

type fakeRegistrar struct{ regs []domains.Registration }

func (fakeRegistrar) Name() string { return "godaddy" }
func (f fakeRegistrar) Domains(context.Context) ([]domains.Registration, error) {
	return f.regs, nil
}

// emptyDNS answers NXDOMAIN for everything, which is enough to drive the
// entry point end to end without the network.
type emptyDNS struct{}

func nx() error { return &net.DNSError{Err: "no such host", IsNotFound: true} }

func (emptyDNS) LookupHost(context.Context, string) ([]string, error)    { return nil, nx() }
func (emptyDNS) LookupCNAME(_ context.Context, h string) (string, error) { return h + ".", nil }
func (emptyDNS) LookupMX(context.Context, string) ([]*net.MX, error)     { return nil, nx() }
func (emptyDNS) LookupTXT(context.Context, string) ([]string, error)     { return nil, nx() }
func (emptyDNS) LookupNS(context.Context, string) ([]*net.NS, error)     { return nil, nx() }

// TestRunEndToEnd drives run() itself - flags, env, inventory, registrar,
// state - because the unit tests of the parts cannot catch the entry point
// failing to call one of them. That has happened in this repository.
func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(inv, []byte("example.com send\nexample.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GODADDY_PAT", "test-pat")
	t.Setenv("FLEET_ENV", filepath.Join(dir, "absent.env"))
	registrarFor = func(tok string) domains.Registrar {
		if tok != "test-pat" {
			t.Errorf("token = %q", tok)
		}
		return fakeRegistrar{regs: []domains.Registration{
			{Domain: "example.com", Status: "ACTIVE", Expires: time.Now().AddDate(1, 0, 0), AutoRenew: true, Locked: true},
			{Domain: "forgotten.example", Status: "ACTIVE", Locked: true, AutoRenew: true},
		}}
	}
	resolver = emptyDNS{}
	webProber = func(context.Context, string) (domains.Fetch, domains.Fetch, domains.Cert) {
		t.Error("web fetched for a name that does not resolve")
		return domains.Fetch{}, domains.Fetch{}, domains.Cert{}
	}

	state := filepath.Join(dir, "state", "domains-state.json")
	html, txt, subj := filepath.Join(dir, "r.html"), filepath.Join(dir, "r.txt"), filepath.Join(dir, "r.subject")
	os.Args = []string{"cti-domains", "--inventory", inv, "--state", state,
		"--out", html, "--text-out", txt, "--subject-out", subj}
	if code := run(); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	body, _ := os.ReadFile(txt)
	s := string(body)
	for _, want := range []string{
		"forgotten.example",          // in the account, not the inventory
		"not in the godaddy account", // example.net
		"no SPF record",              // sender with nothing
		"First run",                  // no state yet
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q:\n%s", want, s)
		}
	}
	sb, _ := os.ReadFile(subj)
	if !strings.HasPrefix(string(sb), "CTI Fleet Domains ") {
		t.Errorf("subject = %q", sb)
	}
	for _, p := range []string{html, txt, subj, state} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", p, fi.Mode().Perm())
		}
	}
}
