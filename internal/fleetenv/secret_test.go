package fleetenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretPrefersTheCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CLIENT_SECRET"), []byte("from-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("CLIENT_SECRET", "from-env")
	if got := Secret("CLIENT_SECRET"); got != "from-credential" {
		t.Fatalf("Secret = %q", got)
	}
	t.Setenv("JIRA_API_TOKEN", "env-only")
	if got := Secret("JIRA_API_TOKEN"); got != "env-only" {
		t.Fatalf("no credential: Secret = %q, want the environment", got)
	}
}

func TestSecretWithoutSystemdIsTheEnvironment(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("QUALYS_PASSWORD", "pw")
	if got := Secret("QUALYS_PASSWORD"); got != "pw" {
		t.Fatalf("Secret = %q", got)
	}
}

func TestABadNameNeverLeavesTheFolder(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	for _, n := range []string{"../etc/passwd", "lower", "", "A/B"} {
		if HasCredential(n) {
			t.Errorf("HasCredential(%q) = true", n)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "DIRNAME"), 0o700); err != nil {
		t.Fatal(err)
	}
	if HasCredential("DIRNAME") {
		t.Error("a directory counted as a credential")
	}
}

func TestLoadDoesNotPutACredentialSecretBackInTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CLIENT_SECRET"), []byte("cred"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(t.TempDir(), "fleet.env")
	if err := os.WriteFile(env, []byte("CLIENT_SECRET=from-file\nGRAPH_FOLDER=Inbox\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("CLIENT_SECRET", "")
	_ = os.Unsetenv("CLIENT_SECRET")
	t.Setenv("GRAPH_FOLDER", "")
	_ = os.Unsetenv("GRAPH_FOLDER")
	LoadFrom(env)
	if _, set := os.LookupEnv("CLIENT_SECRET"); set {
		t.Fatal("Load copied a credential secret into the environment")
	}
	if os.Getenv("GRAPH_FOLDER") != "Inbox" {
		t.Fatal("Load skipped an ordinary setting")
	}
}

func TestASymlinkIsNotACredential(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "CLIENT_SECRET")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if HasCredential("CLIENT_SECRET") {
		t.Fatal("a symlink counted as a credential")
	}
}
