package fleetenv

// SECRETS AS SYSTEMD CREDENTIALS (step 2 of splitting fleet.env, RUNBOOK 11n)
//
// A secret used to reach every program as an environment variable, because
// every unit loads all of fleet.env. Now each unit imports only the secrets
// its programs read (ImportCredential=, from /etc/credstore.encrypted), and
// systemd decrypts them into a private in-memory folder named by
// $CREDENTIALS_DIRECTORY, one file per secret, which is removed when the run
// ends. A file is not inherited by child processes the way an environment
// variable is.
//
// Secret reads the file when systemd provided one and falls back to the
// environment otherwise, so the move happens one secret at a time with
// nothing breaking: before a secret is encrypted, it still comes from
// fleet.env; after, from its credential. Load (fleetenv.go) also refuses to
// copy a secret from fleet.env into the environment when its credential is
// there, so the environment copy that the runners drop does not come back.

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var credName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

// maxSecret caps a credential read: a secret is a token or a password, never
// a file's worth.
const maxSecret = 64 << 10

// credentialFile is the path of name's credential, or "" when systemd gave
// this process none.
func credentialFile(name string) string {
	dir := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if dir == "" || !credName.MatchString(name) {
		return ""
	}
	p := filepath.Join(dir, name)
	// #nosec G703 -- dir is the folder systemd creates for this unit alone,
	// and name passed credName above (letters, digits, underscore; no
	// separator), so p cannot leave it. Lstat: a symlink is not a credential.
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return p
}

// HasCredential reports whether systemd provided name as a credential.
func HasCredential(name string) bool { return credentialFile(name) != "" }

// Secret returns a secret's value: from its systemd credential when there is
// one, else from the environment (fleet.env, during the move). A trailing
// newline, as `echo ... | systemd-creds encrypt` leaves, is removed.
func Secret(name string) string {
	if p := credentialFile(name); p != "" {
		// #nosec G304 -- p is $CREDENTIALS_DIRECTORY/NAME, a folder systemd
		// creates for this unit alone, and NAME passed credName above.
		f, err := os.Open(p)
		if err == nil {
			defer func() { _ = f.Close() }()
			b, rerr := io.ReadAll(io.LimitReader(f, maxSecret))
			if rerr == nil {
				return strings.TrimRight(string(b), "\r\n")
			}
		}
	}
	return os.Getenv(name)
}
