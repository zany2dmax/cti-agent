package shellgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const errexit = "#!/usr/bin/env bash\nset -euo pipefail\n"

func TestTheExactLineThatKilledAnInstall(t *testing.T) {
	// Verbatim from install-fedora.sh. It ended the script four lines after
	// "daemon-reload" on the first box whose fleet.env had no
	// FLEET_PATCHTUESDAY_TIME, and nothing printed.
	src := errexit + `_pt="$(grep -E '^FLEET_PATCHTUESDAY_TIME=' "$CONF_DIR/fleet.env" 2>/dev/null | tail -1 | cut -d= -f2-)"`
	f := Scan("install-fedora.sh", src)
	if len(f) != 1 {
		t.Fatalf("missed the line that cost us an install: %+v", f)
	}
	if !strings.Contains(f[0].Why, "silently") {
		t.Errorf("the message does not name the consequence: %q", f[0].Why)
	}
}

func TestTheGitGrepCountThatAbortedOnSuccess(t *testing.T) {
	// scrub-history.sh. git grep exits 1 on zero matches, and zero matches is
	// the case the check exists to confirm - so a clean history failed here.
	src := errexit + `    hits=$(git grep -l -E "$pat" $ALL_COMMITS -- 2>/dev/null | wc -l | tr -d ' ')`
	if f := Scan("scrub-history.sh", src); len(f) != 1 {
		t.Fatalf("a `git grep | wc -l` count was not flagged: %+v", f)
	}
}

func TestABareGrepAssignmentIsAlsoFatal(t *testing.T) {
	// No pipeline at all, so pipefail is not even involved: the substitution
	// IS the grep, and its status is the assignment's status.
	src := errexit + `V="$(grep KEY file)"`
	if f := Scan("x.sh", src); len(f) != 1 {
		t.Fatalf("a bare grep assignment was not flagged: %+v", f)
	}
}

func TestTwoStatementsOnOneLineAreBothChecked(t *testing.T) {
	// `local cur; cur="$(...)"`. The leading token is `local`, so a whole-line
	// assignment test sees nothing and waves it through - and this exact line
	// is what made check_path's "KEY is unset" diagnostic unreachable.
	src := errexit + `      local cur; cur="$(grep -E "^$1=" "$CONF_DIR/fleet.env" 2>/dev/null | tail -1)"`
	if f := Scan("install-fedora.sh", src); len(f) != 1 {
		t.Fatalf("a second-statement assignment was not flagged: %+v", f)
	}
}

func TestTheAcceptedFixesPass(t *testing.T) {
	// Each of these is a real rewrite made in this repository. If the gate
	// flags them it is useless, because there would be nothing left to do.
	for _, good := range []string{
		`v="$(sed -n "s/^KEY=//p" "$f" | tail -1)"`,
		`n=$({ git grep -l "$p" || true; } | wc -l)`,
		`reason="$(echo "$out" | { grep -v '^alert$' || true; } | tr '\n' ' ')"`,
		`rows=$(grep -c '^| CVE-' "$RAW" || true)`,
		`if grep -q KEY "$f"; then echo yes; fi`,
		`while read -r l; do :; done < <(grep X f)`,
		`[ -n "$(grep X f)" ] && echo found`,
		`echo "count: $(grep -c X f || echo 0)"`,
	} {
		if f := Scan("x.sh", errexit+good); len(f) != 0 {
			t.Errorf("false positive on a correct line:\n  %s\n  -> %v", good, f)
		}
	}
}

func TestAScriptWithoutSetEIsNotScanned(t *testing.T) {
	// Without `set -e` the same line leaves a variable empty and carries on.
	// That may still be a bug, but it is not THIS bug, and flagging it would
	// bury the findings that end scripts.
	src := "#!/bin/sh\n" + `V="$(grep KEY file | head -1)"`
	if f := Scan("x.sh", src); len(f) != 0 {
		t.Errorf("flagged a script that does not set -e: %+v", f)
	}
}

func TestSetEIsFoundInEveryFormWeWrite(t *testing.T) {
	for _, line := range []string{"set -e", "set -eu", "set -euo pipefail", "  set -eo pipefail"} {
		if !setsErrexit([]string{line}) {
			t.Errorf("setsErrexit missed %q", line)
		}
	}
	for _, line := range []string{"set -u", "set -o pipefail", "set +e", "# set -e"} {
		if setsErrexit([]string{line}) {
			t.Errorf("setsErrexit matched %q, which does not enable errexit", line)
		}
	}
}

func TestACommandNamedLikeAGrepIsNotAGrep(t *testing.T) {
	for _, s := range []string{
		`V="$(echo "$grepped" | tr a b)"`,
		`V="$(/opt/x/my-grep-tool run)"`,
	} {
		if f := Scan("x.sh", errexit+s); len(f) != 0 {
			t.Errorf("false positive on %q: %+v", s, f)
		}
	}
	// ...but a path to a real grep still is one.
	if f := Scan("x.sh", errexit+`V="$(/usr/bin/grep X f)"`); len(f) != 1 {
		t.Errorf("/usr/bin/grep was not recognised: %+v", f)
	}
}

// TestTheFleetsOwnScriptsAreClean is the gate itself. Everything above exists
// so that a failure here can be trusted.
func TestTheFleetsOwnScriptsAreClean(t *testing.T) {
	root := repoRoot(t)
	var all []Finding

	for _, dir := range []string{"fleet-kit", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err //nolint:wrapcheck // walk errors are already contextual
			}
			b, err := os.ReadFile(p) // #nosec G304 -- paths come from WalkDir over the repo
			if err != nil {
				return err //nolint:wrapcheck // same
			}
			if !looksLikeShell(p, string(b)) {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			all = append(all, Scan(rel, string(b))...)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	for _, f := range all {
		t.Errorf("%s", f)
	}
	if len(all) > 0 {
		t.Log("See the package comment for the three ways this has already bitten us.")
	}
}

func looksLikeShell(path, content string) bool {
	if strings.HasSuffix(path, ".sh") {
		return true
	}
	first, _, _ := strings.Cut(content, "\n")
	return strings.HasPrefix(first, "#!") &&
		(strings.Contains(first, "sh") && !strings.Contains(first, "python"))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		d = filepath.Dir(d)
	}
	t.Fatal("could not find the repository root from the test's working directory")
	return ""
}
