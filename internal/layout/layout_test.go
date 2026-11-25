package layout

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The install paths live here and nowhere else in the Go code, so a layout set
// at build time (-X) reaches every binary. A literal elsewhere would keep
// pointing at the FHS default on a relocated box, silently.
func TestNoOtherGoFileNamesAnInstallPath(t *testing.T) {
	paths := regexp.MustCompile(`"[^"]*(/opt/cti-agent|/etc/cti-agent|/var/lib/cti-agent|/var/log/cti-agent)([/"][^"]*)?"|"ctiagent"`)
	root := filepath.Join("..", "..")
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && p != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		if filepath.Base(filepath.Dir(p)) == "layout" && filepath.Base(p) == "layout.go" {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the repository's own Go files
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if paths.MatchString(code) {
				hits = append(hits, p+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Errorf("install paths outside internal/layout (use layout.CodeDir, layout.Conf, ...):\n%s", strings.Join(hits, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestTheHelpersJoinUnderTheLayout(t *testing.T) {
	old := ConfDir
	t.Cleanup(func() { ConfDir = old })
	ConfDir = "/srv/fleet/etc"
	if got := Conf("domains.txt"); got != "/srv/fleet/etc/domains.txt" {
		t.Errorf("Conf = %q", got)
	}
	if got := Bin("fleet-board"); got != filepath.Join(CodeDir, "bin", "fleet-board") {
		t.Errorf("Bin = %q", got)
	}
}
