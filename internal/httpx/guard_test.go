package httpx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoClientBypassesHTTPX fails when Go code builds an HTTP client or
// transport by hand, or reaches for the net/http defaults. A hand-built
// client has no TLS floor and will send a credential over http:// if its base
// URL says so (Prime guardrail "TLS Version Requirement"). Use httpx.New, or
// httpx.Guard around a transport.
//
// It reads the syntax tree, so it sees the import under any alias, comments
// and strings cannot hide a construct, and new(http.Client), var c
// http.Client, http.DefaultTransport and the http.Get family are all caught.
//
// Every exception below carries its reason.
func TestNoClientBypassesHTTPX(t *testing.T) {
	root := filepath.Join("..", "..")

	// Whole files allowed to build net/http clients or transports.
	allowedFiles := map[string]string{
		"internal/httpx/httpx.go": "this package",
		"internal/domains/web.go": "probes other people's websites over http and https and measures what they serve; it sends no credential (certificate validity is checked separately with verification on). Keep credentials out of this file",
	}
	// Qualys clients may wrap the rate limiter, which qualysrl.New builds on
	// httpx.Transport and httpx.Guard, provided the same literal also sets
	// CheckRedirect: httpx.CheckRedirect.
	limiterFiles := map[string]bool{
		"internal/appscan/qualys/findings.go": true,
		"internal/vmscan/qualysapi.go":        true,
		"internal/netmap/qualys.go":           true,
	}
	// Files allowed to call httpx.Transport() without Guard on the same
	// expression: it is wrapped by Guard straight away.
	transportFiles := map[string]string{
		"internal/qualysrl/limiter.go": "sets the response-header timeout, then wraps the transport in httpx.Guard in the same function",
	}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".toolchain", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if _, ok := allowedFiles[rel]; ok {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		httpName, httpxName := "", ""
		for _, im := range f.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			local := filepath.Base(p)
			if im.Name != nil {
				local = im.Name.Name
			}
			switch p {
			case "net/http":
				httpName = local
			case "github.com/zany2dmax/cti-agent/internal/httpx":
				httpxName = local
			}
		}
		isSel := func(e ast.Expr, pkg string, names ...string) (string, bool) {
			s, ok := e.(*ast.SelectorExpr)
			if !ok || pkg == "" {
				return "", false
			}
			id, ok := s.X.(*ast.Ident)
			if !ok || id.Name != pkg {
				return "", false
			}
			if len(names) == 0 {
				return s.Sel.Name, true
			}
			for _, n := range names {
				if s.Sel.Name == n {
					return n, true
				}
			}
			return "", false
		}
		report := func(pos token.Pos, what string) {
			t.Errorf("%s:%d %s: use httpx.New (or httpx.Guard around a transport), or add this to the allowlist in guard_test.go with a reason",
				rel, fset.Position(pos).Line, what)
		}
		// A client literal is allowed only as a limiter wrapper.
		okLimiterClient := func(lit *ast.CompositeLit) bool {
			if !limiterFiles[rel] {
				return false
			}
			var transportL, redirect bool
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					return false
				}
				key, _ := kv.Key.(*ast.Ident)
				if key == nil {
					return false
				}
				switch key.Name {
				case "Timeout":
				case "Transport":
					id, ok := kv.Value.(*ast.Ident)
					transportL = ok && id.Name == "l"
				case "CheckRedirect":
					_, redirect = isSel(kv.Value, httpxName, "CheckRedirect")
				default:
					return false
				}
			}
			return transportL && redirect
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if name, ok := isSel(x.Type, httpName, "Client", "Transport"); ok {
					if name == "Client" && okLimiterClient(x) {
						return true
					}
					report(x.Pos(), "builds an http."+name+" by hand")
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
					if name, ok := isSel(x.Args[0], httpName, "Client", "Transport"); ok {
						report(x.Pos(), "builds an http."+name+" with new()")
					}
				}
				if _, ok := isSel(x.Fun, httpxName, "Transport"); ok {
					if _, allowed := transportFiles[rel]; !allowed {
						report(x.Pos(), "calls httpx.Transport() outside the one file that wraps it in Guard")
					}
				}
			case *ast.ValueSpec:
				if name, ok := isSel(x.Type, httpName, "Client", "Transport"); ok {
					report(x.Pos(), "declares an http."+name+" value")
				}
			case *ast.SelectorExpr:
				if name, ok := isSel(x, httpName, "DefaultClient", "DefaultTransport", "Get", "Post", "PostForm", "Head"); ok {
					report(x.Pos(), "uses http."+name+", which is the default client or goes through it")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
