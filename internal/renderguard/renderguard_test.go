// Package renderguard holds one test: no Go file may format a non-constant,
// non-escaped value into an HTML tag string (PrimeSec Top-232, output
// encoding at the rendering boundary).
package renderguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowed lists deliberate exceptions, keyed "relative/file.go:funcName",
// "relative/file.go:funcName:argumentText" (one argument only) or
// "relative/file.go:*" (whole file).
// Each needs a one-line reason: the value is built from trusted constants or
// already escaped before it reaches the call. A new entry is a review item.
var allowed = map[string]string{
	"internal/emailkit/emailkit.go:*":                                            "layout helpers: title/org/heading/text are escaped inside; inner/lines/caption/subtitle params are documented as already-built HTML and are checked at each caller",
	"internal/xlsx/xlsxtest/build.go:*":                                          "test fixture builder for spreadsheet XML, never rendered to a reader",
	"internal/appscan/qualys/findings.go:*":                                      "Qualys request XML, not HTML to a reader; values are escaped with xmlEscape or are constants",
	"internal/appscan/qualys/scans.go:*":                                         "Qualys request XML, not HTML to a reader; values are constants or time formats",
	"internal/appscan/qualys/webapps.go:*":                                       "Qualys request XML, not HTML to a reader; values are constants or numbers",
	"internal/appscan/ownerreport.go:writeSummary:v":                             "row's value parameter: every row() call passes h(...) output or a constant",
	"internal/appscan/ownerreport.go:writeKinds:param":                           "set from the literal &ndash; or \"<code>\"+h(param)+\"</code>\"",
	"internal/appscan/ownerreport.go:writeSummary:t.name":                        "severity label from the fixed sevOf table, not scanner text",
	"internal/appscan/ownerreport.go:writeKinds:st.name":                         "severity label from the fixed sevOf table, not scanner text",
	"internal/patchtuesday/render.go:HTML:lead":                                  "qqlBlock's lead is always a constant sentence at both call sites",
	"internal/patchtuesday/render.go:HTML:caption":                               "built only from Sprintf of ints and literals",
	"internal/patchtuesday/render.go:HTML:hosts":                                 "number rendering with a literal prefix",
	"internal/patchtuesday/render.go:HTML:body":                                  "sect's body is escaped at every call site",
	"internal/supplier/ticket.go:UpdateComment:VerdictLabel(prior.Verdict)":      "VerdictLabel maps the verdict enum to fixed labels",
	"internal/supplier/ticket.go:UpdateComment:VerdictLabel(r.Decision.Verdict)": "VerdictLabel maps the verdict enum to fixed labels",
	"cmd/cti-jira/appscan.go:findingBlock:title":                                 "para's title is a constant at all three call sites",
	"internal/report/markdown.go:WriteMarkdownScan:m":                            "held-CVE month key in a local markdown report, not rendered as HTML",
	"cmd/cti-appreport/main.go:newestTicketsFile":                                "usage text for the terminal: the '<' is a placeholder, not markup",
}

// tokenVars are package-level names bound to emailkit tokens (collected).
var tokenVars = map[string]bool{}

// renderers are functions that return finished, escaped markup.
var renderers = map[string]bool{"paras": true, "statusChip": true, "num": true, "footerCounts": true, "reportCSS": true, "linkHTML": true, "sevLabel": true}

// tagRe matches an HTML tag or Jira wiki markup around a verb: {{%s}} monospace and *%s* bold. Plain-text
// formats are not covered.
var tagRe = regexp.MustCompile(`</?[a-zA-Z][a-zA-Z0-9]*[ >/]|</?[a-zA-Z][a-zA-Z0-9]*$|\{\{%|\*%s\*`)
var verbRe = regexp.MustCompile(`%(%|[-+# 0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[a-zA-Z])`)

// formatFuncs maps a function name to the index of its format string.
var formatFuncs = map[string]int{"Sprintf": 0, "Fprintf": 1, "Printf": 0, "Errorf": 0}

// safeCall reports whether a call expression yields a value that is safe to
// put in markup: an escaper, or a number rendering.
func (c *ctx) safeCall(call *ast.CallExpr) bool {
	var name string
	switch f := call.Fun.(type) {
	case *ast.Ident:
		name = f.Name
		if c.aliases[name] {
			return true
		}
	case *ast.SelectorExpr:
		name = f.Sel.Name
	}
	if renderers[name] {
		return true
	}
	l := strings.ToLower(name)
	// A fragment another builder already rendered (xxxHTML(), b.String(),
	// strings.Join of rows) is checked where it is built, not here.
	if strings.HasSuffix(l, "html") || l == "string" || l == "join" {
		return true
	}
	if l == "sprintf" && len(call.Args) > 0 {
		if f, ok := literal(call.Args[0]); ok && tagRe.MatchString(f) {
			return true // its own arguments are scanned
		}
	}
	switch l {
	case "replaceall", "trimsuffix", "trimprefix", "trimspace", "toupper", "tolower", "trim":
		if len(call.Args) > 0 {
			return c.safeArg(call.Args[0])
		}
	}
	if l == "format" {
		return true // time layouts
	}
	if strings.Contains(l, "esc") || strings.Contains(l, "wiki") || strings.Contains(l, "sanit") || l == "itoa" || l == "len" ||
		l == "formatint" || l == "formatfloat" || l == "int" || l == "float64" || l == "int64" {
		return true
	}
	return false
}

// ctx carries per-file facts: imported package names, and local names bound
// to an escaper (e := html.EscapeString).
type ctx struct {
	pkgs    map[string]bool
	aliases map[string]bool
}

// collectAliases records names bound to an escaper anywhere in f: local
// "e := html.EscapeString" and one-line wrappers such as
// "func h(s string) string { return html.EscapeString(s) }".
func collectAliases(f *ast.File, into map[string]bool) {
	isEsc := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "EscapeString"
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil && len(fd.Body.List) == 1 {
			if r, ok := fd.Body.List[0].(*ast.ReturnStmt); ok && len(r.Results) == 1 {
				if c, ok := r.Results[0].(*ast.CallExpr); ok && isEsc(c.Fun) {
					into[fd.Name.Name] = true
				}
			}
		}
	}
	// package-level "var font = emailkit.Font": a name bound to tokens only.
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok || len(vs.Values) != len(vs.Names) {
				continue
			}
			for i, v := range vs.Values {
				if sel, ok := v.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "emailkit" {
						tokenVars[vs.Names[i].Name] = true
					}
				}
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, r := range as.Rhs {
			if id, ok := as.Lhs[i].(*ast.Ident); ok && isEsc(r) {
				into[id.Name] = true
			}
		}
		return true
	})
}

func newCtx(f *ast.File, aliases map[string]bool) *ctx {
	c := &ctx{pkgs: map[string]bool{}, aliases: aliases}
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		c.pkgs[name] = true
	}
	return c
}

// safeLocal reports whether a local name was bound (":=") to a safe value:
// a literal, a constant, an escaped value, or a Sprintf whose own tag format
// is checked where it is written.
func (c *ctx) safeLocal(id *ast.Ident, depth int) bool {
	if id.Obj == nil || depth > 3 {
		return false
	}
	as, ok := id.Obj.Decl.(*ast.AssignStmt)
	if !ok || as.Tok != token.DEFINE || len(as.Lhs) != len(as.Rhs) {
		return false
	}
	for i, l := range as.Lhs {
		if li, ok := l.(*ast.Ident); ok && li.Name == id.Name {
			return c.safeArgDepth(as.Rhs[i], depth+1)
		}
	}
	return false
}

func (c *ctx) safeArg(e ast.Expr) bool { return c.safeArgDepth(e, 0) }

func (c *ctx) safeArgDepth(e ast.Expr, depth int) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if tokenVars[v.Name] {
			return true
		}
		return v.Obj != nil && (v.Obj.Kind == ast.Con || c.safeLocal(v, depth))
	case *ast.SelectorExpr:
		// colour tokens on a tone struct (t.Fg, tone.Bg)
		if v.Sel.Name == "Fg" || v.Sel.Name == "Bg" {
			return true
		}
		// pkg.Const (emailkit.Font): an exported name of an imported package
		// holds a constant or token, never request data.
		x, ok := v.X.(*ast.Ident)
		return ok && c.pkgs[x.Name]
	case *ast.CallExpr:
		return c.safeCall(v)
	case *ast.ParenExpr:
		return c.safeArgDepth(v.X, depth)
	case *ast.BinaryExpr:
		return c.safeArgDepth(v.X, depth) && c.safeArgDepth(v.Y, depth)
	}
	return false
}

// literal returns the constant string value of e when it is a literal or a
// concatenation of literals.
func literal(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		a, ok1 := literal(v.X)
		b, ok2 := literal(v.Y)
		return a + b, ok1 && ok2
	case *ast.ParenExpr:
		return literal(v.X)
	}
	return "", false
}

// scan returns violation descriptions ("file:line: ...") for one parsed file.
func scan(fset *token.FileSet, f *ast.File, rel string, aliases map[string]bool) []string {
	c := newCtx(f, aliases)
	var out []string
	var fn string
	report := func(pos token.Pos, arg, msg string) {
		key := rel + ":" + fn
		if _, ok := allowed[key]; ok {
			return
		}
		if _, ok := allowed[rel+":*"]; ok {
			return
		}
		if _, ok := allowed[key+":"+arg]; ok {
			return
		}
		out = append(out, fmt.Sprintf("%s:%d (%s): %s", rel, fset.Position(pos).Line, key, msg))
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok {
			fn = fd.Name.Name
		} else {
			fn = ""
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				var name string
				switch fun := x.Fun.(type) {
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				case *ast.Ident:
					name = fun.Name
				}
				idx, ok := formatFuncs[name]
				if !ok || len(x.Args) <= idx {
					return true
				}
				format, ok := literal(x.Args[idx])
				if !ok || !tagRe.MatchString(format) {
					return true
				}
				args := x.Args[idx+1:]
				ai := 0
				for _, m := range verbRe.FindAllStringSubmatch(format, -1) {
					if m[1] == "%" {
						continue
					}
					verb := m[1][len(m[1])-1]
					if ai >= len(args) {
						break
					}
					a := args[ai]
					ai++
					switch verb {
					case 'd', 'f', 'g', 'x', 't', 'c':
						continue
					}
					if !c.safeArg(a) {
						report(a.Pos(), render(fset, a), "argument "+render(fset, a)+" is formatted into markup without an escaper; wrap it in html.EscapeString or the emailkit escaper, or add a reasoned entry to allowed")
					}
				}
			case *ast.BinaryExpr:
				// "<td>" + value + "</td>" built by concatenation
				if x.Op != token.ADD {
					return true
				}
				if s, ok := literal(x.X); ok && tagRe.MatchString(s) && !c.safeArg(x.Y) {
					report(x.Y.Pos(), render(fset, x.Y), "value "+render(fset, x.Y)+" is concatenated into markup without an escaper (see allowed)")
				}
				if s, ok := literal(x.Y); ok && tagRe.MatchString(s) && !c.safeArg(x.X) {
					if _, isBin := x.X.(*ast.BinaryExpr); !isBin {
						report(x.X.Pos(), render(fset, x.X), "value "+render(fset, x.X)+" is concatenated into markup without an escaper (see allowed)")
					}
				}
			}
			return true
		})
	}
	return out
}

func render(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	_ = printer.Fprint(&sb, fset, e)
	return sb.String()
}

func aliasesOf(f *ast.File) map[string]bool {
	m := map[string]bool{}
	collectAliases(f, m)
	return m
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

func TestNoRawValuesInMarkup(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	type parsed struct {
		fset *token.FileSet
		f    *ast.File
		rel  string
	}
	var files []parsed
	aliases := map[string]bool{}
	for _, dir := range []string{"cmd", "internal"} {
		_ = filepath.Walk(filepath.Join(root, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				t.Errorf("parse %s: %v", p, perr)
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			collectAliases(f, aliases)
			files = append(files, parsed{fset, f, rel})
			return nil
		})
	}
	for _, p := range files {
		bad = append(bad, scan(p.fset, p.f, p.rel, aliases)...)
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("raw value formatted into markup (untrusted text must go through html.EscapeString or the emailkit escaper first):\n  %s", strings.Join(bad, "\n  "))
	}
}

func TestAllowlistHasNoStaleEntries(t *testing.T) {
	root := repoRoot(t)
	for k, why := range allowed {
		file := k[:strings.Index(k, ":")]
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			t.Errorf("allowlist entry %s points at a missing file", k)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("allowlist entry %s has no reason", k)
		}
	}
}

func TestGuardCatchesARawValue(t *testing.T) {
	const bad = `package x
import ("fmt";"html";"strings")
func a(b *strings.Builder, name string) {
	fmt.Fprintf(b, "<td>%s</td>", name)
	b.WriteString("<li>" + name + "</li>")
}
func ok(b *strings.Builder, name string, n int) {
	fmt.Fprintf(b, "<td>%s %d</td>", html.EscapeString(name), n)
	b.WriteString("<li>" + html.EscapeString(name) + "</li>")
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", bad, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := scan(fset, f, "x.go", aliasesOf(f))
	if len(got) != 2 {
		t.Fatalf("want 2 violations (both in a), got %d: %v", len(got), got)
	}
	for _, g := range got {
		if !strings.Contains(g, "(x.go:a)") {
			t.Errorf("violation outside a(): %s", g)
		}
	}
}
