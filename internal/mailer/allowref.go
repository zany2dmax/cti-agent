package mailer

import (
	"fmt"
	"strings"
)

// MaxRefDepth bounds how far one allowlist may chase references into others.
//
// Low on purpose. Three audiences that each build on the last is already more
// indirection than a recipient list should need, and anything deeper is a sign
// the lists want flattening rather than a bigger limit.
const MaxRefDepth = 5

// ExpandAllow resolves an allowlist that may reference other allowlists.
//
//	VM_ALLOW_TO=alice@example.com,bob@example.com
//	PT_ALLOW_TO=$VM_ALLOW_TO,carol@example.com
//
// A token beginning with "$" or "${...}" names another variable, which is
// looked up and expanded in place. Everything else is taken as an address.
// Order is preserved and duplicates are collapsed, so a person who appears
// through two references is still mailed once.
//
// # WHY AN UNKNOWN REFERENCE IS AN ERROR AND NOT AN EMPTY STRING
//
// Shell expansion of an undefined variable yields nothing, silently. Applied
// to a recipient list that is the worst available behaviour: a typo in
// $VM_ALLOW_TOO would quietly shrink the list, every recipient inherited
// through it would start being refused, and the error a human eventually sees
// names the RECIPIENTS rather than the typo that removed them. They would go
// looking in the wrong place.
//
// So an unresolvable reference stops the send and names the variable.
//
// # WHAT A REFERENCE COSTS YOU
//
// It is a live link, not a copy. If VM_ALLOW_TO later gains somebody, every
// list referencing it gains them too, without anyone revisiting that list.
// That is the point of the feature and also its one hazard: the cheapest way
// to widen an audience you did not mean to widen is to widen one it inherits
// from. Reference deliberately; spell the list out when the audiences are
// meant to drift apart.
func ExpandAllow(name, raw string, lookup func(string) (string, bool)) ([]string, error) {
	seen := map[string]bool{}  // addresses, for dedupe
	chain := map[string]bool{} // variables currently being expanded, for cycles
	var out []string

	var walk func(varName, value string, depth int) error
	walk = func(varName, value string, depth int) error {
		if depth > MaxRefDepth {
			return fmt.Errorf(
				"%s: allowlist references nest more than %d deep - flatten them",
				name, MaxRefDepth)
		}
		for _, tok := range SplitList(value) {
			ref, isRef := refName(tok)
			if !isRef {
				if k := strings.ToLower(tok); !seen[k] {
					seen[k] = true
					out = append(out, tok)
				}
				continue
			}
			if chain[ref] {
				return fmt.Errorf(
					"%s: allowlist reference cycle at $%s - a list cannot "+
						"include itself, directly or through another", name, ref)
			}
			v, ok := lookup(ref)
			if !ok {
				return fmt.Errorf(
					"%s references $%s, which is not set in fleet.env. This is "+
						"refused rather than treated as empty: an unset reference "+
						"silently removes every recipient inherited through it, "+
						"and the error you would see next names the recipients "+
						"instead of the typo", name, ref)
			}
			chain[ref] = true
			if err := walk(ref, v, depth+1); err != nil {
				return err
			}
			delete(chain, ref)
		}
		return nil
	}

	if err := walk(name, raw, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// refName reports whether a token is a variable reference, and its name.
//
// Accepts $NAME and ${NAME}. A bare "$" or an empty ${} is not a reference to
// anything and is refused as a malformed address later, rather than being
// quietly dropped.
func refName(tok string) (string, bool) {
	t := strings.TrimSpace(tok)
	if !strings.HasPrefix(t, "$") {
		return "", false
	}
	t = strings.TrimPrefix(t, "$")
	if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
		t = t[1 : len(t)-1]
	}
	t = strings.TrimSpace(t)
	if t == "" {
		return "", false
	}
	// A variable name, not an address. Anything else is somebody writing an
	// address that begins with a dollar sign, which is not a thing.
	for i := 0; i < len(t); i++ {
		c := t[i]
		ok := c == '_' ||
			(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9' && i > 0)
		if !ok {
			return "", false
		}
	}
	return t, true
}
