package netmap

import (
	"fmt"
	"strconv"
	"strings"
)

// THE SHEET'S CONVENTIONS THAT DIFFER BY ORGANIZATION.
//
// The reader's format is the fleet's documented one (the report's "How the
// spreadsheet is read"), but two parts of it are one IP plan's habits rather
// than the format's: which third octet marks a location's user network, and
// which row labels a sheet uses. cti-vmscan sets both from its settings at
// startup; unset, they are what the reader always did.

// DefaultUserOctet is the third octet of a location's user network, 10.X.30,
// when nothing else is configured.
const DefaultUserOctet = 30

// userOctet is the configured octet, or -1 when the rule is off and only a
// row labelled corp decides.
var userOctet = DefaultUserOctet

// UserOctet is the third octet that marks a location's user network, and
// whether that rule is on at all.
func UserOctet() (int, bool) {
	return userOctet, userOctet >= 0
}

// UseSheetConventions sets the two conventions. octet is a number from 0 to
// 255, "off", or empty for DefaultUserOctet. labels is a comma-separated list
// of extra row labels (lower-cased; letters, digits, spaces and - _ /), added
// to the built-in ones so a row carrying one is never read as a location.
// Anything else is an error, and nothing is changed.
func UseSheetConventions(octet, labels string) error {
	n := DefaultUserOctet
	switch o := strings.ToLower(strings.TrimSpace(octet)); o {
	case "":
	case "off":
		n = -1
	default:
		v, err := strconv.Atoi(o)
		if err != nil || v < 0 || v > 255 {
			return fmt.Errorf("user-network octet %q: give a number from 0 to 255, or off", octet)
		}
		n = v
	}
	var add []string
	for _, l := range strings.Split(labels, ",") {
		l = strings.ToLower(strings.Join(strings.Fields(l), " "))
		if l == "" {
			continue
		}
		if len(l) > 40 || strings.IndexFunc(l, badLabelRune) >= 0 {
			return fmt.Errorf("row label %q: letters, digits, spaces and - _ / only, at most 40 characters", l)
		}
		add = append(add, l)
	}
	userOctet = n
	for _, l := range add {
		roleLabels[l] = true
	}
	return nil
}

func badLabelRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == ' ', r == '-', r == '_', r == '/':
		return false
	}
	return true
}
