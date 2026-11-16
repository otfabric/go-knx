// SPDX-License-Identifier: MIT

// Package redact writes the text that stands for a value holding a
// secret, for the verbs package fmt passes to a Format method.
package redact

import "fmt"

// Format writes text for verb, with the flags, width and precision of s.
// %v, %s, %q, %x and %X format text as fmt formats a string, as a String
// method would have it; %#v and every other verb (%d, %o, %b...) write
// text itself, padded to the width, as a GoString method would.
func Format(s fmt.State, verb rune, text string) {
	switch verb {
	case 's', 'q', 'x', 'X':
	case 'v':
		if s.Flag('#') {
			verb = 's'
		}
	default:
		verb = 's'
	}
	// A Format method has no error to return; fmt reports none for it.
	_, _ = fmt.Fprintf(s, fmt.FormatString(s, verb), text)
}
