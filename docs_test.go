// SPDX-License-Identifier: MIT

package knx

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDropReasonsDocumented: OBSERVABILITY.md lists the reasons the
// library gives to Metrics.OnDropped, no more and no less. A reason added
// to the code without its row, or a row whose reason the code no longer
// reports, fails here.
func TestDropReasonsDocumented(t *testing.T) {
	call := regexp.MustCompile(`\.OnDropped\([^"\n]*"([a-z_]+)"\)`)
	inCode := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range call.FindAllSubmatch(b, -1) {
			inCode[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inCode) < 10 {
		t.Fatalf("found %d drop reasons in the code: the search no longer matches the calls", len(inCode))
	}

	doc, err := os.ReadFile("OBSERVABILITY.md")
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may convert the line endings.
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")
	_, section, found := strings.Cut(text, "\n## Drop reasons\n")
	if !found {
		t.Fatal(`OBSERVABILITY.md has no section "Drop reasons"`)
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")
	inDoc := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		if inDoc[m[1]] {
			t.Errorf("OBSERVABILITY.md lists the reason %q twice", m[1])
		}
		inDoc[m[1]] = true
	}
	var missing, stale []string
	for r := range inCode {
		if !inDoc[r] {
			missing = append(missing, r)
		}
	}
	for r := range inDoc {
		if !inCode[r] {
			stale = append(stale, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("reasons the code reports and OBSERVABILITY.md does not list: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("reasons OBSERVABILITY.md lists and the code does not report: %v", stale)
	}
}
