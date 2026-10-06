package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runCompare checks whether the .log and .tar.gz files sitting directly in
// dirA (no subdirectories) exist anywhere under dirB (recursive), matching on
// file name only. It writes compare_report.csv with one line per match, or a
// single "Missing" line when a file has no match.
func runCompare(dirA, dirB, outDir string) {
	a, err := filepath.Abs(dirA)
	if err != nil {
		fatal(err)
	}
	b, err := filepath.Abs(dirB)
	if err != nil {
		fatal(err)
	}
	for _, d := range []string{a, b} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			fatal(fmt.Errorf("%s is not a readable directory", d))
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}
	reportPath := filepath.Join(outDir, "compare_report.csv")
	if abs, err := filepath.Abs(reportPath); err == nil {
		skipPaths[abs] = true
	}

	// Directory A: top level only, .log and .tar.gz files.
	des, err := os.ReadDir(a)
	if err != nil {
		fatal(err)
	}
	var namesA []string
	for _, de := range des {
		n := strings.ToLower(de.Name())
		if de.IsDir() || de.Type()&os.ModeSymlink != 0 {
			continue
		}
		if strings.HasSuffix(n, ".log") || strings.HasSuffix(n, ".tar.gz") {
			namesA = append(namesA, de.Name())
		}
	}
	sort.Strings(namesA)

	// Directory B: everything below it, indexed by file name.
	var entriesB []*entry
	walk(b, &entriesB)
	inB := map[string][]string{}
	for _, e := range entriesB {
		if e.Type == "file" {
			inB[e.Name] = append(inB[e.Name], e.Dir)
		}
	}

	rows := [][]string{}
	missing := 0
	for _, name := range namesA {
		dirs := inB[name]
		if len(dirs) == 0 {
			missing++
			rows = append(rows, []string{name, "Missing", a, ""})
			continue
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			rows = append(rows, []string{name, "Found", a, d})
		}
	}
	writeCSV(reportPath, []string{"Name", "Status", "DirectoryA", "DirectoryB"}, rows)

	fmt.Printf("Checked %d file(s) from %s\n", len(namesA), a)
	fmt.Printf("  Found in B:   %d\n  Missing from B: %d\n", len(namesA)-missing, missing)
	fmt.Printf("Wrote %s\n", reportPath)
}
