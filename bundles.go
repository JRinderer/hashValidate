package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// runBundles hashes each folder sitting directly in dir as a single unit and
// writes bundles_report.csv with one line per folder. Each hash covers
// everything inside the folder (same algorithm as folder hashes in normal
// mode) but no per-file rows are written. Files directly in dir are ignored.
func runBundles(dir, outDir string) {
	root, err := filepath.Abs(dir)
	if err != nil {
		fatal(err)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fatal(fmt.Errorf("%s is not a readable directory", root))
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}
	reportPath := filepath.Join(outDir, "bundles_report.csv")
	if abs, err := filepath.Abs(reportPath); err == nil {
		skipPaths[abs] = true
	}

	des, err := os.ReadDir(root)
	if err != nil {
		fatal(err)
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	var bundles []string
	for _, de := range des {
		if de.IsDir() && de.Type()&os.ModeSymlink == 0 && !isZip(de.Name()) && !isTarGz(de.Name()) {
			bundles = append(bundles, filepath.Join(root, de.Name()))
		}
	}

	doHash = true
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		prog.enabled = true
		fmt.Fprintln(os.Stderr, "Scanning...")
	}
	for _, b := range bundles {
		scan(b)
	}

	rows := [][]string{}
	failed := 0
	for _, b := range bundles {
		var entries []*entry
		sha, md, werr := walk(b, &entries)
		errMsg := ""
		if werr != nil {
			errMsg = werr.Error()
		} else {
			// Unreadable files inside the bundle make its hash incomplete.
			n := 0
			for _, e := range entries {
				if e.Err != "" {
					n++
				}
			}
			if n > 0 {
				errMsg = fmt.Sprintf("%d item(s) inside could not be read; hash is incomplete", n)
			}
		}
		if errMsg != "" {
			failed++
		}
		rows = append(rows, []string{filepath.Base(b), filepath.Dir(b), md, sha, errMsg})
	}
	prog.current = "done"
	prog.draw(true)
	if prog.enabled {
		fmt.Fprintln(os.Stderr)
	}
	writeCSV(reportPath, []string{"BundleName", "Directory", "MD5", "SHA256", "Error"}, rows)

	fmt.Printf("Hashed %d bundle folder(s) under %s (%d with errors)\n", len(bundles), root, failed)
	fmt.Printf("Wrote %s\n", reportPath)
}
