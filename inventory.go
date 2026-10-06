package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// runInventory walks dir (recursively), opens each .zip only far enough to
// read its table of contents, and writes inventory_report.csv with one line
// per file inside each zip. The files inside the zips are never extracted or
// read.
func runInventory(dir, outDir string) {
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
	reportPath := filepath.Join(outDir, "inventory_report.csv")

	var zips []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink != 0 {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && isZip(d.Name()) {
			zips = append(zips, p)
		}
		return nil
	})
	sort.Strings(zips)

	rows := [][]string{}
	entries := 0
	for _, z := range zips {
		r, err := zip.OpenReader(z)
		if err != nil {
			rows = append(rows, []string{filepath.Base(z), filepath.Dir(z), "", "", "", err.Error()})
			continue
		}
		for _, f := range r.File {
			if f.FileInfo().IsDir() {
				continue
			}
			entries++
			rows = append(rows, []string{
				filepath.Base(z), filepath.Dir(z), f.Name, path.Base(f.Name),
				fmt.Sprint(f.UncompressedSize64), "",
			})
		}
		r.Close()
	}
	writeCSV(reportPath, []string{"ZipFile", "ZipDirectory", "EntryPath", "EntryName", "Size", "Error"}, rows)

	fmt.Printf("Found %d zip file(s) under %s\n", len(zips), root)
	fmt.Printf("Listed %d file(s) inside them\n", entries)
	fmt.Printf("Wrote %s\n", reportPath)
}
