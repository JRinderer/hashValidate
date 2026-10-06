package main

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// runInventory walks dir (recursively), opens each .zip only far enough to
// read its table of contents, and writes inventory_report.csv with one line
// per file inside each zip. The files inside the zips are never extracted or
// read. With -hash, each entry is streamed through SHA-256 and MD5 (in memory
// only, nothing is written to disk) and the digests are added as columns.
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
			row := []string{filepath.Base(z), filepath.Dir(z), "", "", ""}
			if doHash {
				row = append(row, "", "")
			}
			rows = append(rows, append(row, err.Error()))
			continue
		}
		for _, f := range r.File {
			if f.FileInfo().IsDir() {
				continue
			}
			entries++
			row := []string{
				filepath.Base(z), filepath.Dir(z), f.Name, path.Base(f.Name),
				fmt.Sprint(f.UncompressedSize64),
			}
			errMsg := ""
			if doHash {
				sha, md, err := hashZipEntry(f)
				if err != nil {
					errMsg = err.Error()
				}
				row = append(row, md, sha)
			}
			rows = append(rows, append(row, errMsg))
		}
		r.Close()
	}
	header := []string{"ZipFile", "ZipDirectory", "EntryPath", "EntryName", "Size"}
	if doHash {
		header = append(header, "MD5", "SHA256")
	}
	writeCSV(reportPath, append(header, "Error"), rows)

	fmt.Printf("Found %d zip file(s) under %s\n", len(zips), root)
	fmt.Printf("Listed %d file(s) inside them\n", entries)
	fmt.Printf("Wrote %s\n", reportPath)
}

// hashZipEntry streams one zip entry through SHA-256 and MD5 in a single pass.
func hashZipEntry(f *zip.File) (sha, md string, err error) {
	rc, err := f.Open()
	if err != nil {
		return "", "", err
	}
	defer rc.Close()
	hs, hm := sha256.New(), md5.New()
	if _, err := io.Copy(io.MultiWriter(hs, hm), rc); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(hs.Sum(nil)), hex.EncodeToString(hm.Sum(nil)), nil
}
