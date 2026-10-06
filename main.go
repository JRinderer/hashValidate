// hashvalidation walks a directory tree, hashes every file and folder with
// SHA-256 and MD5, writes the results to hash_validation.csv, and flags
// names that appear more than once.
//
// Usage: go run . <root-dir> [output.csv]
//
// Folder hashes are derived from their contents: the hash of the sorted list
// of "<child name>:<child hash>" lines, so a folder's hash changes if anything
// inside it is added, removed, renamed or modified.
package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type entry struct {
	Type    string // "file" or "folder"
	Name    string
	RelPath string
	SHA256  string
	MD5     string
	Err     string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hashvalidation <root-dir> [output.csv]")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatal(err)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fatal(fmt.Errorf("%s is not a readable directory", root))
	}
	outPath := "hash_validation.csv"
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}
	outAbs, _ := filepath.Abs(outPath)

	var entries []*entry
	walk(root, root, outAbs, &entries)

	// Count occurrences of each name, separately for files and folders.
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Type+"\x00"+e.Name]++
	}

	f, err := os.Create(outPath)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"Type", "Name", "RelativePath", "SHA256", "MD5", "Duplicate", "DuplicateCount", "Error"})
	dupGroups := map[string][]string{}
	for _, e := range entries {
		n := counts[e.Type+"\x00"+e.Name]
		dup := "No"
		if n > 1 {
			dup = "Yes"
			k := e.Type + ": " + e.Name
			dupGroups[k] = append(dupGroups[k], e.RelPath)
		}
		w.Write([]string{e.Type, e.Name, e.RelPath, e.SHA256, e.MD5, dup, fmt.Sprint(n), e.Err})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fatal(err)
	}

	fmt.Printf("Wrote %d entries to %s\n", len(entries), outPath)
	if len(dupGroups) == 0 {
		fmt.Println("No duplicate names found.")
		return
	}
	keys := make([]string, 0, len(dupGroups))
	for k := range dupGroups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("\n%d duplicated name(s):\n", len(keys))
	for _, k := range keys {
		fmt.Printf("  %s (%d)\n", k, len(dupGroups[k]))
		for _, p := range dupGroups[k] {
			fmt.Printf("      %s\n", p)
		}
	}
}

// walk records every file and folder under dir (pre-order) and returns dir's
// own SHA-256 and MD5, computed from its children.
func walk(root, dir, skip string, out *[]*entry) (sha, md string, err error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })

	var shaLines, mdLines strings.Builder
	for _, de := range des {
		p := filepath.Join(dir, de.Name())
		if p == skip || de.Type()&os.ModeSymlink != 0 {
			continue
		}
		rel, _ := filepath.Rel(root, p)
		e := &entry{Name: de.Name(), RelPath: rel}
		*out = append(*out, e)

		if de.IsDir() {
			e.Type = "folder"
			var werr error
			e.SHA256, e.MD5, werr = walk(root, p, skip, out)
			if werr != nil {
				e.Err = werr.Error()
			}
		} else {
			e.Type = "file"
			var herr error
			e.SHA256, e.MD5, herr = hashFile(p)
			if herr != nil {
				e.Err = herr.Error()
			}
		}
		fmt.Fprintf(&shaLines, "%s:%s\n", e.Name, e.SHA256)
		fmt.Fprintf(&mdLines, "%s:%s\n", e.Name, e.MD5)
	}
	s := sha256.Sum256([]byte(shaLines.String()))
	m := md5.Sum([]byte(mdLines.String()))
	return hex.EncodeToString(s[:]), hex.EncodeToString(m[:]), nil
}

func hashFile(path string) (sha, md string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	hs, hm := sha256.New(), md5.New()
	if _, err := io.Copy(io.MultiWriter(hs, hm), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(hs.Sum(nil)), hex.EncodeToString(hm.Sum(nil)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
