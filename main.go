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
	"time"
)

// progress reports items and bytes processed on stderr. It only draws when
// stderr is a terminal, so redirected output stays clean.
type progress struct {
	totalItems, doneItems int
	totalBytes, doneBytes int64
	current               string
	last                  time.Time
	enabled               bool
}

var prog progress

func (p *progress) draw(force bool) {
	if !p.enabled || (!force && time.Since(p.last) < 100*time.Millisecond) {
		return
	}
	p.last = time.Now()
	pct := 100.0
	if p.totalBytes > 0 {
		pct = float64(p.doneBytes) / float64(p.totalBytes) * 100
	} else if p.totalItems > 0 {
		pct = float64(p.doneItems) / float64(p.totalItems) * 100
	}
	name := p.current
	if len(name) > 40 {
		name = "..." + name[len(name)-37:]
	}
	fmt.Fprintf(os.Stderr, "\r[%5.1f%%] %d/%d items | %s / %s | %-40s",
		pct, p.doneItems, p.totalItems, human(p.doneBytes), human(p.totalBytes), name)
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// countingWriter feeds hashed bytes into the progress tracker.
type countingWriter struct{}

func (countingWriter) Write(b []byte) (int, error) {
	prog.doneBytes += int64(len(b))
	prog.draw(false)
	return len(b), nil
}

// scan totals the items and bytes that walk will process.
func scan(root, skip string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		if p == skip || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		prog.totalItems++
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				prog.totalBytes += fi.Size()
			}
		}
		return nil
	})
}

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

	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		prog.enabled = true
		fmt.Fprintln(os.Stderr, "Scanning...")
	}
	scan(root, outAbs)

	var entries []*entry
	walk(root, root, outAbs, &entries)
	prog.current = "done"
	prog.draw(true)
	if prog.enabled {
		fmt.Fprintln(os.Stderr)
	}

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
			prog.current = e.RelPath
			var herr error
			e.SHA256, e.MD5, herr = hashFile(p)
			if herr != nil {
				e.Err = herr.Error()
			}
		}
		prog.doneItems++
		prog.draw(false)
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
	if _, err := io.Copy(io.MultiWriter(hs, hm, countingWriter{}), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(hs.Sum(nil)), hex.EncodeToString(hm.Sum(nil)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
