// hashvalidate walks a directory tree and lists every file and folder in
// hash_validation.csv, flagging names that appear more than once. With -hash
// it also records SHA-256 and MD5 for each entry.
//
// Usage: go run . [-hash] <root-dir> [output.csv]
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
	"flag"
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

// doHash is set by the -hash flag. By default only names are collected.
var doHash bool

// compareMode is set by the -compare flag.
var compareMode bool

// inventoryMode is set by the -inventory flag.
var inventoryMode bool

// bundlesMode is set by the -bundles flag.
var bundlesMode bool

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
	if !doHash {
		fmt.Fprintf(os.Stderr, "\r[%5.1f%%] %d/%d items | %-40s", pct, p.doneItems, p.totalItems, name)
		return
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
func scan(root string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		if skipPaths[p] || isZip(d.Name()) || d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		prog.totalItems++
		if d.IsDir() && isTarGz(d.Name()) {
			return filepath.SkipDir
		}
		if doHash && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				prog.totalBytes += fi.Size()
			}
		}
		return nil
	})
}

type entry struct {
	Type   string // "file" or "folder"
	Name   string
	Dir    string // absolute path of the directory containing the entry
	SHA256 string
	MD5    string
	Err    string
}

// skipPaths holds the report files so they never list themselves.
var skipPaths = map[string]bool{}

func isZip(name string) bool   { return strings.HasSuffix(strings.ToLower(name), ".zip") }
func isTarGz(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".tar.gz") }

func main() {
	flag.BoolVar(&doHash, "hash", false, "also compute SHA-256 and MD5 (for -inventory: of every file inside the zips)")
	flag.BoolVar(&compareMode, "compare", false, "check that the .log/.tar.gz files in dirA exist anywhere under dirB")
	flag.BoolVar(&inventoryMode, "inventory", false, "list the files inside every .zip under a directory")
	flag.BoolVar(&bundlesMode, "bundles", false, "hash each folder directly under a directory as one unit (one row per folder)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: hashvalidate [-hash] <root-dir> [output-dir]")
		fmt.Fprintln(os.Stderr, "       hashvalidate -compare <dirA> <dirB> [output-dir]")
		fmt.Fprintln(os.Stderr, "       hashvalidate -inventory [-hash] <dir> [output-dir]")
		fmt.Fprintln(os.Stderr, "       hashvalidate -bundles <dir> [output-dir]")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if bundlesMode {
		if len(args) < 1 {
			flag.Usage()
			os.Exit(2)
		}
		outDir := "."
		if len(args) > 1 {
			outDir = args[1]
		}
		runBundles(args[0], outDir)
		return
	}
	if inventoryMode {
		if len(args) < 1 {
			flag.Usage()
			os.Exit(2)
		}
		outDir := "."
		if len(args) > 1 {
			outDir = args[1]
		}
		runInventory(args[0], outDir)
		return
	}
	if compareMode {
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		outDir := "."
		if len(args) > 2 {
			outDir = args[2]
		}
		runCompare(args[0], args[1], outDir)
		return
	}
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	root, err := filepath.Abs(args[0])
	if err != nil {
		fatal(err)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fatal(fmt.Errorf("%s is not a readable directory", root))
	}
	outDir := "."
	if len(args) > 1 {
		outDir = args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}
	allPath := filepath.Join(outDir, "all_files.csv")
	dupPath := filepath.Join(outDir, "duplicate_files.csv")
	for _, rp := range []string{allPath, dupPath} {
		if a, err := filepath.Abs(rp); err == nil {
			skipPaths[a] = true
		}
	}

	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		prog.enabled = true
		fmt.Fprintln(os.Stderr, "Scanning...")
	}
	scan(root)

	var entries []*entry
	walk(root, &entries)
	prog.current = "done"
	prog.draw(true)
	if prog.enabled {
		fmt.Fprintln(os.Stderr)
	}

	// Report 1: every file (and folder) with the directory it lives in.
	header := []string{"Type", "Name", "Directory"}
	if doHash {
		header = append(header, "SHA256", "MD5")
	}
	header = append(header, "Error")
	var rows [][]string
	for _, e := range entries {
		row := []string{e.Type, e.Name, e.Dir}
		if doHash {
			row = append(row, e.SHA256, e.MD5)
		}
		rows = append(rows, append(row, e.Err))
	}
	writeCSV(allPath, header, rows)

	// Report 2: every occurrence of a duplicated name on its own line.
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Type+"\x00"+e.Name]++
	}
	var dups []*entry
	for _, e := range entries {
		if counts[e.Type+"\x00"+e.Name] > 1 {
			dups = append(dups, e)
		}
	}
	sort.SliceStable(dups, func(i, j int) bool {
		a, b := dups[i], dups[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Dir < b.Dir
	})
	var dupRows [][]string
	for _, e := range dups {
		dupRows = append(dupRows, []string{e.Type, e.Name, e.Dir, fmt.Sprint(counts[e.Type+"\x00"+e.Name])})
	}
	writeCSV(dupPath, []string{"Type", "Name", "Directory", "TimesFound"}, dupRows)

	fmt.Printf("Wrote %d entries to %s\n", len(entries), allPath)
	fmt.Printf("Wrote %d duplicate entries to %s\n", len(dups), dupPath)
}

func writeCSV(path string, header []string, rows [][]string) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write(header)
	w.WriteAll(rows)
	w.Flush()
	if err := w.Error(); err != nil {
		fatal(err)
	}
}

// walk records every file and folder under dir (pre-order) and returns dir's
// own SHA-256 and MD5, computed from its children.
func walk(dir string, out *[]*entry) (sha, md string, err error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })

	var shaLines, mdLines strings.Builder
	for _, de := range des {
		p := filepath.Join(dir, de.Name())
		if skipPaths[p] || isZip(de.Name()) || de.Type()&os.ModeSymlink != 0 {
			continue
		}
		e := &entry{Name: de.Name(), Dir: dir}
		*out = append(*out, e)

		if de.IsDir() && isTarGz(de.Name()) {
			// Treated as a plain file: record the name, never look inside.
			e.Type = "file"
		} else if de.IsDir() {
			e.Type = "folder"
			var werr error
			e.SHA256, e.MD5, werr = walk(p, out)
			if !doHash {
				e.SHA256, e.MD5 = "", ""
			}
			if werr != nil {
				e.Err = werr.Error()
			}
		} else if !doHash {
			e.Type = "file"
			prog.current = p
		} else {
			e.Type = "file"
			prog.current = p
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
