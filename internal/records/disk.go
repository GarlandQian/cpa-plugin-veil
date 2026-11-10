package records

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// keepBytes is how much the days on disk hold in all; a variable for the
// tests.
var keepBytes int64 = 100 << 20

const (
	// keepDays is how many days of records the disk keeps, today among them.
	keepDays = 30
	dayForm  = "2006-01-02"
	// dirName is the directory the days go in, under the persistent one,
	// which may be the plugin directory other plugins share.
	dirName = "veil-records"
	// lineMax is the longest record a day's file may hold.
	lineMax = 4 << 20
)

func recordsDir(dir string) string {
	return filepath.Join(dir, dirName)
}

// diskState is what a Store knows of its directory; Store.mu guards it.
type diskState struct {
	ready  bool   // the directory exists
	pruned string // the day the days were last pruned
	bytes  int64  // the days' size in all, as of the last prune and since
	aggs   map[string]cachedAgg
}

// cachedAgg is a day's summary as of the size its file had.
type cachedAgg struct {
	size int64
	agg  *agg
}

// dayFile is one day's file.
type dayFile struct {
	day  string
	path string
	size int64
}

// write appends r to its day's file, without its Snips; s.mu is held. A
// failed write loses r on disk only.
func (s *Store) write(r Record) {
	if !s.disk.ready {
		if os.MkdirAll(s.dir, 0o700) != nil {
			return
		}
		s.disk.ready = true
	}
	n := appendRecord(s.dir, r)
	if n == 0 {
		return
	}
	s.disk.bytes += int64(n)
	day := r.Time.Local().Format(dayForm)
	if day != s.disk.pruned || s.disk.bytes > keepBytes {
		s.disk.pruned = day
		s.prune(r.Time)
	}
}

// appendRecord preserves the JSONL format. A patch cannot recreate a day
// removed by Clear or retention, and does not prune an old directory.
func appendRecord(dir string, r Record) int {
	r.Snips = nil
	line, err := json.Marshal(r)
	if err != nil {
		return 0
	}
	line = append(line, '\n')
	flags := os.O_WRONLY | os.O_APPEND
	if !r.Patch {
		flags |= os.O_CREATE
	}
	path := filepath.Join(dir, r.Time.Local().Format(dayForm)+".jsonl")
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return 0
	}
	n, err := f.Write(line)
	if errClose := f.Close(); err == nil {
		err = errClose
	}
	if err != nil {
		return 0
	}
	return n
}

// prune deletes the days older than keepDays, then the oldest days until all
// of them fit in keepBytes; s.mu is held.
func (s *Store) prune(now time.Time) {
	cutoff := now.Local().AddDate(0, 0, 1-keepDays).Format(dayForm)
	var kept []dayFile
	var total int64
	for _, f := range days(s.dir) {
		if f.day < cutoff {
			s.remove(f)
			continue
		}
		kept = append(kept, f)
		total += f.size
	}
	for len(kept) > 0 && total > keepBytes {
		s.remove(kept[0])
		total -= kept[0].size
		kept = kept[1:]
	}
	s.disk.bytes = total
}

func (s *Store) remove(f dayFile) {
	_ = os.Remove(f.path)
	delete(s.disk.aggs, f.day)
}

// clearDisk deletes every day; s.mu is held.
func (s *Store) clearDisk() error {
	if s.dir == "" {
		return nil
	}
	var first error
	for _, f := range days(s.dir) {
		if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	s.disk.aggs = nil
	s.disk.bytes = 0
	return first
}

// days are the day files in dir, the oldest first.
func days(dir string) []dayFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []dayFile
	for _, e := range entries {
		name := e.Name()
		day, ok := strings.CutSuffix(name, ".jsonl")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		if _, err := time.Parse(dayForm, day); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, dayFile{day: day, path: filepath.Join(dir, name), size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].day < out[j].day })
	return out
}

// read calls fn with each record of a day's file, in the order written,
// each with what the patch lines after it add: what its response restored,
// and what later Passes of its request found. A line that does not parse,
// such as one cut short, is skipped.
func read(path string, fn func(Record)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), lineMax)
	var all []Record
	at := map[int64]int{}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if json.Unmarshal(line, &r) != nil {
			continue
		}
		if r.Patch {
			if i, ok := at[r.Key]; ok {
				all[i] = all[i].patched(r)
			}
			continue
		}
		at[r.Key] = len(all)
		all = append(all, r)
	}
	for _, r := range all {
		fn(r)
	}
}
