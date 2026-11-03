package records

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func record(caller, kind, placeholder string, at time.Time) Record {
	return Record{
		Time:   at,
		Caller: caller,
		Model:  "m",
		N:      1,
		Values: []Value{{Placeholder: placeholder, Kind: kind, Rule: "r", Head: "a", Len: 9, N: 1, Action: "mask", Paths: []string{"input"}}},
		Snips:  map[string]string{placeholder: "mail " + placeholder},
	}
}

func TestMemoryKeepsTheNewestAndTheirSnips(t *testing.T) {
	s := New()
	now := time.Now()
	for i := 0; i < keepRecords+5; i++ {
		if !s.Add(record("c", "EMAIL", fmt.Sprintf("{{EMAIL_%08d}}", i), now)) {
			t.Fatal("a record was dropped with room to spare")
		}
		if i%100 == 99 {
			s.Flush() // the queue holds fewer than keepRecords
		}
	}
	s.Flush()
	all, more := s.List(0, keepRecords+10, Filter{})
	if len(all) != keepRecords || more {
		t.Fatalf("memory holds %d records, more=%v", len(all), more)
	}
	for i, r := range all {
		if i > 0 && r.Key >= all[i-1].Key {
			t.Fatal("records are not the newest first")
		}
		if (i < keepSnips) != (r.Snips != nil) {
			t.Fatalf("record %d of the newest has snips %v", i, r.Snips)
		}
	}
	if all[0].Values[0].Placeholder != fmt.Sprintf("{{EMAIL_%08d}}", keepRecords+4) {
		t.Fatalf("the newest record is %+v", all[0])
	}
}

func TestAFullQueueDropsAndCounts(t *testing.T) {
	s := &Store{queue: make(chan item, 1), clock: time.Now} // no writer running
	if !s.Add(record("c", "EMAIL", "{{EMAIL_a}}", time.Now())) {
		t.Fatal("the first record was dropped")
	}
	if s.Add(record("c", "EMAIL", "{{EMAIL_b}}", time.Now())) || s.Dropped() != 1 {
		t.Fatalf("a record past the queue was not dropped: %d", s.Dropped())
	}
}

func TestDaysOnDiskWithoutSnips(t *testing.T) {
	dir := t.TempDir()
	s := New()
	s.SetDir(dir)
	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)
	s.Add(record("c", "EMAIL", "{{EMAIL_old}}", yesterday))
	s.Add(record("c", "EMAIL", "{{EMAIL_new}}", today))
	s.Flush()
	for _, d := range []time.Time{yesterday, today} {
		path := filepath.Join(dir, dirName, d.Format(dayForm)+".jsonl")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", path, info.Mode().Perm())
		}
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), "snips") || strings.Contains(string(raw), "mail ") {
			t.Errorf("a day holds snips: %s", raw)
		}
	}
	if !s.Persisted() {
		t.Fatal("a store with a directory says it is not persisted")
	}

	// Past what memory holds, records come from disk.
	s.mu.Lock()
	s.ring = nil
	s.mu.Unlock()
	got, _ := s.List(0, 10, Filter{})
	if len(got) != 2 || got[0].Values[0].Placeholder != "{{EMAIL_new}}" || got[1].Values[0].Placeholder != "{{EMAIL_old}}" {
		t.Fatalf("records from disk = %+v", got)
	}
	if r, ok := s.Get(got[1].Key); !ok || r.Values[0].Placeholder != "{{EMAIL_old}}" {
		t.Fatalf("Get from disk = %+v, %v", r, ok)
	}
}

func TestPruneKeepsThirtyDaysAndTheByteLimit(t *testing.T) {
	dir := t.TempDir()
	days := filepath.Join(dir, dirName)
	if err := os.MkdirAll(days, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := filepath.Join(days, now.AddDate(0, 0, -keepDays).Format(dayForm)+".jsonl")
	recent := filepath.Join(days, now.AddDate(0, 0, -2).Format(dayForm)+".jsonl")
	other := filepath.Join(days, "notes.txt")
	for path, size := range map[string]int{old: 10, recent: 4096, other: 10} {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := keepBytes
	keepBytes = 2048
	t.Cleanup(func() { keepBytes = saved })

	s := New()
	s.SetDir(dir)
	s.Add(record("c", "EMAIL", "{{EMAIL_a}}", now))
	s.Flush()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a day older than keepDays was kept")
	}
	if _, err := os.Stat(recent); !os.IsNotExist(err) {
		t.Error("the oldest day was kept past keepBytes")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("a file that is no day was removed")
	}
	if _, err := os.Stat(filepath.Join(days, now.Format(dayForm)+".jsonl")); err != nil {
		t.Error("today's records were removed")
	}
}

func TestClearDeletesRecordsOnly(t *testing.T) {
	dir := t.TempDir()
	s := New()
	s.SetDir(dir)
	s.Add(record("c", "EMAIL", "{{EMAIL_a}}", time.Now()))
	s.Flush()
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(0, 10, Filter{}); len(got) != 0 {
		t.Fatalf("cleared store lists %v", got)
	}
	if len(days(filepath.Join(dir, dirName))) != 0 {
		t.Fatal("a day survived Clear")
	}
}

func TestMemoryOnlyWithoutADirectory(t *testing.T) {
	s := New()
	s.Add(record("c", "EMAIL", "{{EMAIL_a}}", time.Now()))
	s.Flush()
	if s.Persisted() {
		t.Fatal("a store without a directory says it is persisted")
	}
	if got, _ := s.List(0, 10, Filter{}); len(got) != 1 {
		t.Fatalf("memory lists %d records", len(got))
	}
}

func TestListFiltersAndPages(t *testing.T) {
	s := New()
	now := time.Now()
	stopped := record("", "SECRET", "{{SECRET_s}}", now)
	stopped.Stopped = StoppedBlock
	stopped.Values[0].Action = "block"
	warned := record("b", "PHONE", "{{PHONE_p}}", now)
	warned.Values[0].Action = "warn"
	for _, r := range []Record{record("a", "EMAIL", "{{EMAIL_1}}", now), record("a", "EMAIL", "{{EMAIL_2}}", now), warned, stopped} {
		s.Add(r)
	}
	s.Flush()
	def, a := "", "a"
	for name, tc := range map[string]struct {
		f    Filter
		want int
	}{
		"kind":          {Filter{Kinds: []string{"EMAIL", "PHONE"}}, 3},
		"caller":        {Filter{Caller: &a}, 2},
		"default scope": {Filter{Caller: &def}, 1},
		"action":        {Filter{Action: "warn"}, 1},
		"stopped":       {Filter{Stopped: true}, 1},
		"model":         {Filter{Model: "other"}, 0},
	} {
		if got, _ := s.List(0, 10, tc.f); len(got) != tc.want {
			t.Errorf("%s: %d records, want %d", name, len(got), tc.want)
		}
	}
	first, more := s.List(0, 2, Filter{})
	rest, more2 := s.List(first[1].Key, 2, Filter{})
	if len(first) != 2 || !more || len(rest) != 2 || more2 || rest[0].Key >= first[1].Key {
		t.Fatalf("pages = %d (more %v), %d (more %v)", len(first), more, len(rest), more2)
	}
}

func TestSummary(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		s := New()
		if persisted {
			s.SetDir(t.TempDir())
		}
		now := time.Now()
		r1 := record("a", "EMAIL", "{{EMAIL_1}}", now)
		r1.Values[0].N = 3
		r2 := record("b", "EMAIL", "{{EMAIL_1}}", now)
		r3 := record("a", "PHONE", "{{PHONE_1}}", now.AddDate(0, 0, -1))
		r3.Values[0].Action = "warn"
		r4 := record("a", "SECRET", "{{SECRET_1}}", now.AddDate(0, 0, -10)) // outside 7 days
		r4.Stopped = StoppedBlock
		for _, r := range []Record{r1, r2, r3, r4} {
			s.Add(r)
		}
		s.Flush()
		sum := s.Summary(7)
		if len(sum.Days) != 7 || sum.Days[6].Requests != 2 || sum.Days[5].Requests != 1 {
			t.Fatalf("persisted=%v days = %+v", persisted, sum.Days)
		}
		if sum.Requests != 3 || sum.N != 5 || sum.Distinct != 2 || sum.Warned != 1 || sum.Stopped != 0 || sum.Persisted != persisted {
			t.Errorf("persisted=%v totals = %+v", persisted, sum)
		}
		if len(sum.Kinds) != 2 || sum.Kinds[0].Name != "EMAIL" || sum.Kinds[0].N != 4 || sum.Kinds[0].Requests != 2 || sum.Kinds[0].Distinct != 1 {
			t.Errorf("persisted=%v kinds = %+v", persisted, sum.Kinds)
		}
		if len(sum.Callers) != 2 || sum.Callers[0].Name != "a" || sum.Callers[0].Requests != 2 {
			t.Errorf("persisted=%v callers = %+v", persisted, sum.Callers)
		}
		if len(sum.Values) != 2 || sum.Values[0].Placeholder != "{{EMAIL_1}}" || sum.Values[0].N != 4 || sum.Values[0].Requests != 2 {
			t.Errorf("persisted=%v values = %+v", persisted, sum.Values)
		}
		// A second Summary of the same days reads the cache and agrees.
		again := s.Summary(7)
		a, _ := json.Marshal(sum)
		b, _ := json.Marshal(again)
		if string(a) != string(b) {
			t.Errorf("persisted=%v summaries differ:\n%s\n%s", persisted, a, b)
		}
	}
}

func TestKeysGrowWithinOneMicrosecond(t *testing.T) {
	s := &Store{clock: time.Now}
	at := time.Now()
	a, b := s.nextKey(at), s.nextKey(at)
	if b <= a {
		t.Fatalf("keys %d then %d", a, b)
	}
}
