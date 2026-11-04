package records

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Hold the writer at an I/O boundary without adding a production test hook.
// Assertions below use the Store interface, including its on-disk view.
func holdWriter(s *Store) func() {
	entered, resume := make(chan struct{}), make(chan struct{})
	s.intake.Lock()
	s.queue <- item{control: func() error { close(entered); <-resume; return nil }, done: make(chan error, 1)}
	s.intake.Unlock()
	<-entered
	return sync.OnceFunc(func() { close(resume) })
}

func TestClearOrdersQueuedRecordsAndLateRestores(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		s := New()
		defer s.Close()
		s.SetDir(dir)
		release := holdWriter(s)
		defer release()
		old, ok := s.Add(record("c", "EMAIL", "{{EMAIL_old}}", time.Now()))
		if !ok {
			t.Fatal("old record rejected")
		}
		s.Restore(old, map[string]int{"{{EMAIL_old}}": 1}, nil)
		cleared := make(chan error, 1)
		go func() { cleared <- s.Clear() }()
		synctest.Wait() // Clear is queued behind the blocked writer.
		fresh, ok := s.Add(record("c", "EMAIL", "{{EMAIL_new}}", time.Now()))
		if !ok {
			t.Fatal("new record rejected")
		}
		s.Restore(old, map[string]int{"{{EMAIL_old}}": 2}, nil)
		s.Restore(fresh, map[string]int{"{{EMAIL_new}}": 3}, nil)
		release()
		if err := <-cleared; err != nil {
			t.Fatal(err)
		}
		s.Flush()
		all, _ := s.List(0, 10, Filter{})
		if len(all) != 1 || all[0].Key != fresh.Key || all[0].Restored.Back["{{EMAIL_new}}"] != 3 {
			t.Fatalf("after clear: %+v", all)
		}
		assertNoPatch(t, dir, old)
		if sum := s.Summary(1); sum.Requests != 1 || sum.Restored != 3 {
			t.Fatalf("summary after clear: %+v", sum)
		}
	})
}

func TestSwitchOrdersQueuedRecordsAndLateRestores(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldDir, newDir := t.TempDir(), t.TempDir()
		s := New()
		defer s.Close()
		s.SetDir(oldDir)
		release := holdWriter(s)
		defer release()
		// Record time can differ from its monotonic Key, including crossing a day.
		s.Add(record("c", "EMAIL", "{{EMAIL_first}}", time.Now()))
		old, _ := s.Add(record("c", "EMAIL", "{{EMAIL_old}}", time.Now().AddDate(0, 0, -1)))
		switched := make(chan struct{})
		go func() { s.SetDir(newDir); close(switched) }()
		synctest.Wait()
		fresh, ok := s.Add(record("c", "EMAIL", "{{EMAIL_new}}", time.Now()))
		if !ok {
			t.Fatal("new record rejected")
		}
		release()
		<-switched
		// Retention in the previous directory must not run for a late response.
		marker := filepath.Join(recordsDir(oldDir), "1990-01-01.jsonl")
		if err := os.WriteFile(marker, []byte("\n"), 0600); err != nil {
			t.Fatal(err)
		}
		s.Restore(old, map[string]int{"{{EMAIL_old}}": 2}, nil)
		s.Restore(fresh, map[string]int{"{{EMAIL_new}}": 1}, nil)
		s.Flush()
		all, _ := s.List(0, 10, Filter{})
		if len(all) != 1 || all[0].Key != fresh.Key || all[0].Restored.Back["{{EMAIL_new}}"] != 1 {
			t.Fatalf("current view: %+v", all)
		}
		if _, ok := s.Get(old.Key); ok {
			t.Fatal("old record entered current view")
		}
		if sum := s.Summary(2); sum.Requests != 1 || sum.Restored != 1 {
			t.Fatalf("current summary: %+v", sum)
		}
		disk := New()
		defer disk.Close()
		disk.SetDir(oldDir)
		r, ok := disk.Get(old.Key)
		if !ok || r.Restored == nil || r.Restored.Back["{{EMAIL_old}}"] != 2 {
			t.Fatalf("old directory lost late tally: %+v", r)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("late tally pruned old files:", err)
		}
	})
}

func assertNoPatch(t *testing.T, dir string, ref Ref) {
	t.Helper()
	for _, f := range days(recordsDir(dir)) {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), fmt.Sprintf(`"key":%d`, ref.Key)) {
			t.Fatalf("cleared record reappeared in %s", f.path)
		}
	}
}

func TestClearInvalidatesRefsAcrossDirectoryRevisits(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := New()
	defer s.Close()
	s.SetDir(a)
	old, _ := s.Add(record("c", "EMAIL", "{{EMAIL_old}}", time.Now()))
	s.SetDir(b)
	other, _ := s.Add(record("c", "EMAIL", "{{EMAIL_other}}", time.Now()))
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	s.Restore(old, map[string]int{"{{EMAIL_old}}": 1}, nil)
	s.SetDir(a)
	r, ok := s.Get(old.Key)
	if !ok || r.Restored == nil || r.Restored.Back["{{EMAIL_old}}"] != 1 {
		t.Fatal("clearing another directory discarded an old response")
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	// A new day file must not let a stale Ref append an orphan patch.
	s.Add(record("c", "EMAIL", "{{EMAIL_new}}", time.Now()))
	s.SetDir(b)
	s.Restore(old, map[string]int{"{{EMAIL_old}}": 2}, nil)
	s.Restore(other, map[string]int{"{{EMAIL_other}}": 2}, nil)
	s.Flush()
	assertNoPatch(t, a, old)
	assertNoPatch(t, b, other)
}

func TestCloseDrainsAFullQueueAndRejectsNewRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New()
		release := holdWriter(s)
		defer release()
		for n := 0; n < queueLen; n++ {
			if _, ok := s.Add(record("c", "EMAIL", "{{EMAIL_old}}", time.Now())); !ok {
				t.Fatal("queue filled early")
			}
		}
		if _, ok := s.Add(Record{}); ok || s.Dropped() != 1 {
			t.Fatal("full queue did not drop and count")
		}
		closed := make(chan struct{})
		go func() { s.Close(); close(closed) }()
		synctest.Wait()
		if _, ok := s.Add(Record{}); ok {
			t.Fatal("Close admitted a new record")
		}
		release()
		<-closed
		s.Close()
		s.Flush()
		all, _ := s.List(0, queueLen+1, Filter{})
		if len(all) != queueLen {
			t.Fatalf("close kept %d/%d records", len(all), queueLen)
		}
		select {
		case <-s.finished:
		default:
			t.Fatal("writer survived Close")
		}
	})
}

func TestDrainKeepsFinalTalliesWhenTheQueueIsFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New()
		defer s.Close()
		release := holdWriter(s)
		defer release()
		ref, _ := s.Add(record("c", "EMAIL", "{{EMAIL_a}}", time.Now()))
		for n := 1; n < queueLen; n++ {
			s.Add(Record{})
		}
		s.BeginDrain()
		done := make(chan struct{})
		go func() {
			for n := 0; n < 3; n++ {
				s.Restore(ref, map[string]int{"{{EMAIL_a}}": 1}, nil)
			}
			close(done)
		}()
		synctest.Wait()
		release()
		<-done
		s.Close()
		r, ok := s.Get(ref.Key)
		if !ok || r.Restored == nil || r.Restored.Back["{{EMAIL_a}}"] != 3 || s.Dropped() != 0 {
			t.Fatalf("final tallies lost: %+v, dropped %d", r.Restored, s.Dropped())
		}
	})
}
