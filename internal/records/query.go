package records

import (
	"math"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// Filter picks records; a zero Filter picks every one.
type Filter struct {
	Kinds  []string // a record with a value of any of them
	Caller *string  // of this Caller scope; "" is the Default scope
	Model  string
	Action string // a record with a value under this Action
	// Stopped picks only the requests that did not reach the upstream.
	Stopped bool
}

func (f Filter) match(r Record) bool {
	if f.Caller != nil && r.Caller != *f.Caller {
		return false
	}
	if f.Model != "" && r.Model != f.Model {
		return false
	}
	if f.Stopped && r.Stopped == "" {
		return false
	}
	if len(f.Kinds) == 0 && f.Action == "" {
		return true
	}
	for _, v := range r.Values {
		if (len(f.Kinds) == 0 || slices.Contains(f.Kinds, v.Kind)) && (f.Action == "" || v.Action == f.Action) {
			return true
		}
	}
	return false
}

// snapshot returns a copy of what memory holds and the directory.
func (s *Store) snapshot() ([]Record, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.ring...), s.dir
}

// List returns up to limit records that f picks, the newest first, all with
// a Key below before (0: from the newest), and whether more are left.
// Records older than memory holds come from disk, without Snips.
func (s *Store) List(before int64, limit int, f Filter) ([]Record, bool) {
	if limit <= 0 {
		limit = 50
	}
	if before <= 0 {
		before = math.MaxInt64
	}
	ring, dir := s.snapshot()
	var out []Record
	oldest := before
	for i := len(ring) - 1; i >= 0; i-- {
		r := ring[i]
		oldest = min(oldest, r.Key)
		if r.Key >= before || !f.match(r) {
			continue
		}
		if len(out) == limit {
			return out, true
		}
		out = append(out, r)
	}
	if dir == "" {
		return out, false
	}
	// What memory no longer holds, older than all it does.
	all := days(dir)
	for i := len(all) - 1; i >= 0; i-- {
		var day []Record
		read(all[i].path, func(r Record) {
			if r.Key < oldest && f.match(r) {
				day = append(day, r)
			}
		})
		for j := len(day) - 1; j >= 0; j-- {
			if len(out) == limit {
				return out, true
			}
			out = append(out, day[j])
		}
	}
	return out, false
}

// Get returns the record with key.
func (s *Store) Get(key int64) (Record, bool) {
	ring, dir := s.snapshot()
	for i := len(ring) - 1; i >= 0; i-- {
		if ring[i].Key == key {
			return ring[i], true
		}
	}
	if dir == "" {
		return Record{}, false
	}
	t := time.UnixMicro(key).Local()
	for _, d := range []time.Time{t, t.AddDate(0, 0, -1), t.AddDate(0, 0, 1)} {
		var found Record
		ok := false
		read(filepath.Join(dir, d.Format(dayForm)+".jsonl"), func(r Record) {
			if r.Key == key {
				found, ok = r, true
			}
		})
		if ok {
			return found, true
		}
	}
	return Record{}, false
}

// Day is one day's count.
type Day struct {
	Day      string `json:"day"`
	Requests int    `json:"requests"`
	N        int    `json:"n"`        // places, each counted
	Distinct int    `json:"distinct"` // different values
	Warned   int    `json:"warned"`   // places sent as written
	Stopped  int    `json:"stopped"`  // requests that did not reach the upstream
	// Restored is the places responses had restored, and Unrestored the
	// Placeholders they held that could not be.
	Restored   int `json:"restored"`
	Unrestored int `json:"unrestored"`
}

// Count is one Kind's, caller's, model's or rule's share.
type Count struct {
	Name     string `json:"name"`
	Requests int    `json:"requests"`
	N        int    `json:"n"`
	Distinct int    `json:"distinct"`
}

// Seen is one different value, told as a record tells it.
type Seen struct {
	Placeholder string    `json:"p"`
	Kind        string    `json:"kind"`
	Rule        string    `json:"rule,omitempty"`
	Head        string    `json:"head,omitempty"`
	Len         int       `json:"len"`
	N           int       `json:"n"`
	Requests    int       `json:"requests"`
	Last        time.Time `json:"last"`
}

// Summary is what masking did over some days.
type Summary struct {
	Days       []Day   `json:"days"` // the oldest first, every day of them
	Requests   int     `json:"requests"`
	N          int     `json:"n"`
	Distinct   int     `json:"distinct"`
	Warned     int     `json:"warned"`
	Stopped    int     `json:"stopped"`
	Restored   int     `json:"restored"`
	Unrestored int     `json:"unrestored"`
	Kinds      []Count `json:"kinds"`
	Callers    []Count `json:"callers"`
	Models     []Count `json:"models"`
	Rules      []Count `json:"rules"`
	Values     []Seen  `json:"values"` // the most masked first, at most topValues
	Dropped    int64   `json:"dropped"`
	Persisted  bool    `json:"persisted"`
}

// topValues is how many values a Summary lists.
const topValues = 60

// agg adds records up.
type agg struct {
	day      Day
	distinct map[string]bool
	kinds    map[string]*share
	callers  map[string]*share
	models   map[string]*share
	rules    map[string]*share
	values   map[string]*Seen
}

type share struct {
	requests, n int
	distinct    map[string]bool
}

func newAgg(day string) *agg {
	return &agg{
		day:      Day{Day: day},
		distinct: map[string]bool{},
		kinds:    map[string]*share{},
		callers:  map[string]*share{},
		models:   map[string]*share{},
		rules:    map[string]*share{},
		values:   map[string]*Seen{},
	}
}

func (a *agg) add(r Record) {
	a.day.Requests++
	if r.Stopped != "" {
		a.day.Stopped++
	}
	if r.Restored != nil {
		for _, n := range r.Restored.Back {
			a.day.Restored += n
		}
		for _, n := range r.Restored.Unrestored {
			a.day.Unrestored += n
		}
	}
	seenKinds, seenRules := map[string]bool{}, map[string]bool{}
	for _, v := range r.Values {
		a.day.N += v.N
		if v.Action == "warn" {
			a.day.Warned += v.N
		}
		a.distinct[v.Placeholder] = true
		tallyShare(a.kinds, v.Kind, v, !seenKinds[v.Kind])
		seenKinds[v.Kind] = true
		tallyShare(a.rules, v.Rule, v, !seenRules[v.Rule])
		seenRules[v.Rule] = true
		seen := a.values[v.Placeholder]
		if seen == nil {
			seen = &Seen{Placeholder: v.Placeholder, Kind: v.Kind, Rule: v.Rule, Head: v.Head, Len: v.Len}
			a.values[v.Placeholder] = seen
		}
		seen.N += v.N
		seen.Requests++
		if r.Time.After(seen.Last) {
			seen.Last = r.Time
		}
	}
	for _, m := range []struct {
		to   map[string]*share
		name string
	}{{a.callers, r.Caller}, {a.models, r.Model}} {
		sh := m.to[m.name]
		if sh == nil {
			sh = &share{distinct: map[string]bool{}}
			m.to[m.name] = sh
		}
		sh.requests++
		for _, v := range r.Values {
			sh.n += v.N
			sh.distinct[v.Placeholder] = true
		}
	}
	a.day.Distinct = len(a.distinct)
}

func tallyShare(to map[string]*share, name string, v Value, newRequest bool) {
	sh := to[name]
	if sh == nil {
		sh = &share{distinct: map[string]bool{}}
		to[name] = sh
	}
	if newRequest {
		sh.requests++
	}
	sh.n += v.N
	sh.distinct[v.Placeholder] = true
}

// merge adds b into a.
func (a *agg) merge(b *agg) {
	a.day.Requests += b.day.Requests
	a.day.N += b.day.N
	a.day.Warned += b.day.Warned
	a.day.Stopped += b.day.Stopped
	a.day.Restored += b.day.Restored
	a.day.Unrestored += b.day.Unrestored
	for p := range b.distinct {
		a.distinct[p] = true
	}
	a.day.Distinct = len(a.distinct)
	for _, m := range [][2]map[string]*share{{a.kinds, b.kinds}, {a.callers, b.callers}, {a.models, b.models}, {a.rules, b.rules}} {
		for name, from := range m[1] {
			to := m[0][name]
			if to == nil {
				to = &share{distinct: map[string]bool{}}
				m[0][name] = to
			}
			to.requests += from.requests
			to.n += from.n
			for p := range from.distinct {
				to.distinct[p] = true
			}
		}
	}
	for p, from := range b.values {
		to := a.values[p]
		if to == nil {
			c := *from
			a.values[p] = &c
			continue
		}
		to.N += from.N
		to.Requests += from.Requests
		if from.Last.After(to.Last) {
			to.Last = from.Last
		}
	}
}

// Summary sums up the records of the last days days, today among them.
func (s *Store) Summary(days int) Summary {
	if days <= 0 {
		days = 7
	}
	today := s.clock().Local()
	names := make([]string, days)
	for i := range names {
		names[i] = today.AddDate(0, 0, i-days+1).Format(dayForm)
	}
	perDay := s.dayAggs(names)
	total := newAgg("")
	out := Summary{Dropped: s.Dropped(), Persisted: s.Persisted()}
	for _, name := range names {
		a := perDay[name]
		if a == nil {
			out.Days = append(out.Days, Day{Day: name})
			continue
		}
		out.Days = append(out.Days, a.day)
		total.merge(a)
	}
	out.Requests, out.N, out.Distinct = total.day.Requests, total.day.N, total.day.Distinct
	out.Warned, out.Stopped = total.day.Warned, total.day.Stopped
	out.Restored, out.Unrestored = total.day.Restored, total.day.Unrestored
	out.Kinds = counts(total.kinds)
	out.Callers = counts(total.callers)
	out.Models = counts(total.models)
	out.Rules = counts(total.rules)
	for _, v := range total.values {
		out.Values = append(out.Values, *v)
	}
	sort.Slice(out.Values, func(i, j int) bool {
		a, b := out.Values[i], out.Values[j]
		if a.N != b.N {
			return a.N > b.N
		}
		return a.Placeholder < b.Placeholder
	})
	if len(out.Values) > topValues {
		out.Values = out.Values[:topValues]
	}
	return out
}

// dayAggs sums up each of the days named: from disk where the records go
// there, caching a day for as long as its file keeps its size, else from
// memory.
func (s *Store) dayAggs(names []string) map[string]*agg {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string]*agg{}
	s.mu.Lock()
	dir := s.dir
	if dir == "" {
		ring := append([]Record(nil), s.ring...)
		s.mu.Unlock()
		for _, r := range ring {
			day := r.Time.Local().Format(dayForm)
			if !want[day] {
				continue
			}
			if out[day] == nil {
				out[day] = newAgg(day)
			}
			out[day].add(r)
		}
		return out
	}
	revision := s.revision
	cache := make(map[string]cachedAgg, len(s.disk.aggs))
	for day, c := range s.disk.aggs {
		cache[day] = c
	}
	s.mu.Unlock()
	fresh := map[string]cachedAgg{}
	for _, f := range days(dir) {
		if !want[f.day] {
			continue
		}
		if c, ok := cache[f.day]; ok && c.size == f.size {
			out[f.day] = c.agg
			fresh[f.day] = c
			continue
		}
		a := newAgg(f.day)
		read(f.path, a.add)
		out[f.day] = a
		fresh[f.day] = cachedAgg{size: f.size, agg: a}
	}
	s.mu.Lock()
	if s.dir == dir && s.revision == revision {
		if s.disk.aggs == nil {
			s.disk.aggs = map[string]cachedAgg{}
		}
		for day, c := range fresh {
			s.disk.aggs[day] = c
		}
	}
	s.mu.Unlock()
	return out
}

func counts(m map[string]*share) []Count {
	out := make([]Count, 0, len(m))
	for name, sh := range m {
		out = append(out, Count{Name: name, Requests: sh.requests, N: sh.n, Distinct: len(sh.distinct)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Name < out[j].Name
	})
	return out
}
