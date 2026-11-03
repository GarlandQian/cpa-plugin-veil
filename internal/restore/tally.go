package restore

// Tally counts what restoring one response did: by Placeholder or Stand-in,
// the places it was put back, and the Placeholders it held that the Vault
// does not, such as one from provider-held history after a restart. A nil
// Tally counts nothing.
type Tally struct {
	Back       map[string]int
	Unrestored map[string]int
}

func (t *Tally) back(p string) {
	if t == nil {
		return
	}
	if t.Back == nil {
		t.Back = map[string]int{}
	}
	t.Back[p]++
}

func (t *Tally) miss(p string) {
	if t == nil {
		return
	}
	if t.Unrestored == nil {
		t.Unrestored = map[string]int{}
	}
	t.Unrestored[p]++
}

// Add adds o's counts to t.
func (t *Tally) Add(o *Tally) {
	if t == nil || o == nil {
		return
	}
	for p, n := range o.Back {
		if t.Back == nil {
			t.Back = map[string]int{}
		}
		t.Back[p] += n
	}
	for p, n := range o.Unrestored {
		if t.Unrestored == nil {
			t.Unrestored = map[string]int{}
		}
		t.Unrestored[p] += n
	}
}
