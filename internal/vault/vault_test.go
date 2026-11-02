package vault

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestPlaceholderIsDeterministicAndScoped(t *testing.T) {
	a := New(testKey, 0)
	p := a.Placeholder("s1", "EMAIL", "a@b.com")
	if !regexp.MustCompile(`^\{\{EMAIL_[a-z2-7]{8}\}\}$`).MatchString(p) {
		t.Fatalf("placeholder %q has the wrong shape", p)
	}
	if again := a.Placeholder("s1", "EMAIL", "a@b.com"); again != p {
		t.Fatalf("same value minted %q then %q", p, again)
	}
	// A fresh vault under the same key, as after a restart, agrees.
	if restarted := New(testKey, 0).Placeholder("s1", "EMAIL", "a@b.com"); restarted != p {
		t.Fatalf("restart changed the placeholder: %q vs %q", p, restarted)
	}
	if other := a.Placeholder("s2", "EMAIL", "a@b.com"); other == p {
		t.Fatal("two Caller scopes share a placeholder")
	}
	if other := a.Placeholder("s1", "SECRET", "a@b.com"); other == p {
		t.Fatal("two Kinds share a placeholder")
	}
	if v, ok := a.Lookup("s1", p); !ok || v != "a@b.com" {
		t.Fatalf("lookup = %q, %v", v, ok)
	}
	if _, ok := a.Lookup("s2", p); ok {
		t.Fatal("a placeholder restored in another Caller scope")
	}
}

func TestCollisionTakesLongerHash(t *testing.T) {
	v := New(testKey, 0)
	p := v.Placeholder("s", "EMAIL", "first@example.com")
	// Plant a different value on the first value's 8-character placeholder,
	// as a 40-bit collision would.
	v.mu.Lock()
	v.entries[slot{"s", p}].value = "planted@example.com"
	v.mu.Unlock()
	long := v.Placeholder("s", "EMAIL", "first@example.com")
	if !regexp.MustCompile(`^\{\{EMAIL_[a-z2-7]{12}\}\}$`).MatchString(long) {
		t.Fatalf("colliding value got %q, want a 12-character hash", long)
	}
	if got, _ := v.Lookup("s", long); got != "first@example.com" {
		t.Fatalf("12-character placeholder restores %q", got)
	}
	if got, _ := v.Lookup("s", p); got != "planted@example.com" {
		t.Fatalf("8-character placeholder now restores %q", got)
	}
}

func TestEvictionKeepsRecentlyUsedHalf(t *testing.T) {
	v := New(testKey, 4)
	old := v.Placeholder("s", "EMAIL", "old-one@example.com")
	kept := v.Placeholder("s", "EMAIL", "kept-one@example.com")
	v.Placeholder("s", "EMAIL", "third-one@example.com")
	v.Placeholder("s", "EMAIL", "fourth-one@example.com")
	v.Lookup("s", kept)
	v.Lookup("s", old)
	v.Placeholder("s", "EMAIL", "fifth-one@example.com") // full: evicts the two least recently used
	if v.Len() != 3 {
		t.Fatalf("len = %d after eviction, want 3", v.Len())
	}
	for _, p := range []string{old, kept} {
		if _, ok := v.Lookup("s", p); !ok {
			t.Fatalf("recently used %s was evicted", p)
		}
	}
	if m := v.KnownMatches("s", "third-one@example.com"); len(m) != 0 {
		t.Fatalf("evicted value is still known: %+v", m)
	}
}

func TestKnownMatches(t *testing.T) {
	v := New(testKey, 0)
	v.Placeholder("s", "SECRET", "hunter2-long-pass")
	v.Placeholder("s", "SECRET", "hunter2-long-password")
	v.Placeholder("s", "PHONE", "short") // below KnownMinLen: never known
	text := "use hunter2-long-password, not hunter2-long-pass; short"
	got := v.KnownMatches("s", text)
	if len(got) != 2 {
		t.Fatalf("matches = %+v", got)
	}
	if text[got[0].Start:got[0].End] != "hunter2-long-password" || text[got[1].Start:got[1].End] != "hunter2-long-pass" {
		t.Fatalf("matches = %q, %q", text[got[0].Start:got[0].End], text[got[1].Start:got[1].End])
	}
	if m := v.KnownMatches("other", text); len(m) != 0 {
		t.Fatalf("known values leaked into another scope: %+v", m)
	}
}

func TestPlaceholderSpans(t *testing.T) {
	v := New(testKey, 0)
	p := v.Placeholder("s", "ID_CARD", "11010519900307743X")
	text := "id " + p + " and {{not one}} and {{EMAIL_abc}}"
	spans := PlaceholderSpans(text)
	if len(spans) != 1 || text[spans[0][0]:spans[0][1]] != p {
		t.Fatalf("spans = %v", spans)
	}
}

func TestScopeOf(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	bearer := ScopeOf(h("Authorization", "Bearer sk-client-1"))
	if bearer == DefaultScope || strings.Contains(bearer, "sk-client-1") {
		t.Fatalf("bearer scope = %q", bearer)
	}
	if got := ScopeOf(h("X-Api-Key", "sk-client-1")); got != bearer {
		t.Fatal("the same key through x-api-key gave another scope")
	}
	if got := ScopeOf(h("X-Goog-Api-Key", "sk-client-1")); got != bearer {
		t.Fatal("the same key through x-goog-api-key gave another scope")
	}
	if ScopeOf(h("Authorization", "Bearer sk-client-2")) == bearer {
		t.Fatal("two keys share a scope")
	}
	if got := ScopeOf(h("Authorization", "Basic abc")); got != DefaultScope {
		t.Fatalf("non-bearer authorization gave scope %q", got)
	}
	if got := ScopeOf(nil); got != DefaultScope {
		t.Fatalf("no headers gave scope %q", got)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	second, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the key changed between loads")
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("a corrupt key file must fail rather than be replaced")
	}
}

func TestStandIns(t *testing.T) {
	v := New(testKey, 0)
	user := v.Placeholder("s", "USERNAME", "garland")
	if !regexp.MustCompile(`^[a-z]{8}$`).MatchString(user) {
		t.Fatalf("user name stand-in %q", user)
	}
	ip := v.Placeholder("s", "IP", "47.100.12.34")
	if !regexp.MustCompile(`^public-ip-[a-z]{8}$`).MatchString(ip) {
		t.Fatalf("IP stand-in %q", ip)
	}
	if again := New(testKey, 0).Placeholder("s", "USERNAME", "garland"); again != user {
		t.Fatal("a stand-in changed across a restart")
	}
	if other := v.Placeholder("t", "USERNAME", "garland"); other == user {
		t.Fatal("two scopes share a stand-in")
	}
	if got, ok := v.Lookup("s", user); !ok || got != "garland" {
		t.Fatalf("lookup = %q %v", got, ok)
	}
	if !v.IsStandIn("s", strings.ToUpper(user)) || v.IsStandIn("t", user) || !v.HasStandIns("s") || v.HasStandIns("u") {
		t.Fatal("stand-in bookkeeping is off")
	}
	if !v.StandInPrefix("s", "PUBLIC-IP-"+ip[10:12]) || v.StandInPrefix("s", "zzzz") {
		t.Fatal("prefix lookup is off")
	}
}

// When every candidate is already another value's, the value goes as a
// Placeholder.
func TestStandInFallsBackToPlaceholder(t *testing.T) {
	v := New(testKey, 0)
	seen := map[string]bool{}
	for i := 0; i <= standInTries; i++ {
		got := v.Placeholder("s", "USERNAME", "garland")
		if strings.HasPrefix(got, "{{") {
			if i != standInTries || !regexp.MustCompile(`^\{\{USERNAME_[a-z2-7]{8}\}\}$`).MatchString(got) {
				t.Fatalf("call %d gave %q", i, got)
			}
			return
		}
		if seen[got] || !regexp.MustCompile(`^[a-z]{8}$`).MatchString(got) {
			t.Fatalf("call %d gave %q again or malformed", i, got)
		}
		seen[got] = true
		// Another value takes this candidate, as a collision would.
		v.mu.Lock()
		v.entries[slot{"s", got}].value = "someone-else"
		v.mu.Unlock()
	}
	t.Fatal("never fell back to a placeholder")
}

// The vault is shared by every request and stream at once.
func TestConcurrentUse(t *testing.T) {
	v := New(testKey, 512)
	done := make(chan struct{})
	for g := 0; g < 16; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			scope := []string{"a", "b"}[g%2]
			for i := 0; i < 300; i++ {
				value := "value-" + strings.Repeat("x", g%3) + string(rune('a'+i%26)) + "-long-enough"
				kind := []string{"EMAIL", "USERNAME", "IP", "SECRET"}[i%4]
				p := v.Placeholder(scope, kind, value)
				if got, ok := v.Lookup(scope, p); ok && got != value {
					t.Errorf("%s restored to %q, want %q", p, got, value)
					return
				}
				v.KnownMatches(scope, "text with "+value+" in it")
				v.IsStandIn(scope, p)
				v.StandInPrefix(scope, "pub")
			}
		}(g)
	}
	for g := 0; g < 16; g++ {
		<-done
	}
	if v.Len() > 512 {
		t.Fatalf("vault grew past its limit: %d", v.Len())
	}
}
