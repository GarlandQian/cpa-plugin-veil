package detect

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// containsAnyKeyword is the prefilter the keyword index replaced: lower the
// whole text, then look for each keyword in turn.
func containsAnyKeyword(r *secretRule, lowText string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, kw := range r.keywords {
		if strings.Contains(lowText, kw) {
			return true
		}
	}
	return false
}

func TestKeywordIndexMatchesContains(t *testing.T) {
	d, err := newFromPath(gitleaksRules)
	if err != nil {
		t.Fatal(err)
	}
	rules := d.secrets.rules
	var texts []string
	for _, gen := range []func() []bulkCase{genRealSecrets, genCloudSecrets, genConfigFragments, genCodeSnippets, genLogLines, genCommandLines, genAdversarial, genMultilingual} {
		for _, c := range gen() {
			texts = append(texts, c.input, strings.ToUpper(c.input))
		}
	}
	// Every keyword alone, upper-cased, at the end of a text, and split by a
	// byte that breaks it.
	for _, r := range rules {
		for _, kw := range r.keywords {
			texts = append(texts, kw, strings.ToUpper(kw), "xx"+kw, kw[:len(kw)/2]+"\x00"+kw[len(kw)/2:])
		}
	}
	random := rand.New(rand.NewSource(1))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:=/ 密码"
	for i := 0; i < 2000; i++ {
		b := make([]byte, random.Intn(64))
		for j := range b {
			b[j] = alphabet[random.Intn(len(alphabet))]
		}
		texts = append(texts, string(b))
	}

	for _, text := range texts {
		got := d.secrets.keywords.scan(text)
		low := strings.ToLower(text)
		want := make([]bool, len(rules))
		for i := range rules {
			want[i] = containsAnyKeyword(&rules[i], low)
		}
		if !reflect.DeepEqual(got, want) {
			for i := range rules {
				if got[i] != want[i] {
					t.Fatalf("text %q rule %s: index says %v, Contains says %v", text, rules[i].id, got[i], want[i])
				}
			}
		}
	}
}

func TestDetectCacheReturnsCopies(t *testing.T) {
	d, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("plain words ", 30) + "mail me at someone@example.com"
	first := d.Detect(text)
	if len(first) != 1 || first[0].Kind != KindEmail {
		t.Fatalf("hits = %+v", first)
	}
	first[0].Kind = KindSecret
	second := d.Detect(text)
	if len(second) != 1 || second[0].Kind != KindEmail {
		t.Fatalf("cache returned a mutated entry: %+v", second)
	}
}
