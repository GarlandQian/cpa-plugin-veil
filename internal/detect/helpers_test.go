package detect

import (
	"os"
	"strings"
)

// gitleaksRules is the rule file the plugin embeds.
const gitleaksRules = "../../rules/gitleaks.toml"

// newFromPath builds a Detector from a rule file; an empty path uses the
// built-in rules.
func newFromPath(path string) (*Detector, error) {
	if path == "" {
		return New(nil, Options{})
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return New(raw, Options{})
}

// redaction is what the tests inherited from privacy-filter assert on: the
// text with each hit replaced by a label, as that library rendered it.
type redaction struct {
	Redacted string
	Hit      bool
	Count    int
}

// testLabels are privacy-filter's labels; a password and a private key were
// secrets there.
var testLabels = map[Kind]string{
	KindEmail:      "[EMAIL]",
	KindPhone:      "[PHONE]",
	KindIDCard:     "[ID]",
	KindBankCard:   "[BANK_CARD]",
	KindIP:         "[IP]",
	KindSecret:     "[SECRET]",
	KindPassword:   "[SECRET]",
	KindPrivateKey: "[SECRET]",
}

func label(kind Kind) string {
	if l, ok := testLabels[kind]; ok {
		return l
	}
	return "[" + string(kind) + "]"
}

func (d *Detector) Redact(text string) redaction {
	hits := d.Detect(text)
	if len(hits) == 0 {
		return redaction{Redacted: text}
	}
	var b strings.Builder
	prev := 0
	for _, h := range hits {
		b.WriteString(text[prev:h.Start])
		b.WriteString(label(h.Kind))
		prev = h.End
	}
	b.WriteString(text[prev:])
	return redaction{Redacted: b.String(), Hit: true, Count: len(hits)}
}

func mustRead(t interface{ Fatal(...any) }, path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
