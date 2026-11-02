package jsontree

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAgreesWithEncodingJSON(t *testing.T) {
	for _, src := range []string{
		`{}`, `[]`, `""`, `0`, `-0.5e+10`, `true`, `null`, ` {"a" : [1, 2.5, "x"] } `,
		`{"a":"é\n\"q\"","b":{"c":[{"d":null}]}}`,
		`{"big":12345678901234567890,"html":"<a>&</a>"}`,
		`{`, `{"a"}`, `{"a":}`, `[1,]`, `01`, `1.`, `.5`, `1e`, `-`, `"\x"`, "\"a\tb\"", `"\u12"`, `tru`, `{} {}`, `{"a":1,}`,
		`"unterminated`, `[1 2]`, `{"a" 1}`, `nul`, `+1`, `{"a":"\ud800"}`,
	} {
		_, errOurs := Parse([]byte(src))
		errStd := json.Unmarshal([]byte(src), new(any))
		if (errOurs == nil) != (errStd == nil) {
			t.Errorf("%q: ours=%v encoding/json=%v", src, errOurs, errStd)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	deep := strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1)
	if _, err := Parse([]byte(deep)); err == nil {
		t.Fatal("expected nesting past the limit to fail")
	}
}

func TestRewriteKeepsOtherBytes(t *testing.T) {
	src := `{"z":1,"big":12345678901234567890, "html":"<b>&",` + "\n" + `"text":"mail a@b.com","esc":"A\n","list":["keep","swap"]}`
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := doc.Text(doc.Root.Get("text"))
	doc.SetString(doc.Root.Get("text"), strings.Replace(text, "a@b.com", "[EMAIL]", 1))
	doc.SetString(doc.Root.Get("list").Items[1], "<\"new\"\n>")
	want := `{"z":1,"big":12345678901234567890, "html":"<b>&",` + "\n" + `"text":"mail [EMAIL]","esc":"A\n","list":["keep","<\"new\"\n>"]}`
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestTextDecodesEscapes(t *testing.T) {
	doc, err := Parse([]byte(`{"a":"xé😀\"","key":"v"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := doc.Text(doc.Root.Get("a")); got != "xé😀\"" {
		t.Fatalf("text = %q", got)
	}
	if doc.Root.Get("key") == nil {
		t.Fatal("escaped key must decode")
	}
}

func TestAppendStringRoundTrips(t *testing.T) {
	for _, s := range []string{"", "plain", "quote\" back\\slash", "ctl\x00\x01\x1f\n\r\t", "<>&", "é😀", "bad\xffutf8", " "} {
		var got string
		if err := json.Unmarshal(AppendString(nil, s), &got); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		want := strings.ToValidUTF8(s, "�")
		if got != want {
			t.Fatalf("%q round-tripped to %q", s, got)
		}
	}
}

func TestDuplicateKeys(t *testing.T) {
	doc, err := Parse([]byte(`{"a":"first","a":"second"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := doc.Text(doc.Root.Get("a")); got != "second" {
		t.Fatalf("Get must return the last duplicate, got %q", got)
	}
	if n := len(doc.Root.All("a")); n != 2 {
		t.Fatalf("All returned %d values", n)
	}
}
