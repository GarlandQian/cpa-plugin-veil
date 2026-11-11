package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const recordedEmail = "test@acme-corp.cn"

func recordsOf(t *testing.T, i *veilPlugin) []records.Record {
	t.Helper()
	p := i
	if p.records == nil {
		return nil
	}
	p.records.Flush()
	got, _ := p.records.List(0, 100, records.Filter{})
	return got
}

func TestARequestWithValuesLeavesARecordWithoutThem(t *testing.T) {
	i := newConfiguredInterceptor(t, "actions:\n  PHONE: warn\n")
	req := abiRequestInterceptRequest{
		RequestID:    newRequestID(),
		Model:        "gpt-test",
		SourceFormat: "openai",
		Headers:      bearer("client-a"),
		Body:         []byte(`{"messages":[{"role":"user","content":"mail ` + recordedEmail + `, 我的手机号是 13800138000"}]}`),
	}
	masked := intercept(t, i, req)
	got := recordsOf(t, i)
	if len(got) != 1 {
		t.Fatalf("%d records", len(got))
	}
	r := got[0]
	if r.Caller != vault.ScopeOf(req.Headers) || r.Model != "gpt-test" || r.Format != "openai" || r.Stopped != "" || r.N != 2 || len(r.Values) != 2 {
		t.Fatalf("record = %+v", r)
	}
	for _, v := range r.Values {
		switch v.Kind {
		case "EMAIL":
			if v.Action != "mask" || !strings.Contains(string(masked), v.Placeholder) || !v.New || r.Snips[v.Placeholder] == "" {
				t.Errorf("email = %+v, snip %q", v, r.Snips[v.Placeholder])
			}
		case "PHONE":
			if v.Action != "warn" {
				t.Errorf("phone = %+v", v)
			}
		}
	}
	told, _ := json.Marshal(r)
	for _, original := range []string{recordedEmail, "13800138000"} {
		if strings.Contains(string(told), original) {
			t.Fatalf("the record holds %q: %s", original, told)
		}
	}

	// The after-auth pass of the same request leaves no second record.
	interceptAfter(t, i, abiRequestInterceptRequest{RequestID: req.RequestID, Headers: req.Headers, Body: masked})
	if n := len(recordsOf(t, i)); n != 1 {
		t.Fatalf("after-auth left %d records", n)
	}
}

func TestCleanRequestsLeaveNoRecord(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	intercept(t, i, abiRequestInterceptRequest{Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)})
	if n := len(recordsOf(t, i)); n != 0 {
		t.Fatalf("a clean request left %d records", n)
	}
}

func TestRecordsCanBeTurnedOff(t *testing.T) {
	i := newConfiguredInterceptor(t, "records: false\n")
	intercept(t, i, abiRequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	if i.records != nil {
		t.Fatal("records: false still keeps records")
	}
}

func TestStoppedRequestsAreRecorded(t *testing.T) {
	i := newConfiguredInterceptor(t, "actions:\n  EMAIL: block\n")
	intercept(t, i, abiRequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	intercept(t, i, abiRequestInterceptRequest{Body: []byte(`{"input": "cut short`)})
	got := recordsOf(t, i)
	if len(got) != 2 || got[0].Stopped != records.StoppedMalformed || got[1].Stopped != records.StoppedBlock {
		t.Fatalf("records = %+v", got)
	}
	if v := got[1].Values; len(v) != 1 || v[0].Action != "block" || len(got[1].Snips) != 0 {
		t.Fatalf("blocked record values = %+v, snips %v", v, got[1].Snips)
	}
}

func TestClearingRecordsKeepsRestoring(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	masked := intercept(t, i, abiRequestInterceptRequest{Headers: bearer("k"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	p := i
	recordsOf(t, i)
	if err := p.records.Clear(); err != nil {
		t.Fatal(err)
	}
	placeholder := emailPlaceholder.FindString(string(masked))
	out := restore.New(p.vault).Body(vault.ScopeOf(bearer("k")), []byte(`{"output_text":"sent to `+placeholder+`"}`))
	if !strings.Contains(string(out), recordedEmail) {
		t.Fatalf("restoring stopped after Clear: %s", out)
	}
}

func TestRecordsOnDiskHoldNoValues(t *testing.T) {
	dir := t.TempDir()
	i := buildInterceptor(t, dir, "")
	p := i
	intercept(t, i, abiRequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	p.records.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "veil-records", "*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("days on disk: %v", files)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("day file mode %v, %v", info.Mode().Perm(), err)
	}
	raw, _ := os.ReadFile(files[0])
	if strings.Contains(string(raw), recordedEmail) || strings.Contains(string(raw), "snips") || !strings.Contains(string(raw), `"kind":"EMAIL"`) {
		t.Fatalf("day file = %s", raw)
	}
}

func TestResponsesAddWhatTheyRestoredToTheRecord(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	h := hostOf(t, i)
	r := h.send("k", `{"input":"mail `+recordedEmail+`"}`)
	placeholder := emailPlaceholder.FindString(string(r.upstream))
	gone := "{{EMAIL_aaaaaaaa}}"
	if resp := h.respond(r, `{"output_text":"sent to `+placeholder+`, not `+gone+`"}`); !strings.Contains(resp, recordedEmail) {
		t.Fatalf("response not restored: %s", resp)
	}
	got := recordsOf(t, i)
	if len(got) != 1 || got[0].Restored == nil || got[0].Restored.Back[placeholder] != 1 || got[0].Restored.Unrestored[gone] != 1 {
		t.Fatalf("record restored = %+v", got[0].Restored)
	}
	// A second response to the same request is not linked twice.
	h.respond(r, `{"output_text":"`+placeholder+`"}`)
	if got := recordsOf(t, i); got[0].Restored.Back[placeholder] != 1 {
		t.Fatalf("a second response counted: %+v", got[0].Restored)
	}
}

func TestStreamsAddWhatTheyRestoredToTheRecord(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	h := hostOf(t, i)
	r := h.send("k", `{"messages":[{"role":"user","content":"mail `+recordedEmail+`"}]}`)
	placeholder := emailPlaceholder.FindString(string(r.upstream))
	var chunks []string
	for _, piece := range []string{"to ", placeholder[:7], placeholder[7:], " ok"} {
		chunks = append(chunks, deltaEvent(piece)...)
	}
	chunks = append(chunks, "event: message_stop\n", `data: {"type":"message_stop"}`+"\n", "\n")
	h.stream(r, chunks)
	got := recordsOf(t, i)
	if len(got) != 1 || got[0].Restored == nil || got[0].Restored.Back[placeholder] != 1 {
		t.Fatalf("record restored = %+v", got[0].Restored)
	}
}
