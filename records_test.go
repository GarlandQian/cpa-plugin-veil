package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const recordedEmail = "test@acme-corp.cn"

func recordsOf(t *testing.T, i pluginapi.RequestInterceptor) []records.Record {
	t.Helper()
	p := i.(*veilPlugin)
	if p.records == nil {
		return nil
	}
	p.records.Flush()
	got, _ := p.records.List(0, 100, records.Filter{})
	return got
}

func TestARequestWithValuesLeavesARecordWithoutThem(t *testing.T) {
	i := newConfiguredInterceptor(t, "actions:\n  PHONE: warn\n")
	req := pluginapi.RequestInterceptRequest{
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
	if _, err := i.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{Headers: req.Headers, Body: masked}); err != nil {
		t.Fatal(err)
	}
	if n := len(recordsOf(t, i)); n != 1 {
		t.Fatalf("after-auth left %d records", n)
	}
}

func TestCleanRequestsLeaveNoRecord(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	intercept(t, i, pluginapi.RequestInterceptRequest{Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)})
	if n := len(recordsOf(t, i)); n != 0 {
		t.Fatalf("a clean request left %d records", n)
	}
}

func TestRecordsCanBeTurnedOff(t *testing.T) {
	i := newConfiguredInterceptor(t, "records: false\n")
	intercept(t, i, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	if i.(*veilPlugin).records != nil {
		t.Fatal("records: false still keeps records")
	}
}

func TestStoppedRequestsAreRecorded(t *testing.T) {
	i := newConfiguredInterceptor(t, "actions:\n  EMAIL: block\n")
	intercept(t, i, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	intercept(t, i, pluginapi.RequestInterceptRequest{Body: []byte(`{"input": "cut short`)})
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
	masked := intercept(t, i, pluginapi.RequestInterceptRequest{Headers: bearer("k"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	p := i.(*veilPlugin)
	recordsOf(t, i)
	if err := p.records.Clear(); err != nil {
		t.Fatal(err)
	}
	placeholder := emailPlaceholder.FindString(string(masked))
	out := p.restorer.Body(vault.ScopeOf(bearer("k")), []byte(`{"output_text":"sent to `+placeholder+`"}`))
	if !strings.Contains(string(out), recordedEmail) {
		t.Fatalf("restoring stopped after Clear: %s", out)
	}
}

func TestRecordsOnDiskHoldNoValues(t *testing.T) {
	resetMasking(t)
	recordsOnDisk = true
	t.Cleanup(func() { recordsOnDisk = false })
	dir := t.TempDir()
	i := buildInterceptor(t, dir, "")
	p := i.(*veilPlugin)
	t.Cleanup(func() {
		// Before the directory goes: nothing left to write into it.
		p.records.Flush()
		p.records.SetDir("")
	})
	intercept(t, i, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
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
	p := i.(*veilPlugin)
	headers := bearer("k")
	masked := intercept(t, i, pluginapi.RequestInterceptRequest{Headers: headers, Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	placeholder := emailPlaceholder.FindString(string(masked))
	gone := "{{EMAIL_aaaaaaaa}}"
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestHeaders:  headers,
		OriginalRequest: masked,
		Body:            []byte(`{"output_text":"sent to ` + placeholder + `, not ` + gone + `"}`),
	})
	if err != nil || !strings.Contains(string(resp.Body), recordedEmail) {
		t.Fatalf("response not restored: %s %v", resp.Body, err)
	}
	got := recordsOf(t, i)
	if len(got) != 1 || got[0].Restored == nil || got[0].Restored.Back[placeholder] != 1 || got[0].Restored.Unrestored[gone] != 1 {
		t.Fatalf("record restored = %+v", got[0].Restored)
	}
	// A second response to the same request is not linked twice.
	p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{RequestHeaders: headers, OriginalRequest: masked, Body: []byte(`{"output_text":"` + placeholder + `"}`)})
	if got := recordsOf(t, i); got[0].Restored.Back[placeholder] != 1 {
		t.Fatalf("a second response counted: %+v", got[0].Restored)
	}
}

func TestStreamsAddWhatTheyRestoredToTheRecord(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	p := i.(*veilPlugin)
	headers := bearer("k")
	masked := intercept(t, i, pluginapi.RequestInterceptRequest{Headers: headers, Body: []byte(`{"messages":[{"role":"user","content":"mail ` + recordedEmail + `"}]}`)})
	placeholder := emailPlaceholder.FindString(string(masked))
	req := pluginapi.StreamChunkInterceptRequest{RequestHeaders: headers, OriginalRequest: masked, RequestBody: masked, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex}
	if _, err := p.InterceptStreamChunk(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var chunks []string
	for _, piece := range []string{"to ", placeholder[:7], placeholder[7:], " ok"} {
		chunks = append(chunks, deltaEvent(piece)...)
	}
	chunks = append(chunks, "event: message_stop\n", `data: {"type":"message_stop"}`+"\n", "\n")
	for n, c := range chunks {
		req.ChunkIndex, req.Body = n, []byte(c)
		if _, err := p.InterceptStreamChunk(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	got := recordsOf(t, i)
	if len(got) != 1 || got[0].Restored == nil || got[0].Restored.Back[placeholder] != 1 {
		t.Fatalf("record restored = %+v", got[0].Restored)
	}
}
