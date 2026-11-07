package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const correlationTerm = "veil-record-correlation"

// Exercise the host's JSON field names, not only the Go interceptor methods.
func callRecordRuntime(t *testing.T, r *pluginRuntime, method string, request, result any) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = seamCall(t.Context(), r, method, raw)
	if err != nil {
		t.Fatal(err)
	}
	var envelope abiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("%s: %s", method, raw)
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		t.Fatal(err)
	}
}

func configureRecordRuntime(t *testing.T, r *pluginRuntime, dir string, enabled bool) {
	t.Helper()
	cfg := veilConfig{Key: strings.Repeat("42", 32), BaseDir: dir, Records: &enabled, Terms: []termConfig{{Term: correlationTerm}}}
	method := pluginabi.MethodPluginReconfigure
	if r.plugin == nil {
		method = pluginabi.MethodPluginRegister
	}
	var out abiRegistration
	callRecordRuntime(t, r, method, map[string]any{"config_yaml": configBytes(t, cfg), "schema_version": 5}, &out)
}

func maskRecordRuntime(t *testing.T, r *pluginRuntime, id, caller string) ([]byte, string) {
	t.Helper()
	req := map[string]any{"Headers": bearer(caller), "Body": []byte(`{"input":"` + correlationTerm + `"}`)}
	if id != "" {
		req["RequestID"] = id
	}
	var before, after pluginapi.RequestInterceptResponse
	callRecordRuntime(t, r, pluginabi.MethodRequestInterceptBefore, req, &before)
	var body struct{ Input string }
	if err := json.Unmarshal(before.Body, &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Input, "{{TERM_") {
		t.Fatalf("fixture not masked: %s", before.Body)
	}
	req["Body"] = before.Body
	callRecordRuntime(t, r, pluginabi.MethodRequestInterceptAfter, req, &after)
	if len(after.Body) != 0 && !bytes.Equal(after.Body, before.Body) {
		t.Fatalf("after-auth changed masked body: %s", after.Body)
	}
	return before.Body, body.Input
}

func restoreRecordRuntime(t *testing.T, r *pluginRuntime, id, caller string, masked []byte, placeholder string, count int, stream bool) {
	t.Helper()
	h := &fakeHost{t: t, profile: hostV7, runtime: r}
	if id != "" {
		h.profile, h.schema = hostV8, veilSchemaVersion
	}
	req := &fakeRequest{id: id, headers: bearer(caller), original: masked, upstream: masked}
	text := strings.Repeat(placeholder+" ", count)
	var restored string
	if stream {
		restored = h.stream(req, []string{strings.Join(deltaEvent(text), ""), "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"})
	} else {
		restored = h.respond(req, `{"output_text":"`+text+`"}`)
	}
	if got := strings.Count(restored, correlationTerm); got != count {
		t.Fatalf("response restored %d of %d occurrences: %s", got, count, restored)
	}
}

func listedRuntimeRecords(t *testing.T, r *pluginRuntime) []records.Record {
	t.Helper()
	r.plugin.records.Flush()
	var response pluginapi.ManagementResponse
	callRecordRuntime(t, r, pluginabi.MethodManagementHandle, map[string]any{"Method": http.MethodGet, "Path": "/v0/management/plugins/veil/records"}, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("records status: %d", response.StatusCode)
	}
	var out struct{ Records []records.Record }
	if err := json.Unmarshal(response.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Records
}

func storedRuntimeRecords(t *testing.T, dir string) []records.Record {
	t.Helper()
	store := records.New()
	defer store.Close()
	store.SetDir(dir)
	all, _ := store.List(0, 100, records.Filter{})
	return all
}

func TestRuntimeRecordIDsFollowTheOriginalDirectory(t *testing.T) {
	for _, mode := range []string{"response", "stream"} {
		t.Run(mode, func(t *testing.T) {
			a, b := t.TempDir(), t.TempDir()
			r := &pluginRuntime{}
			defer r.close()
			configureRecordRuntime(t, r, a, true)
			old, placeholder := maskRecordRuntime(t, r, "old", "caller")
			before := listedRuntimeRecords(t, r)
			if len(before) != 1 {
				t.Fatalf("old records: %+v", before)
			}
			configureRecordRuntime(t, r, b, true)
			newer, _ := maskRecordRuntime(t, r, "new", "caller")
			if !bytes.Equal(old, newer) {
				t.Fatal("fixture bodies differ")
			}
			// Even the old stream's header-init arrives after the directory switch
			// and after the new, indistinguishable body has been accepted.
			restoreRecordRuntime(t, r, "old", "caller", old, placeholder, 1, mode == "stream")
			current := listedRuntimeRecords(t, r)
			if len(current) != 1 || current[0].Key == before[0].Key || current[0].Restored != nil {
				t.Fatalf("old response affected the current page: %+v", current)
			}
			disk := storedRuntimeRecords(t, a)
			if len(disk) != 1 || disk[0].Key != before[0].Key || disk[0].Restored == nil || disk[0].Restored.Back[placeholder] != 1 {
				t.Fatalf("old directory lost its tally: %+v", disk)
			}
			restoreRecordRuntime(t, r, "new", "caller", newer, placeholder, 2, mode == "stream")
			current = listedRuntimeRecords(t, r)
			if len(current) != 1 || current[0].Restored == nil || current[0].Restored.Back[placeholder] != 2 {
				t.Fatalf("new response tally: %+v", current)
			}
		})
	}
}

func TestRuntimeRecordIDsCannotReviveClearedRecords(t *testing.T) {
	for _, mode := range []string{"response", "stream"} {
		t.Run(mode, func(t *testing.T) {
			r := &pluginRuntime{}
			defer r.close()
			configureRecordRuntime(t, r, t.TempDir(), true)
			old, placeholder := maskRecordRuntime(t, r, "old", "caller")
			var cleared pluginapi.ManagementResponse
			callRecordRuntime(t, r, pluginabi.MethodManagementHandle, map[string]any{"Method": http.MethodPost, "Path": "/v0/management/plugins/veil/clear"}, &cleared)
			if cleared.StatusCode != http.StatusOK {
				t.Fatalf("clear status: %d", cleared.StatusCode)
			}
			newer, _ := maskRecordRuntime(t, r, "new", "caller")
			restoreRecordRuntime(t, r, "old", "caller", old, placeholder, 1, mode == "stream")
			all := listedRuntimeRecords(t, r)
			if len(all) != 1 || all[0].Restored != nil {
				t.Fatalf("late response revived or changed a record: %+v", all)
			}
			restoreRecordRuntime(t, r, "new", "caller", newer, placeholder, 2, mode == "stream")
			all = listedRuntimeRecords(t, r)
			if len(all) != 1 || all[0].Restored == nil || all[0].Restored.Back[placeholder] != 2 {
				t.Fatalf("new response tally: %+v", all)
			}
		})
	}
}

func TestRuntimeUnknownRecordIDDoesNotConsumeALegacyRecord(t *testing.T) {
	r := &pluginRuntime{}
	defer r.close()
	configureRecordRuntime(t, r, t.TempDir(), true)
	masked, placeholder := maskRecordRuntime(t, r, "", "caller")
	restoreRecordRuntime(t, r, "unknown", "caller", masked, placeholder, 1, false)
	all := listedRuntimeRecords(t, r)
	if len(all) != 1 || all[0].Restored != nil {
		t.Fatalf("unknown ID fell back to body: %+v", all)
	}
	// A unique legacy request still works, including its no-op after-auth hook.
	restoreRecordRuntime(t, r, "", "caller", masked, placeholder, 2, false)
	all = listedRuntimeRecords(t, r)
	if len(all) != 1 || all[0].Restored == nil || all[0].Restored.Back[placeholder] != 2 {
		t.Fatalf("unique legacy response tally: %+v", all)
	}
}

func TestRuntimeAmbiguousLegacyRecordsNeverTakeANewerRecord(t *testing.T) {
	for _, initiallyEnabled := range []bool{true, false} {
		name := "recorded"
		if !initiallyEnabled {
			name = "records_disabled"
		}
		t.Run(name, func(t *testing.T) {
			a, b := t.TempDir(), t.TempDir()
			r := &pluginRuntime{}
			defer r.close()
			configureRecordRuntime(t, r, a, initiallyEnabled)
			masked, placeholder := maskRecordRuntime(t, r, "", "caller")
			configureRecordRuntime(t, r, b, true)
			maskRecordRuntime(t, r, "", "caller")
			for n := 0; n < 2; n++ {
				restoreRecordRuntime(t, r, "", "caller", masked, placeholder, 1, false)
			}
			// A further request must not erase ambiguity left by earlier ones.
			maskRecordRuntime(t, r, "", "caller")
			restoreRecordRuntime(t, r, "", "caller", masked, placeholder, 1, false)
			current := listedRuntimeRecords(t, r)
			if len(current) != 2 {
				t.Fatalf("current records: %+v", current)
			}
			old := storedRuntimeRecords(t, a)
			wantOld := 0
			if initiallyEnabled {
				wantOld = 1
			}
			if len(old) != wantOld {
				t.Fatalf("old records: %+v", old)
			}
			for _, record := range append(current, old...) {
				if record.Restored != nil {
					t.Fatalf("ambiguous response assigned a tally: %+v", record)
				}
			}
		})
	}
}
