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
	req := map[string]any{"RequestID": id, "Headers": bearer(caller), "Body": []byte(`{"input":"` + correlationTerm + `"}`)}
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
	h := &fakeHost{t: t, profile: hostV8, runtime: r, schema: veilSchemaVersion}
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

// A response is its request's by the request ID alone: one that names another
// request takes no record, however alike the bodies.
func TestRuntimeUnknownRecordIDTakesNoRecord(t *testing.T) {
	r := &pluginRuntime{}
	defer r.close()
	configureRecordRuntime(t, r, t.TempDir(), true)
	masked, placeholder := maskRecordRuntime(t, r, "known", "caller")
	restoreRecordRuntime(t, r, "unknown", "caller", masked, placeholder, 1, false)
	all := listedRuntimeRecords(t, r)
	if len(all) != 1 || all[0].Restored != nil {
		t.Fatalf("a response of another request took the record: %+v", all)
	}
	restoreRecordRuntime(t, r, "known", "caller", masked, placeholder, 2, false)
	all = listedRuntimeRecords(t, r)
	if len(all) != 1 || all[0].Restored == nil || all[0].Restored.Back[placeholder] != 2 {
		t.Fatalf("the request's own response tally: %+v", all)
	}
}
