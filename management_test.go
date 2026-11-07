package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func manage(t *testing.T, p *veilPlugin, method, path string, query url.Values, body string) (int, map[string]any, string) {
	t.Helper()
	resp := p.handleManagement(pluginapi.ManagementRequest{Method: method, Path: path, Query: query, Body: []byte(body)})
	var out map[string]any
	if strings.HasPrefix(resp.Headers.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(resp.Body, &out); err != nil {
			t.Fatalf("%s %s: not JSON: %s", method, path, resp.Body)
		}
	}
	return resp.StatusCode, out, string(resp.Body)
}

func TestManagementRoutesFollowThePluginID(t *testing.T) {
	for base, want := range map[string]string{
		"/v0/resource/plugins/veil":   "/v0/management/plugins/veil/summary",
		"/v0/resource/plugins/veil2/": "/v0/management/plugins/veil2/summary",
		"":                            "/v0/management/plugins/veil/summary",
	} {
		reg := managementRoutes(base)
		if len(reg.Routes) != 6 || reg.Routes[0].Path != want {
			t.Errorf("%q: routes %+v", base, reg.Routes)
		}
		if reg.Routes[3].Method != http.MethodGet || reg.Routes[3].Path != strings.TrimSuffix(want, "summary")+"record-values" {
			t.Errorf("%q: original-value route does not follow the authenticated plugin prefix", base)
		}
		if len(reg.Resources) != 1 || reg.Resources[0].Path != "/index.html" || reg.Resources[0].Menu != recordsMenu {
			t.Errorf("%q: resources %+v", base, reg.Resources)
		}
	}
}

func TestManagementRecordsWithoutValues(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	p := i
	intercept(t, i, abiRequestInterceptRequest{Headers: bearer("k"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
	p.records.Flush()
	const base = "/v0/management/plugins/veil/"

	resp := p.handleManagement(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/veil/index.html"})
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Headers.Get("Content-Type"), "text/html") || !strings.Contains(string(resp.Body), recordsMenu) {
		t.Fatalf("page = %d %v", resp.StatusCode, resp.Headers)
	}
	var bodies []string
	status, sum, raw := manage(t, p, http.MethodGet, base+"summary", url.Values{"days": {"7"}}, "")
	bodies = append(bodies, raw)
	if status != http.StatusOK || sum["enabled"] != true || sum["requests"] != float64(1) {
		t.Fatalf("summary = %d %s", status, raw)
	}
	status, list, raw := manage(t, p, http.MethodGet, base+"records", url.Values{"limit": {"10"}, "kind": {"EMAIL"}, "caller": {""}}, "")
	bodies = append(bodies, raw)
	if status != http.StatusOK || len(list["records"].([]any)) != 0 {
		t.Fatalf("records of the Default scope = %d %s", status, raw)
	}
	status, list, raw = manage(t, p, http.MethodGet, base+"records", url.Values{"kind": {"EMAIL"}}, "")
	bodies = append(bodies, raw)
	recs := list["records"].([]any)
	if status != http.StatusOK || len(recs) != 1 || recs[0].(map[string]any)["snips"] != nil || !strings.Contains(fmt.Sprint(recs[0].(map[string]any)["glimpse"]), "{{EMAIL_") {
		t.Fatalf("records = %d %s", status, raw)
	}
	key := strconv.FormatInt(int64(recs[0].(map[string]any)["key"].(float64)), 10)
	status, rec, raw := manage(t, p, http.MethodGet, base+"record", url.Values{"key": {key}}, "")
	bodies = append(bodies, raw)
	if status != http.StatusOK || rec["snips"] == nil {
		t.Fatalf("record = %d %s", status, raw)
	}

	before := p.vault.Len()
	status, prev, raw := manage(t, p, http.MethodPost, base+"preview", nil, `{"text":"write to other@acme-corp.cn please"}`)
	bodies = append(bodies, raw)
	if status != http.StatusOK || strings.Contains(prev["text"].(string), "other@acme-corp.cn") || len(prev["hits"].([]any)) != 1 {
		t.Fatalf("preview = %d %s", status, raw)
	}
	if p.vault.Len() != before {
		t.Fatal("a preview put a value in the Vault")
	}
	for _, b := range bodies {
		if strings.Contains(b, recordedEmail) || strings.Contains(b, "other@acme-corp.cn") {
			t.Fatalf("an answer holds a value: %s", b)
		}
	}

	for _, bad := range []struct {
		method, name string
		q            url.Values
	}{
		{http.MethodGet, "summary", url.Values{"days": {"0"}}},
		{http.MethodGet, "records", url.Values{"limit": {"1000"}}},
		{http.MethodGet, "record", url.Values{"key": {"x"}}},
	} {
		if status, _, raw := manage(t, p, bad.method, base+bad.name, bad.q, ""); status != http.StatusBadRequest {
			t.Errorf("%s %v = %d %s", bad.name, bad.q, status, raw)
		}
	}
	if status, _, _ := manage(t, p, http.MethodPost, base+"preview", nil, "not json"); status != http.StatusBadRequest {
		t.Errorf("preview of a bad body = %d", status)
	}
	if status, _, _ := manage(t, p, http.MethodGet, base+"nothing", nil, ""); status != http.StatusNotFound {
		t.Errorf("unknown route = %d", status)
	}

	if status, out, _ := manage(t, p, http.MethodPost, base+"clear", nil, ""); status != http.StatusOK || out["cleared"] != true {
		t.Fatalf("clear = %d %v", status, out)
	}
	if _, list, _ := manage(t, p, http.MethodGet, base+"records", nil, ""); len(list["records"].([]any)) != 0 {
		t.Fatal("records survived clear")
	}
}

// The page loads nothing from anywhere else: CPA serves it to anyone, and a
// management panel embeds it.
func TestRecordsPageIsSelfContained(t *testing.T) {
	page := string(recordsPage)
	for _, bad := range []string{"<script src", "<link", "@import", "src=\"http", "url(http"} {
		if strings.Contains(page, bad) {
			t.Errorf("the page loads %q from elsewhere", bad)
		}
	}
	for _, want := range []string{"cli-proxy-auth", "enc::v2::", "data-cpamp-plugin-host", "/v0/management/plugins/", "api-key-aliases"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

func TestManagementWithRecordsOff(t *testing.T) {
	p := newConfiguredInterceptor(t, "records: false\n")
	if status, out, _ := manage(t, p, http.MethodGet, "/v0/management/plugins/veil/summary", nil, ""); status != http.StatusOK || out["enabled"] != false {
		t.Fatalf("summary with records off = %d %v", status, out)
	}
	if status, out, _ := manage(t, p, http.MethodPost, "/v0/management/plugins/veil/preview", nil, `{"text":"mail test@acme-corp.cn"}`); status != http.StatusOK || len(out["hits"].([]any)) != 1 {
		t.Fatalf("preview with records off = %d %v", status, out)
	}
}

func TestManagementThroughTheABI(t *testing.T) {
	runtime := &pluginRuntime{}
	defer runtime.close()
	ctx := context.Background()
	raw, err := seamCall(ctx, runtime, pluginabi.MethodPluginRegister, registerRequest(t, t.TempDir(), ""))
	if err != nil {
		t.Fatal(err)
	}
	if !decodeRegistration(t, raw).Capabilities.ManagementAPI {
		t.Fatal("the management API is not declared")
	}

	result := func(raw []byte, err error, into any) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var env abiEnvelope
		if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
			t.Fatalf("envelope = %s, %v", raw, err)
		}
		if err := json.Unmarshal(env.Result, into); err != nil {
			t.Fatal(err)
		}
	}
	reqRaw, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{BasePath: "/v0/management", ResourceBasePath: "/v0/resource/plugins/veil"})
	var reg struct {
		Routes    []pluginapi.ManagementRoute `json:"routes"`
		Resources []pluginapi.ResourceRoute   `json:"resources"`
	}
	out, errCall := seamCall(ctx, runtime, pluginabi.MethodManagementRegister, reqRaw)
	result(out, errCall, &reg)
	if len(reg.Routes) != 6 || reg.Routes[0].Method != http.MethodGet || reg.Resources[0].Menu != recordsMenu {
		t.Fatalf("registration = %+v", reg)
	}

	reqRaw, _ = json.Marshal(abiManagementRequest{ManagementRequest: pluginapi.ManagementRequest{
		Method: http.MethodPost, Path: "/v0/management/plugins/veil/preview", Body: []byte(`{"text":"mail test@acme-corp.cn"}`),
	}})
	var resp pluginapi.ManagementResponse
	out, errCall = seamCall(ctx, runtime, pluginabi.MethodManagementHandle, reqRaw)
	result(out, errCall, &resp)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(resp.Body), "test@acme-corp.cn") || !strings.Contains(string(resp.Body), "EMAIL") {
		t.Fatalf("preview through the ABI = %d %s", resp.StatusCode, resp.Body)
	}
}

func TestManagementRecordValuesFollowTheRecordCaller(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	const route = "/v0/management/plugins/veil/record-values"
	for _, caller := range []string{"", "caller-a", "caller-b"} {
		t.Run("scope-"+caller, func(t *testing.T) {
			scope := vault.ScopeOf(bearer(caller))
			r := records.Record{Caller: scope}
			want := make(map[string]string)
			for kind, original := range map[string]string{"TERM": "example <value> & \"quoted\"", "USERNAME": "sample-user"} {
				placeholder := p.vault.Placeholder(scope, kind, original)
				r.Values = append(r.Values, records.Value{Placeholder: placeholder, Kind: kind, Action: "mask", N: 1})
				want[placeholder] = original
			}
			unrelated := p.vault.Placeholder(scope, "TERM", "a value from another request")
			ref, ok := p.records.Add(r)
			if !ok {
				t.Fatal("record was not accepted")
			}
			p.records.Flush()
			q := url.Values{"key": {strconv.FormatInt(ref.Key, 10)}, "caller": {"not-the-record-caller"}, "p": {unrelated}}
			resp := p.handleManagement(pluginapi.ManagementRequest{Method: http.MethodGet, Path: route, Query: q})
			var got struct {
				Values map[string]string `json:"values"`
			}
			if resp.StatusCode != http.StatusOK || resp.Headers.Get("Cache-Control") != "no-store" {
				t.Fatalf("values response = %d, cache = %q", resp.StatusCode, resp.Headers.Get("Cache-Control"))
			}
			if err := json.Unmarshal(resp.Body, &got); err != nil || !reflect.DeepEqual(got.Values, want) {
				t.Fatal("originals did not match this record's values in its Caller scope")
			}
			_, _, body := manage(t, p, http.MethodGet, "/v0/management/plugins/veil/record", q, "")
			for _, original := range want {
				if strings.Contains(body, original) {
					t.Fatal("revealing an original changed the ordinary record response")
				}
			}
			for _, path := range []string{"/v0/resource/plugins/veil/record-values", "/record-values"} {
				if status, _, _ := manage(t, p, http.MethodGet, path, q, ""); status != http.StatusNotFound {
					t.Fatalf("originals exposed outside the management routes: %s", path)
				}
			}
		})
	}
	files, err := filepath.Glob(filepath.Join(p.pluginDir, "veil-records", "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatal("no persistent record file to check")
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "sample-user") || strings.Contains(string(body), "example") {
			t.Fatal("an original was written into a record file")
		}
	}
}

func TestManagementRecordValuesRequireCurrentMappings(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	req := abiRequestInterceptRequest{Headers: bearer("caller-a"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)}
	intercept(t, p, req)
	r := recordsOf(t, p)[0]
	const route = "/v0/management/plugins/veil/record-values"
	q := url.Values{"key": {strconv.FormatInt(r.Key, 10)}}
	assertValues := func(plugin *veilPlugin, available bool) {
		t.Helper()
		status, out, _ := manage(t, plugin, http.MethodGet, route, q, "")
		if status != http.StatusOK {
			t.Fatalf("values status = %d", status)
		}
		values := out["values"].(map[string]any)
		if available && (len(values) != 1 || values[r.Values[0].Placeholder] != recordedEmail) || !available && len(values) != 0 {
			t.Fatal("original availability did not follow the current Caller-scoped mapping")
		}
	}
	assertValues(p, true)
	// A fresh instance reads the saved key and record, but has an empty Vault.
	fresh := buildInterceptor(t, p.pluginDir, "")
	assertValues(fresh, false)
	other := req
	other.Headers = bearer("caller-b")
	intercept(t, fresh, other)
	assertValues(fresh, false)
	intercept(t, fresh, req)
	assertValues(fresh, true)
	if err := fresh.records.Clear(); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := manage(t, fresh, http.MethodGet, route, q, ""); status != http.StatusNotFound {
		t.Fatal("a cleared record still exposed originals")
	}
	for _, key := range []string{"", "invalid", "0", "-1"} {
		if status, _, _ := manage(t, fresh, http.MethodGet, route, url.Values{"key": {key}}, ""); status != http.StatusBadRequest {
			t.Fatalf("invalid record key status = %d", status)
		}
	}
	off := newConfiguredInterceptor(t, "records: false\n")
	if status, _, _ := manage(t, off, http.MethodGet, route, q, ""); status != http.StatusNotFound {
		t.Fatal("originals were available with records disabled")
	}
}

func TestManagementRecordValuesDoNotResolveUnretainedCandidates(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	scope := vault.ScopeOf(bearer("caller"))
	placeholder := p.vault.Placeholder(scope, "TERM", "existing mapped example")
	for _, tc := range []struct{ action, stopped string }{
		{"warn", ""}, {"block", records.StoppedBlock}, {"mask", records.StoppedBlock}, {"mask", records.StoppedError},
	} {
		// Even a candidate that names an existing mapping must not be revealed.
		ref, ok := p.records.Add(records.Record{Caller: scope, Stopped: tc.stopped, Values: []records.Value{{Placeholder: placeholder, Kind: "TERM", Action: tc.action, N: 1}}})
		if !ok {
			t.Fatal("record was not accepted")
		}
		p.records.Flush()
		status, out, _ := manage(t, p, http.MethodGet, "/v0/management/plugins/veil/record-values", url.Values{"key": {strconv.FormatInt(ref.Key, 10)}}, "")
		if status != http.StatusOK || len(out["values"].(map[string]any)) != 0 {
			t.Fatalf("a candidate resolved for action %s, stopped %s", tc.action, tc.stopped)
		}
	}
}
