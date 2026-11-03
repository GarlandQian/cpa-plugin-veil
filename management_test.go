package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

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
		if len(reg.Routes) != 5 || reg.Routes[0].Path != want {
			t.Errorf("%q: routes %+v", base, reg.Routes)
		}
		if len(reg.Resources) != 1 || reg.Resources[0].Path != "/index.html" || reg.Resources[0].Menu != recordsMenu {
			t.Errorf("%q: resources %+v", base, reg.Resources)
		}
	}
}

func TestManagementAnswersWithoutValues(t *testing.T) {
	i := newConfiguredInterceptor(t, "")
	p := i.(*veilPlugin)
	intercept(t, i, pluginapi.RequestInterceptRequest{Headers: bearer("k"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
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
	if status != http.StatusOK || len(recs) != 1 || recs[0].(map[string]any)["snips"] != nil {
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

func TestManagementWithRecordsOff(t *testing.T) {
	p := newConfiguredInterceptor(t, "records: false\n").(*veilPlugin)
	if status, out, _ := manage(t, p, http.MethodGet, "/v0/management/plugins/veil/summary", nil, ""); status != http.StatusOK || out["enabled"] != false {
		t.Fatalf("summary with records off = %d %v", status, out)
	}
	if status, out, _ := manage(t, p, http.MethodPost, "/v0/management/plugins/veil/preview", nil, `{"text":"mail test@acme-corp.cn"}`); status != http.StatusOK || len(out["hits"].([]any)) != 1 {
		t.Fatalf("preview with records off = %d %v", status, out)
	}
}

func TestManagementThroughTheABI(t *testing.T) {
	resetMasking(t)
	veilABIState.Lock()
	previous := veilABIState.plugin
	veilABIState.plugin = nil
	veilABIState.Unlock()
	t.Cleanup(func() {
		veilABIState.Lock()
		veilABIState.plugin = previous
		veilABIState.Unlock()
	})
	ctx := context.Background()
	raw, err := handleVeilRegister(ctx, pluginabi.MethodPluginRegister, registerRequest(t, t.TempDir(), ""))
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
	out, errCall := handleVeilABIMethod(ctx, pluginabi.MethodManagementRegister, reqRaw)
	result(out, errCall, &reg)
	if len(reg.Routes) != 5 || reg.Routes[0].Method != http.MethodGet || reg.Resources[0].Menu != recordsMenu {
		t.Fatalf("registration = %+v", reg)
	}

	reqRaw, _ = json.Marshal(abiManagementRequest{ManagementRequest: pluginapi.ManagementRequest{
		Method: http.MethodPost, Path: "/v0/management/plugins/veil/preview", Body: []byte(`{"text":"mail test@acme-corp.cn"}`),
	}})
	var resp pluginapi.ManagementResponse
	out, errCall = handleVeilABIMethod(ctx, pluginabi.MethodManagementHandle, reqRaw)
	result(out, errCall, &resp)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(resp.Body), "test@acme-corp.cn") || !strings.Contains(string(resp.Body), "EMAIL") {
		t.Fatalf("preview through the ABI = %d %s", resp.StatusCode, resp.Body)
	}
}
