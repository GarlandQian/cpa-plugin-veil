package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestStandInsRoundTrip(t *testing.T) {
	p := newConfiguredInterceptor(t, "categories: {home: true, userhost: true, ip: true}")
	headers := bearer("client-a")
	original := `{"messages":[{"role":"user","content":"open /Users/garland/project and C:\\Users\\garland\\work, then run ssh root@47.100.12.34"}]}`
	masked := intercept(t, p, abiRequestInterceptRequest{Headers: headers, Body: []byte(original)})
	if strings.Contains(string(masked), "garland") || strings.Contains(string(masked), "47.100.12.34") {
		t.Fatalf("not masked: %s", masked)
	}
	user := regexp.MustCompile(`/Users/([a-z]{8})/`).FindStringSubmatch(string(masked))
	ip := regexp.MustCompile(`public-ip-[a-z]{8}`).FindString(string(masked))
	if user == nil || ip == "" || strings.Contains(string(masked), "{{") {
		t.Fatalf("expected stand-ins, not placeholders: %s", masked)
	}
	if again := interceptAfter(t, p, abiRequestInterceptRequest{Headers: headers, Body: masked}); again != nil {
		t.Fatalf("after-auth masked a stand-in again: %s", again)
	}

	answer, _ := json.Marshal(map[string]any{"content": []any{
		map[string]any{"type": "text", "text": "Opened /Users/" + user[1] + "/project and C:\\Users\\" + strings.ToUpper(user[1]) + "\\work."},
		map[string]any{"type": "tool_use", "id": "t", "name": "bash", "input": map[string]any{"command": "ssh root@" + ip + " 'uptime'"}},
		map[string]any{"type": "text", "text": "not " + ip + "x"},
	}})
	got := string(respondTo(t, p, abiResponseInterceptRequest{RequestHeaders: headers, Body: answer}))
	for _, want := range []string{`/Users/garland/project`, `C:\\Users\\garland\\work`, `ssh root@47.100.12.34 'uptime'`, `not ` + ip + `x`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestStandInSplitInAStream(t *testing.T) {
	p := newConfiguredInterceptor(t, "categories: {home: true}")
	masked := intercept(t, p, abiRequestInterceptRequest{Headers: bearer("client-a"), Body: []byte(`{"input":"cd /Users/garland/project"}`)})
	user := regexp.MustCompile(`/Users/([a-z]{8})/`).FindStringSubmatch(string(masked))[1]
	h := openStream(t, p, "client-a", []byte(`{"stream":1}`))
	for _, piece := range []string{"cd /Users/", user[:3], user[3:], "/project done"} {
		for _, line := range deltaEvent(piece) {
			h.send(line)
		}
	}
	for _, line := range []string{"event: message_stop\n", "data: {\"type\":\"message_stop\"}\n", "\n"} {
		h.send(line)
	}
	if got := streamedText(t, h.visible()); got != "cd /Users/garland/project done" {
		t.Fatalf("client saw %q", got)
	}
}
