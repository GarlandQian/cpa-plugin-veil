package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestRuntimeShutdownDrainsCallsStreamsAndRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		r := &pluginRuntime{}
		defer r.close()
		config := registerRequest(t, dir, "")
		if _, err := seamCall(t.Context(), r, pluginabi.MethodPluginRegister, config); err != nil {
			t.Fatal(err)
		}
		p, release, err := r.begin()
		if err != nil {
			t.Fatal(err)
		}
		release = sync.OnceFunc(release)
		defer release()
		host := hostOf(t, p)
		request := host.send("k", `{"input":"mail `+recordedEmail+`"}`)
		placeholder := emailPlaceholder.FindString(string(request.upstream))
		if placeholder == "" {
			t.Fatal("fixture was not masked")
		}
		h := host.open(request)
		for _, line := range deltaEvent(placeholder + " ok") {
			h.send(line)
		}
		store := p.records
		closed := make(chan struct{})
		go func() { r.close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("shutdown returned with a call in flight")
		default:
		}
		if _, done, err := r.begin(); err == nil {
			done()
			t.Fatal("shutdown admitted a call")
		}
		release()
		<-closed
		if _, ok := store.Add(records.Record{}); ok {
			t.Fatal("writer accepts records after shutdown")
		}
		if _, err := seamCall(t.Context(), r, pluginabi.MethodPluginRegister, config); err == nil {
			t.Fatal("register revived a closed runtime")
		}
		disk := records.New()
		defer disk.Close()
		disk.SetDir(dir)
		all, _ := disk.List(0, 10, records.Filter{})
		if len(all) != 1 || all[0].Restored == nil || all[0].Restored.Back[placeholder] != 1 {
			t.Fatalf("shutdown lost stream tally: %+v", all)
		}
		fresh := &pluginRuntime{}
		defer fresh.close()
		if _, err := seamCall(t.Context(), fresh, pluginabi.MethodPluginRegister, config); err != nil {
			t.Fatal(err)
		}
		if fresh.plugin.vault.Len() != 0 {
			t.Fatal("re-enable retained old mappings")
		}
		if again := intercept(t, fresh.plugin, abiRequestInterceptRequest{Headers: request.headers, Body: request.original}); !bytes.Equal(request.upstream, again) {
			t.Fatal("re-enable changed the persisted key")
		}
	})
}

// Arrange a config construction that has been admitted but cannot finish
// until shutdown has closed admission. No timers or disk latency decide who wins.
func TestShutdownWinsOverAnAdmittedRegistration(t *testing.T) {
	dir := t.TempDir()
	r := &pluginRuntime{}
	defer r.close()
	instance := &pluginInstance{}
	r.instance = instance
	instance.mu.Lock()
	unlock := sync.OnceFunc(instance.mu.Unlock)
	defer unlock()
	payload := registerRequest(t, dir, "")
	registered := make(chan error, 1)
	go func() {
		_, err := seamCall(context.Background(), r, pluginabi.MethodPluginRegister, payload)
		registered <- err
	}()
	waitFor(t, func() bool {
		if r.configure.TryLock() {
			r.configure.Unlock()
			return false
		}
		return true
	})
	closed := make(chan struct{})
	go func() { r.close(); close(closed) }()
	waitFor(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.closed })
	unlock()
	if err := <-registered; err == nil {
		t.Fatal("registration published after shutdown began")
	}
	<-closed
	if _, done, err := r.begin(); err == nil {
		done()
		t.Fatal("closed instance is callable")
	}
}

func waitFor(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("lifecycle did not reach the expected boundary")
		}
		runtime.Gosched()
	}
}

func TestReloadRoutesAnOldStreamsTallyToItsOriginalDirectory(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	r := &pluginRuntime{}
	defer r.close()
	cfg := veilConfig{Key: strings.Repeat("42", 32), BaseDir: a}
	register := func() {
		t.Helper()
		if _, err := seamCall(t.Context(), r, pluginabi.MethodPluginReconfigure, registerRequest(t, "", string(configBytes(t, cfg)))); err != nil {
			t.Fatal(err)
		}
	}
	register()
	first := r.plugin
	req := abiRequestInterceptRequest{Headers: bearer("k"), Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)}
	sent := hostOf(t, first).send("k", string(req.Body))
	masked := sent.upstream
	placeholder := emailPlaceholder.FindString(string(masked))
	if placeholder == "" {
		t.Fatal("fixture was not masked")
	}
	stream := hostOf(t, first).open(sent)
	for _, line := range deltaEvent(placeholder[:7]) {
		stream.send(line)
	}
	cfg.BaseDir = b
	register()
	current := r.plugin
	if current.vault != first.vault {
		t.Fatal("reload replaced Vault")
	}
	stream.h = hostOf(t, current)
	for _, line := range deltaEvent(placeholder[7:] + " ok") {
		stream.send(line)
	}
	for _, line := range []string{"event: message_stop\n", "data: {\"type\":\"message_stop\"}\n", "\n"} {
		stream.send(line)
	}
	if got := streamedText(t, stream.visible()); got != recordedEmail+" ok" {
		t.Fatalf("reload lost Held tail: %q", got)
	}
	if got := recordsOf(t, current); len(got) != 0 {
		t.Fatalf("new directory shows old records: %+v", got)
	}
	disk := records.New()
	defer disk.Close()
	disk.SetDir(a)
	all, _ := disk.List(0, 10, records.Filter{})
	if len(all) != 1 || all[0].Restored == nil || all[0].Restored.Back[placeholder] != 1 {
		t.Fatalf("old directory tally: %+v", all)
	}
	if again := intercept(t, current, req); !bytes.Equal(masked, again) {
		t.Fatal("reload changed the Sent form")
	}
	if got := recordsOf(t, current); len(got) != 1 {
		t.Fatalf("new requests not recorded: %+v", got)
	}
}

func TestConcurrentReconfigureAndCalls(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = 'runtime test'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &pluginRuntime{}
	defer r.close()
	config := registerRequest(t, dir, "gitleaks_toml: rules.toml\n")
	if _, err := seamCall(t.Context(), r, pluginabi.MethodPluginRegister, config); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Go(func() {
			req, _ := json.Marshal(abiRequestInterceptRequest{Body: []byte(`{"input":"mail ` + recordedEmail + `"}`)})
			for n := 0; n < 20; n++ {
				if _, err := seamCall(context.Background(), r, pluginabi.MethodRequestInterceptBefore, req); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for n := 0; n < 8; n++ {
		if _, err := seamCall(t.Context(), r, pluginabi.MethodPluginReconfigure, config); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
