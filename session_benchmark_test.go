package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// sessionTurns builds the request bodies an agent sends over a long session:
// every turn re-sends the whole history plus one user message, one assistant
// reply and one tool result, with a few sensitive values scattered through.
func sessionTurns(turns int) [][]byte {
	system := strings.Repeat("You are a coding agent working in a repository. Follow the user's instructions carefully. ", 90)
	messages := []any{}
	bodies := make([][]byte, 0, turns)
	for i := 0; i < turns; i++ {
		user := fmt.Sprintf("Turn %d: please check why the deploy failed and mail ops-%d@acme-corp.cn when done. ", i, i) +
			strings.Repeat("The service logs are attached below for context. ", 8)
		reply := fmt.Sprintf("Looking at turn %d. The handler reads the config and retries the request.\n", i) +
			strings.Repeat("```go\nfunc handle(ctx context.Context, req *Request) error {\n\treturn retry(ctx, req)\n}\n```\n", 6)
		output := strings.Repeat(fmt.Sprintf("2026-11-02T10:%02d:00Z INFO worker=%d processed batch size=128 latency=42ms\n", i%60, i), 30)
		if i%10 == 3 {
			output += fmt.Sprintf("export GITHUB_TOKEN=ghp_%036d\n", i)
		}
		messages = append(messages,
			map[string]any{"role": "user", "content": user},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "text", "text": reply},
				map[string]any{"type": "tool_use", "id": fmt.Sprintf("t%d", i), "name": "bash", "input": map[string]any{"command": "tail -n 30 app.log"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": fmt.Sprintf("t%d", i), "content": output},
			}},
		)
		body, err := json.Marshal(map[string]any{"model": "claude-sonnet-5-5", "system": system, "messages": messages, "max_tokens": 4096})
		if err != nil {
			panic(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// BenchmarkLongSession reports the masking cost of one request of an 80-turn
// session, averaged over the session, with both interception hooks run as the
// host runs them. Each iteration replays the session on a fresh plugin, so
// nothing is cached from an earlier iteration.
func BenchmarkLongSession(b *testing.B) {
	output := log.StandardLogger().Out
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(output) })
	bodies := sessionTurns(80)
	ctx := context.Background()
	dir := b.TempDir()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		masking.Lock()
		masking.dir, masking.vault, masking.masker, masking.streams = "", nil, nil, nil
		masking.key, masking.explicitKey = nil, false
		masking.Unlock()
		plugin, err := buildPlugin(nil, dir)
		if err != nil {
			b.Fatal(err)
		}
		interceptor := plugin.Capabilities.RequestInterceptor
		b.StartTimer()
		for _, body := range bodies {
			before, err := interceptor.InterceptRequestBeforeAuth(ctx, pluginapi.RequestInterceptRequest{Body: body})
			if err != nil {
				b.Fatal(err)
			}
			if len(before.Body) > 0 {
				body = before.Body
			}
			if _, err = interceptor.InterceptRequestAfterAuth(ctx, pluginapi.RequestInterceptRequest{Body: body}); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.Elapsed().Microseconds())/1000/float64(b.N*len(bodies)), "ms/turn")
}
