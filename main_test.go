package main

import (
	"testing"
)

func buildPlugin(t testing.TB, config []byte, dir string) (*veilPlugin, error) {
	t.Helper()
	i := &pluginInstance{}
	t.Cleanup(i.close)
	return i.configure(config, dir)
}
