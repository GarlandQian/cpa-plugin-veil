package main

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"testing"
)

func buildPlugin(t testing.TB, config []byte, dir string) (pluginapi.Plugin, error) {
	t.Helper()
	i := &pluginInstance{}
	t.Cleanup(i.close)
	return i.configure(config, dir)
}
