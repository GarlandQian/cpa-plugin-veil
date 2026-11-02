package main

import (
	"context"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// masking is the state that outlives a config reload: the Vault, so
// Placeholders handed out before the reload still restore, and the Sent
// forms, so prompt prefixes stay the same.
var masking = struct {
	sync.Mutex
	dir    string
	vault  *vault.Vault
	masker *mask.Masker
}{}

// maskerFor returns a Masker detecting with d over the process's Vault,
// creating the Vault, and its key in pluginDir, on first use.
func maskerFor(pluginDir string, d *detect.Detector) (*mask.Masker, *vault.Vault) {
	masking.Lock()
	defer masking.Unlock()
	if masking.vault == nil || masking.dir != pluginDir {
		masking.dir = pluginDir
		masking.vault = vault.New(placeholderKey(pluginDir), vault.DefaultLimit)
		masking.masker = mask.New(d, masking.vault)
		return masking.masker, masking.vault
	}
	masking.masker = masking.masker.WithDetector(d)
	return masking.masker, masking.vault
}

// placeholderKey loads the key from the plugin directory. Without a usable
// directory Veil still masks, under a key that changes on every restart.
func placeholderKey(pluginDir string) []byte {
	if pluginDir != "" {
		key, err := vault.LoadOrCreateKey(pluginDir)
		if err == nil {
			return key
		}
		pluginLog(context.Background(), logLevelError, "veil cannot keep its placeholder key, placeholders will change on restart: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
	} else {
		pluginLog(context.Background(), logLevelError, "veil has no plugin directory for its placeholder key, placeholders will change on restart", nil)
	}
	return vault.NewEphemeralKey()
}
