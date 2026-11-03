package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// masking is the state that outlives a config reload: the Vault, so
// Placeholders handed out before the reload still restore, the Sent forms, so
// prompt prefixes stay the same, the streams in flight and the Masking
// records.
var masking = struct {
	sync.Mutex
	dir         string
	key         []byte
	explicitKey bool
	shadowNoted bool
	vault       *vault.Vault
	masker      *mask.Masker
	streams     *streamRegistry
	records     *records.Store
}{}

// recordsOnDisk says Masking records go to disk where Veil has a persistent
// directory; the tests keep them in memory unless they test the disk.
var recordsOnDisk = true

// recordStore returns the process's Masking records, kept on disk under dir
// when it is a persistent directory.
func recordStore(dir string) *records.Store {
	masking.Lock()
	defer masking.Unlock()
	if masking.records == nil {
		masking.records = records.New()
	}
	if !recordsOnDisk {
		dir = ""
	}
	masking.records.SetDir(dir)
	return masking.records
}

// maskerFor keeps the Vault, Sent forms and active streams on reload. A key
// change needs a restart rather than discarding mappings under live requests.
func maskerFor(pluginDir string, configuredKey []byte, d *detect.Detector, actions map[string]mask.Action) (*mask.Masker, *vault.Vault, *streamRegistry, error) {
	masking.Lock()
	defer masking.Unlock()
	if masking.vault != nil {
		if len(configuredKey) > 0 {
			if !bytes.Equal(configuredKey, masking.key) {
				return nil, nil, nil, fmt.Errorf("changing the veil key requires a CPA restart")
			}
		} else if masking.explicitKey || masking.dir != pluginDir {
			return nil, nil, nil, fmt.Errorf("changing the veil key source requires a CPA restart")
		}
	} else {
		key := configuredKey
		if len(key) == 0 {
			key = placeholderKey(pluginDir)
		}
		masking.key = bytes.Clone(key)
		masking.vault = vault.New(key, vault.DefaultLimit)
		masking.masker = mask.New(d, masking.vault)
		masking.streams = newStreamRegistry()
	}
	masking.dir = pluginDir
	masking.explicitKey = len(configuredKey) > 0
	masking.masker = masking.masker.WithPolicy(d, actions)
	return masking.masker, masking.vault, masking.streams, nil
}

// placeholderKey loads the key from the plugin directory. Without a usable
// directory Veil still masks, under a key that changes on every restart.
func placeholderKey(pluginDir string) []byte {
	if pluginDir != "" {
		key, err := vault.LoadOrCreateKey(pluginDir)
		if err == nil {
			return key
		}
		pluginLog(context.Background(), logLevelError, "veil cannot keep its placeholder key, placeholders will change on restart; set plugins.configs.veil.key: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
	} else {
		pluginLog(context.Background(), logLevelWarn, "veil has no persistent directory for its placeholder key; using an in-memory key, placeholders will change on restart; set plugins.configs.veil.key or base_dir", nil)
	}
	return vault.NewEphemeralKey()
}
