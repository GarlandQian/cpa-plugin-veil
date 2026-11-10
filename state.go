package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/roundtrip"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// pluginInstance owns state until the host calls shutdown. Configuration
// views share its Vault, Sent forms, Round trips and records; close ends them
// all.
// The runtime drains calls before closing the instance.
type pluginInstance struct {
	mu          sync.Mutex
	closed      bool
	dir         string
	key         []byte
	explicitKey bool
	shadowNoted bool
	vault       *vault.Vault
	masker      *mask.Masker
	trips       *roundtrip.Trips
	records     *records.Store
}

func (i *pluginInstance) configureMasking(dir string, key []byte, d *detect.Detector, actions map[string]mask.Action) error {
	if i.vault != nil {
		if len(key) > 0 {
			if !bytes.Equal(key, i.key) {
				return fmt.Errorf("changing the veil key requires a CPA restart, or a full disable and re-enable of the plugin")
			}
		} else if i.explicitKey || i.dir != dir {
			return fmt.Errorf("changing the veil key source requires a CPA restart, or a full disable and re-enable of the plugin")
		}
	} else {
		if len(key) == 0 {
			key = placeholderKey(dir)
		}
		i.key = bytes.Clone(key)
		i.vault = vault.New(key, vault.DefaultLimit)
		i.masker = mask.New(d, i.vault)
		i.trips = roundtrip.New(i.vault)
	}
	i.dir = dir
	i.masker = i.masker.WithPolicy(d, actions)
	return nil
}

func (i *pluginInstance) close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return
	}
	i.closed = true
	if i.records != nil {
		i.records.BeginDrain()
	}
	if i.trips != nil {
		i.trips.Close()
	}
	if i.records != nil {
		i.records.Close()
	}
	i.key, i.vault, i.masker, i.trips, i.records = nil, nil, nil, nil, nil
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
