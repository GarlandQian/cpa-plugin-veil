package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"

	"gopkg.in/yaml.v3"
)

const veilProvider = "veil"
const pluginName = "veil"

type veilConfig struct {
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`
}

// removedConfigKeys are fields earlier releases accepted that no longer do
// anything. They are reported at startup rather than rejected, so an old
// config keeps loading while the operator is told what to delete.
var removedConfigKeys = []string{"replacement", "replacement_labels"}

func defaultConfig() veilConfig {
	return veilConfig{}
}

// parseConfig decodes the plugin config and lists the removed fields it still
// sets.
func parseConfig(raw []byte) (veilConfig, []string, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cfg, nil, nil
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, nil, fmt.Errorf("invalid veil config: %w", err)
	}
	var fields map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &fields); err != nil {
		return cfg, nil, fmt.Errorf("invalid veil config: %w", err)
	}
	var removed []string
	for _, key := range removedConfigKeys {
		if _, ok := fields[key]; ok {
			removed = append(removed, key)
		}
	}
	return cfg, removed, nil
}

// resolveGitleaksPath resolves the configured gitleaks rule file. The return is
// split into a path (may be empty) and an embedded flag: when the path is empty
// and embedded is true, the caller should load the rules baked into the binary.
func (cfg *veilConfig) resolveGitleaksPath(pluginDir string) (path string, embedded bool) {
	if cfg.GitleaksTOML == "" {
		builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if _, err := os.Stat(builtin); err == nil {
			return builtin, false
		}
		// No sidecar file: fall back to the rules compiled into the binary.
		return "", true
	}
	if filepath.IsAbs(cfg.GitleaksTOML) {
		return cfg.GitleaksTOML, false
	}
	return filepath.Join(pluginDir, cfg.GitleaksTOML), false
}

func (cfg *veilConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

func newDetector(pluginDir string, cfg veilConfig) (*detect.Detector, error) {
	tomlPath, embedded := cfg.resolveGitleaksPath(pluginDir)
	var source string
	switch {
	case embedded:
		source = "embedded rules"
	case cfg.GitleaksTOML != "":
		source = fmt.Sprintf("gitleaks_toml %q", tomlPath)
	default:
		source = fmt.Sprintf("sidecar rules file %q", tomlPath)
	}

	rules := embeddedGitleaks
	if !embedded {
		raw, err := os.ReadFile(tomlPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", source, err)
		}
		rules = raw
	}
	d, err := detect.New(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to create the detector from %s: %w", source, err)
	}
	loaded, skipped := d.Stats()
	pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("veil loaded %d rules, %d skipped", loaded, skipped), map[string]any{
		"rules":         loaded,
		"skipped_rules": skipped,
	})
	return d, nil
}
