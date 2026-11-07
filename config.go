package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"

	"gopkg.in/yaml.v3"
)

const pluginName = "veil"

type veilConfig struct {
	Key           string            `yaml:"key"`
	BaseDir       string            `yaml:"base_dir"`
	GitleaksTOML  string            `yaml:"gitleaks_toml"`
	RulesTOML     string            `yaml:"rules_toml"`
	DisabledRules []string          `yaml:"disabled_rules"`
	Categories    map[string]bool   `yaml:"categories"`
	Terms         []termConfig      `yaml:"terms"`
	Allow         []string          `yaml:"allow"`
	SkipModels    []string          `yaml:"skip_models"`
	SkipFormats   []string          `yaml:"skip_formats"`
	Actions       map[string]string `yaml:"actions"`
	// Records keeps a Masking record of each request; on unless false.
	Records *bool `yaml:"records"`
}

// recordsOn says Masking records are kept.
func (cfg *veilConfig) recordsOn() bool {
	return cfg.Records == nil || *cfg.Records
}

// termConfig is a Term, written as the word alone or with its options:
//
//	terms:
//	  - 烛龙
//	  - {term: Phoenix, any_case: true, whole_word: true}
type termConfig struct {
	Term      string `yaml:"term"`
	AnyCase   bool   `yaml:"any_case"`
	WholeWord bool   `yaml:"whole_word"`
}

func (t *termConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		t.Term = node.Value
		return nil
	}
	type plain termConfig
	return node.Decode((*plain)(t))
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
	if _, err := cfg.configuredKey(); err != nil {
		return cfg, nil, err
	}
	if _, err := cfg.actions(); err != nil {
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

// configuredKey accepts the same encoding as veil.key, so copying an existing
// key into the config preserves Placeholders. Never include its value in errors.
func (cfg *veilConfig) configuredKey() ([]byte, error) {
	if cfg.Key == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(cfg.Key))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid veil config: key must be 64 hexadecimal characters (32 bytes)")
	}
	return key, nil
}

// actions returns the configured Action of each Kind, keyed by the Kind in
// upper case.
func (cfg *veilConfig) actions() (map[string]mask.Action, error) {
	out := make(map[string]mask.Action, len(cfg.Actions))
	for kind, action := range cfg.Actions {
		name := strings.ToUpper(strings.TrimSpace(kind))
		if name == "" {
			return nil, fmt.Errorf("actions: empty kind")
		}
		switch a := mask.Action(strings.ToLower(strings.TrimSpace(action))); a {
		case mask.Mask, mask.Block, mask.Warn:
			out[name] = a
		default:
			return nil, fmt.Errorf("actions[%s]: %q is not mask, block or warn", kind, action)
		}
	}
	return out, nil
}

// resolveGitleaksPath resolves the configured gitleaks rule file. The return is
// split into a path (may be empty) and an embedded flag: when the path is empty
// and embedded is true, the caller should load the rules baked into the binary.
func (cfg *veilConfig) resolveGitleaksPath(pluginDir string) (path string, embedded bool, err error) {
	if cfg.GitleaksTOML == "" {
		if pluginDir != "" {
			builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
			if _, err := os.Stat(builtin); err == nil {
				return builtin, false, nil
			}
		}
		// No sidecar file: fall back to the rules compiled into the binary.
		return "", true, nil
	}
	path, err = resolveRulePath(pluginDir, cfg.GitleaksTOML, "gitleaks_toml")
	return path, false, err
}

func resolveRulePath(pluginDir, path, field string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	if pluginDir == "" {
		return "", fmt.Errorf("%s is relative but the original plugin directory is unavailable; set base_dir or use an absolute path", field)
	}
	return filepath.Join(pluginDir, path), nil
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
	tomlPath, embedded, err := cfg.resolveGitleaksPath(pluginDir)
	if err != nil {
		return nil, err
	}
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
	opts := detect.Options{
		Categories:    cfg.Categories,
		Allow:         cfg.Allow,
		DisabledRules: cfg.DisabledRules,
	}
	for _, t := range cfg.Terms {
		opts.Terms = append(opts.Terms, detect.Term{Text: t.Term, AnyCase: t.AnyCase, WholeWord: t.WholeWord})
	}
	if cfg.RulesTOML != "" {
		path, err := resolveRulePath(pluginDir, cfg.RulesTOML, "rules_toml")
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules_toml %q: %w", path, err)
		}
		opts.ExtraRules = raw
	}
	d, err := detect.New(rules, opts)
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
