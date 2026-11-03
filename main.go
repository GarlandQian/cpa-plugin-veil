package main

import (
	"context"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.6.1"

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, removed, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if len(removed) > 0 {
		pluginLog(context.Background(), logLevelWarn, "veil ignores removed config field(s): "+strings.Join(removed, ", ")+"; delete them from plugins.configs.veil", map[string]any{
			"removed_fields": removed,
		})
	}
	pluginDir, errDir := resolvePluginDir(cfg.BaseDir, pluginDir)
	if errDir != nil {
		return pluginapi.Plugin{}, errDir
	}

	d, errDetector := newDetector(pluginDir, cfg)
	if errDetector != nil {
		return pluginapi.Plugin{}, errDetector
	}
	actions, errActions := cfg.actions()
	if errActions != nil {
		return pluginapi.Plugin{}, errActions
	}
	key, errKey := cfg.configuredKey()
	if errKey != nil {
		return pluginapi.Plugin{}, errKey
	}
	masker, v, streams, errState := maskerFor(pluginDir, key, d, actions)
	if errState != nil {
		return pluginapi.Plugin{}, errState
	}
	p := &veilPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		masker:    masker.WithValues(cfg.recordsOn()),
		restorer:  restore.New(v),
		vault:     v,
		streams:   streams,
		clean:     newBodySet(),
	}
	if cfg.recordsOn() {
		p.records, p.links = recordStore(pluginDir)
	}

	return pluginapi.Plugin{
		Metadata: pluginMetadata(),
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor:     p,
			ResponseInterceptor:    p,
			StreamChunkInterceptor: p,
		},
	}, nil
}

func pluginMetadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:             pluginName,
		Version:          pluginVersion,
		Author:           "GarlandQian",
		GitHubRepository: "https://github.com/GarlandQian/cpa-plugin-veil",
		ConfigFields: []pluginapi.ConfigField{
			{
				Name:        "key",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Secret placeholder key: 64 hexadecimal characters (32 random bytes). Keep it in config.yaml for stable placeholders across restarts; changing it requires a restart.",
			},
			{
				Name:        "base_dir",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Persistent directory for relative rule paths, rules/gitleaks.toml and veil.key (when key is unset). Relative to the host working directory. Set this when the host loads a shadow copy.",
			},
			{
				Name:        "gitleaks_toml",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Path to a gitleaks.toml that replaces the built-in rules. Empty uses built-in rules; to add rules, use rules_toml.",
			},
			{
				Name:        "rules_toml",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Path to extra gitleaks rules added to the built-in ones. A rule may set kind to name its own kind.",
			},
			{
				Name:        "disabled_rules",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Rule IDs to turn off, built-in or gitleaks.",
			},
			{
				Name:        "categories",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Turn categories on or off: secrets, personal, ssn, passport, iban, birthday, mac, serial (on); home, userhost, ip, bucket (off).",
			},
			{
				Name:        "terms",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Words to mask wherever they appear, as TERM: a string, or {term, any_case, whole_word}.",
			},
			{
				Name:        "allow",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Values never to mask, compared whole and in any case.",
			},
			{
				Name:        "actions",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "What to do per kind (EMAIL, SECRET, ...): mask (default), block the request, or warn and let it through.",
			},
			{
				Name:        "skip_models",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Model names to skip masking for.",
			},
			{
				Name:        "skip_formats",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Source format names to skip masking for.",
			},
			{
				Name:        "records",
				Type:        pluginapi.ConfigFieldTypeBoolean,
				Description: "Keep a Masking record of each request that had a value masked, warned about or blocked, never the value itself. On unless false. Records go to disk only under base_dir or, on CPA v7, the plugin directory.",
			},
		},
	}
}
