package main

import (
	"context"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.4.0"

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
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	d, errDetector := newDetector(pluginDir, cfg)
	if errDetector != nil {
		return pluginapi.Plugin{}, errDetector
	}
	actions, errActions := cfg.actions()
	if errActions != nil {
		return pluginapi.Plugin{}, errActions
	}
	masker, v, streams := maskerFor(pluginDir, d, actions)
	p := &veilPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		masker:    masker,
		restorer:  restore.New(v),
		vault:     v,
		streams:   streams,
		clean:     newBodySet(),
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
		},
	}
}
