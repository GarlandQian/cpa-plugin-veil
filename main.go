package main

import (
	"context"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.3.0"

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
	masker, v := maskerFor(pluginDir, d)
	p := &veilPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		masker:    masker,
		restorer:  restore.New(v),
		vault:     v,
		clean:     newBodySet(),
	}

	return pluginapi.Plugin{
		Metadata: pluginMetadata(),
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor:  p,
			ResponseInterceptor: p,
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
				Description: "Path to gitleaks.toml rules file. Empty uses built-in rules.",
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
