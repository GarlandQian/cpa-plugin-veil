package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// resolvePluginDir prefers an operator's explicit base_dir, then the host's
// original directory when supplied, then the loaded library's directory. CPA
// v8 shadow copies contain only the library and cannot hold persistent data.
func resolvePluginDir(baseDir, pluginDir string) (string, error) {
	if baseDir != "" {
		pluginDir = baseDir
	} else if pluginDir == "" {
		pluginDir = inferPluginDir()
	}
	if pluginDir == "" {
		return "", nil
	}
	dir, err := filepath.Abs(pluginDir)
	if err != nil {
		return "", fmt.Errorf("resolve plugin directory: %w", err)
	}
	// Resolve aliases too: on macOS a temporary path may start with /var or
	// /private/var, and base_dir may itself be a symlink.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	if isShadowPluginDir(dir) {
		if baseDir != "" {
			return "", fmt.Errorf("base_dir points to a temporary CPA shadow directory; use a persistent directory")
		}
		noteShadowCopy()
		return "", nil
	}
	if baseDir != "" {
		info, err := os.Stat(dir)
		if err != nil {
			return "", fmt.Errorf("base_dir: %w", err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("base_dir must be a directory")
		}
	}
	return dir, nil
}

// noteShadowCopy says once per process that files beside the installed
// library are out of reach. It is no warning: a configured key and the
// embedded rules need nothing from that directory, and a missing key or a
// relative rule path is reported where it goes wrong.
func noteShadowCopy() {
	masking.Lock()
	noted := masking.shadowNoted
	masking.shadowNoted = true
	masking.Unlock()
	if !noted {
		pluginLog(context.Background(), logLevelInfo, "veil runs from a temporary CPA shadow copy, so files beside the installed library such as rules/gitleaks.toml are not read; set base_dir to use them", nil)
	}
}

// This recognizes the v8.0.52 layout, not an ABI guarantee. An explicit
// base_dir avoids depending on the host's loading layout entirely.
func isShadowPluginDir(dir string) bool {
	dir = filepath.Clean(dir)
	if filepath.Base(filepath.Dir(dir)) != "cliproxy-pluginhost" {
		return false
	}
	pid, ok := strings.CutPrefix(filepath.Base(dir), "pid-")
	if !ok || pid == "" {
		return false
	}
	for _, c := range pid {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(pid)
	return err == nil && n > 0
}
