package main

import "testing"

// TestNewDetector_UsesEmbeddedRules simulates a store install: an empty plugin
// directory with no rules/gitleaks.toml sidecar. newDetector must still load
// the embedded rules, proving the plugin works without a sidecar.
func TestNewDetector_UsesEmbeddedRules(t *testing.T) {
	d, err := newDetector(t.TempDir(), defaultConfig())
	if err != nil {
		t.Fatalf("newDetector() with embedded rules error = %v", err)
	}
	rules, _ := d.Stats()
	if rules < 100 {
		t.Fatalf("expected the embedded gitleaks rules to load, got %d rules", rules)
	}
}
