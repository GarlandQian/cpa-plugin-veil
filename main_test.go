package main

import (
	"os"
	"testing"
)

// TestMain keeps Masking records in memory: most tests use a temporary
// directory as the plugin's, which the records' writer could still be
// writing to as the test removes it.
func TestMain(m *testing.M) {
	recordsOnDisk = false
	os.Exit(m.Run())
}
