package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// KeyFile is the name of the file holding the Placeholder key in the plugin
// directory.
const KeyFile = "veil.key"

const keySize = 32

// LoadOrCreateKey reads the Placeholder key from dir, writing a new random one
// (mode 0600) the first time. Keeping the key across restarts keeps every
// Placeholder, and so every cached prompt prefix, the same.
func LoadOrCreateKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, KeyFile)
	if key, err := readKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate placeholder key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process wrote it first; use theirs.
		return readKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create placeholder key %s: %w", path, err)
	}
	_, errWrite := f.WriteString(hex.EncodeToString(key) + "\n")
	errClose := f.Close()
	if err = errors.Join(errWrite, errClose); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write placeholder key %s: %w", path, err)
	}
	return key, nil
}

// NewEphemeralKey returns a random key that lives only as long as the process.
func NewEphemeralKey() []byte {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func readKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != keySize {
		return nil, fmt.Errorf("placeholder key %s is not %d hex-encoded bytes", path, keySize)
	}
	return key, nil
}
