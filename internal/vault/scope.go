package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// DefaultScope is the Caller scope of requests whose client identity Veil
// cannot see, such as a Gemini client passing its key as ?key=, which never
// reaches a plugin.
const DefaultScope = ""

// ScopeOf returns the Caller scope of a request: a hash of the client's API
// key, taken from the first of Authorization: Bearer, x-api-key and
// x-goog-api-key that is set. The key itself is never kept.
func ScopeOf(headers http.Header) string {
	key := ""
	if auth := strings.TrimSpace(headers.Get("Authorization")); auth != "" {
		if scheme, token, ok := strings.Cut(auth, " "); ok && strings.EqualFold(scheme, "Bearer") {
			key = strings.TrimSpace(token)
		}
	}
	for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		if key != "" {
			break
		}
		key = strings.TrimSpace(headers.Get(name))
	}
	if key == "" {
		return DefaultScope
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
