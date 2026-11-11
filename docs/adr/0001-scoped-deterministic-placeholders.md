# Placeholders come from a stable secret key, bound to the Caller scope

A Placeholder's hash is the first 8 base32 characters of HMAC-SHA256 over the Caller scope, the Kind and the value, under a 32-byte secret key. Veil prefers the configured `key` (64 hexadecimal characters); otherwise it reads or creates `veil.key` (mode 0600) in `base_dir` or the original plugin directory when known. Keeping the key and Caller scope unchanged makes re-sent values produce the same Placeholders across restarts, avoiding a change to cached prompt prefixes solely from key rotation; binding the Caller scope makes a Placeholder meaningless outside the caller that minted it.

CPA [v8.0.52 loads temporary shadow copies](https://github.com/router-for-me/CLIProxyAPI/blob/v8.0.52/internal/pluginhost/shadow.go) and its [registration payload does not supply the original directory](https://github.com/router-for-me/CLIProxyAPI/blob/v8.0.52/internal/pluginhost/rpc_schema.go). A recognized shadow directory is never used for keys or rules. `base_dir` explicitly restores file resolution; Veil does not guess the installation directory or change relative rule paths to the working directory. With no usable persistent key, Veil keeps masking with a process-local key and reports that Placeholders will change on restart.

The configured key belongs in the CPA config the operator already persists, so Docker does not need an extra mount when using embedded rules. Client API keys identify Caller scopes but are not used as placeholder keys: their entropy and forwarding policy are outside Veil's control, and exposing one must not also expose the independent masking secret. Existing `veil.key` files remain valid, and copying their exact hex contents into `key` preserves Placeholders without changing the HMAC construction.

## Consequences

- Deleting or rotating the key breaks every cached prefix and leaves Placeholders held on the provider side unrestorable.
- The Vault is only in memory. Even with the same key, provider-held history (Codex compaction, `previous_response_id`) cannot restore after a restart until the corresponding original values are masked again. Stable Placeholders do not persist mappings or guarantee prompt-cache hits.
- Reloads keep the Vault, Sent forms and active streams. A change to the key, removal of an explicit key, or a change to the file-key directory requires a new instance (a CPA restart, or disabling and re-enabling Veil, on which CPA calls shutdown); the plugin rejects that reload and retains the previous valid config. Moving the same file key into config is allowed.
- Anyone holding the key can confirm a guessed value against a Placeholder offline, which is cheap for small spaces such as phone numbers, so the key is as sensitive as the values themselves.
- 8 characters is 40 bits. When two values of one Kind would share a Placeholder in a Caller scope, the newcomer gets a 12-character hash instead of silently restoring as the other value.
