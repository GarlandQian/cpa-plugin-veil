# Placeholders come from a persisted key, bound to the Caller scope

A Placeholder's hash is the first 8 base32 characters of HMAC-SHA256 over the Caller scope, the Kind and the value, under a 32-byte key Veil writes once into the plugin directory (mode 0600) and reuses. Deterministic Placeholders let the history a client re-sends mask to the same text every turn, so prompt caches and provider-held history (Codex compaction, `previous_response_id`) keep working across restarts; binding the Caller scope makes a Placeholder meaningless outside the caller that minted it. magpie derives its Placeholders from a persisted key too, but without a scope and with one map shared across every request, which suits a single-user desktop app and not a CLIProxyAPI instance serving several callers.

## Consequences

- Deleting or rotating the key breaks every cached prefix and leaves Placeholders held on the provider side unrestorable.
- Anyone holding the key can confirm a guessed value against a Placeholder offline, which is cheap for small spaces such as phone numbers, so the key is as sensitive as the values themselves.
- 8 characters is 40 bits. When two values of one Kind would share a Placeholder in a Caller scope, the newcomer gets a 12-character hash instead of silently restoring as the other value.
