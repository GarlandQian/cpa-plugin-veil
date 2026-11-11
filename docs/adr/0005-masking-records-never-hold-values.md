# Masking records never hold the values they mask

A Masking record tells each value by its Placeholder or Stand-in, its Kind and a hint (its first character or a key's prefix, and its length), never by the value. Revised on 2026-11-04 at the operator's request: the management page may reveal a record's original values on demand from the running Vault, so an operator can identify a value and assess a false positive. The management key therefore authorizes viewing available originals across callers; the earlier decision that the page could never reveal values is replaced, while the rule against retaining originals in records remains.

The page serves no data itself (CPA does not authenticate plugin resource pages). A dedicated management route reads an existing record and resolves only its masked values in that record's Caller scope; it does not accept a caller or arbitrary placeholders from the browser. CPA authenticates this route with the same management key used for the other record routes. Its response uses `Cache-Control: no-store`. The page fetches originals only when requested, renders them as text, and drops its copy when hidden, closed, cleared, or returned to login.

## Consequences

- The original-value view is available only while the Vault remembers the mapping. Restart, instance shutdown or eviction can make a value unavailable; masking the same original again under the same key and Caller scope can make it available again. A stable key does not persist originals.
- Values only warned about or in Stopped requests are not retained for this feature. Their candidate placeholders are not looked up, since they may not name a minted mapping.
- Ordinary record and summary responses still contain no originals. Short context is kept only in memory for the latest records; every detected value is hidden there, including values sent as written under `warn`. It is a safe preview, not necessarily the exact upstream text. The full request body is not kept. Original context is reconstructed from these snippets and available mappings, not from a saved original request.
- Records go to disk only where Veil has a persistent directory (`base_dir`, or the library's directory where CPA loads it in place); where CPA loads a shadow copy and `base_dir` is unset they live in memory and are gone after a restart.
