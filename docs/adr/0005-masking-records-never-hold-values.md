# Masking records never hold the values they mask

A Masking record tells each value by its Placeholder or Stand-in, its Kind and a hint (its first character or a key's prefix, and its length), never by the value, and the page that shows the records offers no way to see one, although the Vault holds the originals while CPA runs. magpie shows the original behind a placeholder while it remembers it, which suits a single-user desktop app; a CLIProxyAPI instance serves several callers, so a page that could show originals would hand whoever holds the management key every caller's secrets and personal data. The page serves no data itself (CPA does not authenticate plugin resource pages): it reads the records from management routes, with the management key CPA-Manager-Plus already keeps, or one typed in.

## Consequences

- Telling a false positive apart relies on the hint and on short context around the Placeholder as the upstream saw it, kept in memory only for the latest records; the full request body is not kept.
- Records go to disk only where Veil has a persistent directory (`base_dir`, or the library's directory on CPA v7); on CPA v8 without `base_dir` they live in memory and are gone after a restart.
