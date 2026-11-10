# Veil fails closed on its own because the host fails open

CLIProxyAPI sends the original body upstream when a request interceptor returns an error, and permanently fuses a plugin that panics, after which every request skips it; a plugin has no way to reject a request. So Veil recovers its own panics, never returns an error from masking, and turns a request it cannot mask, or one whose Hit carries the block Action, into a Stopped request by rewriting it so that it fails without carrying any of its original text. There is no switch to fail open: a privacy plugin that sometimes lets the plain request through gives the user nothing they can rely on.

Revised on 2026-11-07: the guarantee holds where the Host calls Veil, not inside it. The Host keeps the original body after any failure answer to a request hook, whatever caused it, so a request hook has no failure answer any more. Veil not yet registered or shutting down, a call it cannot decode, one that names no body and a panic while dispatching all make a Stopped request.

Revised on 2026-11-11: Veil works with CPA v8 only. A Host that does not offer Veil's plugin schema, as CPA v7 does not, gives no request ID to tell one request's calls from another's. Veil still registers there, in the original schema, and makes every request a Stopped request with the reason in the log. A Veil that refused to register would leave that Host running without it, sending every request unmasked.

## Consequences

- If a Host release changes the shape of what it hands Veil, every request fails loudly instead of going upstream unmasked with one warning in the log. Losing availability is accepted; leaking silently is not.
- To keep that from happening over a field Veil never reads, the request, response and stream hooks decode Veil's own shapes, holding only the fields it uses, not the SDK's types. Registration and the Management API keep the SDK's, since a failure there leaks nothing.
- A call Veil cannot decode, or one that names no body, has no body to rewrite, so it becomes `{}`; any other rewrite keeps the model and the stream flag. A body named but empty is a request with nothing to mask.
- Response and stream hooks still let a chunk through on failure: the client may see Placeholders, and nothing original reaches the upstream.
- A request that arrives while Veil shuts down fails instead of passing unmasked (ADR-0006).
- CPA v8 has `Terminate`, which keeps a request from the upstream altogether, so the Host does have a way to reject a request now. A Stopped request's answer carries both Terminate and the rewritten body: the Host refuses the request with a 403 in the client's protocol, naming the Kinds and never the values, and a Host that did not go by Terminate would still send nothing of the request.
- On a Host older than CPA v8 no request gets through. That Host has no Terminate either, so each request reaches the upstream emptied and is rejected there.
