# Veil

A CLIProxyAPI plugin that swaps sensitive values for reversible placeholders before a request reaches the upstream model, and swaps them back before the response reaches the client.

## Language

### Masking and restoring

**Mask** (脱敏):
Replacing a sensitive value in an outgoing request with its Placeholder or Stand-in.
_Avoid_: redact, filter, sanitize, scrub

**Restore** (还原):
Replacing a Placeholder or Stand-in in an incoming response with the original value it stands for.
_Avoid_: unmask, rehydrate, decode

**Placeholder** (占位符):
What a sensitive value goes upstream as, shaped `{{KIND_xxxxxxxx}}`; the same value of the same Kind gets the same Placeholder within a Caller scope while its key stays the same, across restarts too.
_Avoid_: label, replacement, token

**Stand-in** (替身):
A made-up value of the original's form that a sensitive value goes upstream as instead of a Placeholder, for Kinds a model must use exactly as written: a user name in a path, a public IP address. It is as stable as a Placeholder.
_Avoid_: fake value, decoy, shape

**Kind** (类型):
What sort of sensitive value a Placeholder stands for, such as `EMAIL` or `SECRET`.
_Avoid_: type, entity type, label

**Hit** (命中):
One span of request text found to be sensitive, together with its Kind.
_Avoid_: match, finding

**Known value** (已知值):
An original value masked once in a Caller scope, masked again wherever it reappears, later in the same request or in a later request.

**Sent form** (已发送形态):
The masked text a piece of request text became the first time it went upstream in a Caller scope; that text keeps its Sent form in later requests, even after Veil learns new Known values.
_Avoid_: snapshot, frozen text

**Host** (宿主):
The CLIProxyAPI process that loads Veil and hands it each request, response and stream chunk; when Veil answers with a failure, the Host carries on with what it had, so a request goes upstream as it stands.
_Avoid_: server, proxy

**Pass** (遍):
One time the Host hands Veil a request to mask. A request has one Pass before the Host picks a credential and one more for each credential it tries, and all of them are the same request.
_Avoid_: hook call, phase, attempt

**Round trip** (往返):
One request and the response to it: every Pass of the request, then the response, whole or streamed, until it ends. A connection that carries several requests in turn makes a Round trip of each.
_Avoid_: exchange, session, turn, lifecycle

### Isolation

**Caller scope** (调用方范围):
The client identity a request belongs to, derived from the client's API key; a Placeholder or Stand-in minted in one Caller scope never restores in another.
_Avoid_: tenant, user, session

**Default scope** (默认范围):
The Caller scope shared by requests whose client identity Veil cannot see, isolated from every other Caller scope like any other.
_Avoid_: global bucket, global scope

**Vault** (映射):
The in-memory store that maps Placeholders and Stand-ins back to their original values, partitioned by Caller scope. Only values it currently holds can be restored.
_Avoid_: map, cache, store, bucket

### Streaming and signatures

**Held tail** (扣留尾巴):
The end of a streamed chunk that might be the start of a Placeholder or Stand-in, held back until the next chunk shows whether it is.
_Avoid_: buffer, pending text

**Sealed block** (签名块):
A model reasoning block bound to a provider signature (Claude thinking, Gemini thought, OpenAI encrypted reasoning), whose text must go back to the provider exactly as it was signed; Veil neither masks nor restores it.
_Avoid_: thinking block, signed block

### Policy

**Category** (类别):
A group of detections switched on or off as a whole, such as `secrets`, `personal` or `ssn`.
_Avoid_: group, detector set

**Action** (动作):
What Veil does when it finds a Kind in a request: mask it (the default), block it, which makes a Stopped request, or warn and let it through.
_Avoid_: mode, policy

**Term** (用户词):
A word the user lists to be masked wherever it appears, under the Kind `TERM`.
_Avoid_: keyword, custom word

**Allowed value** (放行值):
A value the user lists never to be masked, even when a detection finds it.
_Avoid_: whitelist, exception

**Stopped request** (被拦请求):
A request Veil keeps from reaching the upstream, either because a Hit carries the block Action or because Veil could not mask it; a request Veil cannot mask is never sent as it is, whatever state Veil is in and even when it cannot read what the Host handed it.
_Avoid_: rejected request, fail-open

### Records

**Masking record** (脱敏记录):
What Veil did in one Round trip whose request had a Hit or was a Stopped request, in all its Passes together: which Caller scope sent it, to which model, and each value it masked or warned about, told by its Placeholder or Stand-in, its Kind and a hint, never by the value itself; and once the response is done, how many places each was restored in and which Placeholders came back that could not be restored. A request sent again is another Round trip, with a record of its own.
_Avoid_: log, audit, history
