# Veil

English | [简体中文](README.zh-CN.md)

Veil is a native privacy plugin for CLIProxyAPI. It intercepts model requests, detects sensitive values, and swaps
each one for a placeholder such as `{{EMAIL_ab12cd34}}` before the request is forwarded to an upstream provider.

Veil started as a fork of [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter).
Coming from `privacyfilter`? See [Migrating from privacyfilter](#migrating-from-privacyfilter).

AI learners and builders can join the Linux.do community: [linux.do](https://linux.do/).

Its detection engine derives from [packyme/privacy-filter](https://github.com/packyme/privacy-filter) and runs inside
the CPA plugin ABI from [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## What It Does

When CLIProxyAPI receives a request, Veil scans its text before the request leaves the local process and replaces
each sensitive value with a placeholder. The same value always gets the same placeholder for the same client, so a
conversation re-sent turn after turn masks to the same text and the provider's prompt cache keeps matching.

Typical use cases:

- Prevent accidental leakage of API keys and tokens
- Remove personal contact information before sending prompts to models
- Apply Gitleaks-style secret detection to LLM traffic
- Keep filtering local to the CLIProxyAPI plugin pipeline

## Features

- Request interceptor for the CLIProxyAPI plugin runtime
- Masks emails, phone numbers, secrets, connection strings, certificates, and similar sensitive data with stable
  placeholders, kept apart per client API key
- Restores the placeholders in model responses, tool calls included, so the client sees and runs the real values
- Shows what each request had masked under the management panel's "脱敏记录" (Masking records) menu, with original
  values available on demand while still in memory, CPA-Manager-Plus included
- Uses built-in Gitleaks rules from `rules/gitleaks.toml`
- Supports custom Gitleaks rule files
- Handles OpenAI Chat / Completions, OpenAI Responses, Claude, Gemini, and Gemini CLI request bodies
- Can skip filtering by model name or source format
- Builds as a native shared library for Linux, macOS, and Windows

## Requirements

- Go 1.26+
- CGO enabled
- `make`

## Build

Clone and build the plugin:

```bash
git clone https://github.com/GarlandQian/cpa-plugin-veil.git
cd cpa-plugin-veil

make build
```

The default build writes the shared library to the repository root:

- Linux: `veil.so`
- macOS: `veil.dylib`
- Windows: `veil.dll`

Build for a specific platform:

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

Use `BUILD_DIR` to place build output elsewhere:

```bash
BUILD_DIR=dist make build
```

## Use with CLIProxyAPI

Veil needs CLIProxyAPI v8. An older CLIProxyAPI still loads it, and Veil then stops every request and says why in the
log: a plugin that refused to load would leave every request going out unmasked.

### From the plugin store

Veil is not in the official plugin store, but CLIProxyAPI can add plugin sources with `plugins.store-sources`. Add
Veil's source to `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  store-sources:
    - "https://raw.githubusercontent.com/GarlandQian/cpa-plugin-veil/main/registry.json"
```

CLIProxyAPI reloads the config by itself, and Veil then shows up in the plugin store. Install it from the plugin store
in the management panel, or through the Management API:

```bash
curl -X POST "http://127.0.0.1:8317/v0/management/plugin-store/veil/install" \
  -H "Authorization: Bearer <management key>"
```

The store downloads the zip for your platform from this repository's latest release, checks it against
`checksums.txt`, installs it as `plugins/<os>/<arch>/veil-v<version>.dylib` (`.so` on Linux, `.dll` on Windows) and
sets `plugins.configs.veil.enabled` to `true`. No restart is needed.

### By hand

1. Download `veil_<version>_<os>_<arch>.zip` for your platform from
   [Releases](https://github.com/GarlandQian/cpa-plugin-veil/releases), for example `veil_0.9.0_darwin_arm64.zip` on
   an Apple silicon Mac. You can check it against `checksums.txt` from the same page:

   ```bash
   shasum -a 256 -c checksums.txt --ignore-missing   # sha256sum on Linux
   ```

2. Unzip `veil.so` / `veil.dylib` / `veil.dll` into `<os>/<arch>/` under the plugin directory (`plugins.dir`,
   `plugins` by default), where the plugin store installs plugins too:

   ```text
   plugins/
   └── darwin/
       └── arm64/
           └── veil.dylib   # veil.so on Linux, veil.dll on Windows
   ```

   `plugins/` itself works as well. CLIProxyAPI looks for plugins only in these two places, not in other
   subdirectories. The plugin ID is the file name, so keep it `veil` to match the `plugins.configs.veil` key.

3. Enable the plugin in `config.yaml` (see [Configuration](#configuration)) and restart CLIProxyAPI. A
   `veil loaded ... rules` line in the startup log means it loaded; `GET /v0/management/plugins` also shows
   `effective_enabled: true`.

The gitleaks rules are embedded in the binary, so no extra rule files are required. Configure `key` as described
below to keep placeholders stable across restarts. CLIProxyAPI loads a temporary copy of the library, so its loaded
location cannot hold `veil.key` or locate rules next to the installed library. Set `base_dir` when you need those
files. Where CLIProxyAPI loads the library in place, as early v8 releases do, Veil creates and reuses `veil.key` next
to it.

`key` and `base_dir` arrived in v0.4.1. v0.4.0 does not have them and changes placeholders on every CPA restart, so
upgrade before relying on them.

Plugin metadata:

- Name: `veil`
- Capabilities: `RequestInterceptor`, `ResponseInterceptor`, `StreamChunkInterceptor`
- Author: `GarlandQian`

## Configuration

The plugin is configured inside CLIProxyAPI's main config file (`config.yaml`).
Under `plugins.configs.<id>`, the host-owned fields (`enabled`, `priority`) are
consumed by CLIProxyAPI, and the remaining YAML subtree is passed to the plugin
verbatim.

Enable the plugin:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    veil:
      enabled: true
```

Enable with custom rules:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    veil:
      enabled: true
      gitleaks_toml: ""        # Empty uses embedded rules (or rules/gitleaks.toml sidecar)
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

Plugin fields:

| Field           | Type   | Default | Description                                                                                  |
|-----------------|--------|---------|----------------------------------------------------------------------------------------------|
| `key`          | string | `""`    | Secret placeholder key: 64 hexadecimal characters encoding 32 random bytes. See below.      |
| `base_dir`     | string | `""`    | Directory for relative rules, sidecar rules and `veil.key` when `key` is unset. Relative to CPA's working directory. |
| `gitleaks_toml` | string | `""`    | A gitleaks rule file that replaces the built-in rules. Relative to `base_dir`, or the original plugin directory when known. |
| `rules_toml`    | string | `""`    | A gitleaks rule file added to the built-in rules; see [Rules](#rules).                      |
| `disabled_rules`| array  | `[]`    | Rule IDs to turn off.                                                                        |
| `categories`    | object | `{}`    | Categories to turn on or off; see [Rules](#rules).                                           |
| `terms`         | array  | `[]`    | Words always masked, as `TERM`.                                                              |
| `allow`         | array  | `[]`    | Values never masked, Known values included.                                                  |
| `actions`       | object | `{}`    | What to do with each kind (`EMAIL`, `SECRET`, ...): `mask` (default), `block` or `warn`.     |
| `skip_models`   | array  | `[]`    | Models that should skip masking.                                                             |
| `skip_formats`  | array  | `[]`    | Source formats that should skip masking.                                                     |
| `records`       | bool   | `true`  | Keep a Masking record of each request with a value masked, warned about or blocked, never the value itself; on disk only under `base_dir`, or the plugin directory where CPA loads the library from it |

When `gitleaks_toml` is empty and no `rules/gitleaks.toml` sidecar file exists in the resolved base directory,
the plugin uses the rules embedded in the binary at build time.

### Keeping placeholders stable across restarts

Generate a key once with `openssl rand -hex 32`, then save the result in the CPA config you already persist:

```yaml
plugins:
  enabled: true
  configs:
    veil:
      enabled: true
      key: "<paste the 64 hexadecimal characters here>"
```

Keep this key secret and unchanged. It is independent of client API keys and is never sent upstream. With the
embedded rules, Docker needs only the existing persistent CPA config; no additional directory mount is needed.

`key` takes precedence over `veil.key` and does not read or write a key file. Without `key`, Veil loads or creates
`veil.key` (mode 0600) in `base_dir`, or in the library's own directory where CLIProxyAPI loads it in place. If no
persistent directory is known (as when CLIProxyAPI loads a temporary copy and `base_dir` is unset), or the key file
cannot be used, Veil masks with an in-memory key and logs a warning or error: placeholders then change on restart. It
never writes a key into a recognized CPA shadow directory.

To keep the placeholders of an existing `veil.key`, such as one written under CLIProxyAPI v7, copy its contents into
`key`, or set `base_dir` to the directory containing that file. Both preserve its exact key bytes. Do not generate a
replacement key during that migration. A key already deleted with its old shadow directory cannot be recovered.

Hot reloads keep the Vault and active streams. Moving the same key from `veil.key` into `key` works on reload;
changing the key, removing an explicit key, or changing the directory used for a file key requires a CPA restart,
or disabling and re-enabling Veil.
Such a reload is rejected with a log message and the previous valid configuration remains active.

When the host calls shutdown, Veil stops accepting calls, waits for current calls, finishes active stream counts
and drains the record writer before releasing its instance. CPA does this when disabling or uninstalling Veil;
re-enabling then starts a new Vault and new Sent forms. The persisted key and record files remain, but a new instance
can restore old placeholders only after their original values are masked again. An ordinary config reload keeps this
memory state.

### External rule files

Set `base_dir` to the original directory containing your rules, for example:

```yaml
plugins:
  configs:
    veil:
      base_dir: plugins/darwin/arm64
      rules_toml: rules/extra.toml
```

This also finds `rules/gitleaks.toml` under that directory when `gitleaks_toml` is empty. `base_dir` must exist and
is resolved against the CPA process's working directory, not the location of `config.yaml`. Absolute
`gitleaks_toml` and `rules_toml` paths work without `base_dir`. If CPA has not supplied the original plugin directory,
relative rule paths without `base_dir` are rejected; Veil does not guess a directory or silently load rules from
the working directory. With no external rules configured, it uses its embedded rules.

### Blocking and warning

`actions` changes what happens to a kind of value:

```yaml
plugins:
  configs:
    veil:
      actions:
        SECRET: block   # stop any request that holds a secret
        EMAIL: warn     # let emails through, but log them
```

- `mask` (the default) replaces the value with its placeholder.
- `warn` sends the value as it is and logs a warning with the kind and the JSON path, never the value.
- `block` stops the request.

A stopped request never reaches the upstream: the client gets a 403 with an error in the shape of its own protocol,
naming the kinds that stopped it, never the values or where they were. The CLIProxyAPI log says why:
`veil stopped a request: ...`.

Veil fails closed the same way: if it cannot mask a request, for example because the body starts like JSON but does
not parse, or because masking failed, it stops the request instead of letting it through. A plugin error would make
CLIProxyAPI send the original body, so a request hook never answers with one: a request that reaches Veil while it is
shutting down, or a call Veil cannot read, is stopped too. If a CLIProxyAPI release ever changes what it hands Veil so
that Veil cannot read it, requests fail with that message in the log instead of going upstream unmasked. A request body
that is not JSON at all passes through untouched. If restoring a response fails, the response reaches the client with
its placeholders.

### Invalid configuration

- At startup (`plugin.register`), an invalid config makes registration fail. CLIProxyAPI logs the reason and the
  plugin is not enabled, so check `GET /v0/management/plugins` for `effective_enabled: true`.
- On a hot reload (`plugin.reconfigure`), an invalid config is rejected and the plugin **keeps redacting with the
  previous valid config**, so a typo cannot silently turn filtering off. The host log shows an error such as
  `veil rejected new config, still using the previous valid config: ...` naming the bad field. Fix the
  config and save again to apply it.

### Logging

Plugin logs go through the host's `host.log` callback, so they follow CLIProxyAPI's log level, format, and output and
carry the request ID. Each interception pass that masks something produces one line with the count per kind and the
JSON paths of the masked fields, for example
`veil masked 3 value(s) (EMAIL=2, SECRET=1) in 2 field(s): messages[0].content, system`. Values, parts of values and
their lengths are never logged.

## How It Works

Veil masks in both the before-auth and after-auth request interception hooks. Both see the client-format body
(before executor translation). The after-auth pass catches text that other plugins add later in the chain, for
example a lower-priority before-auth interceptor or a higher-priority after-auth interceptor. Masking is idempotent,
so an already-masked body produces no new hits, and a body the before-auth pass already masked is not scanned again.

1. Checks `skip_models` and `skip_formats`.
2. Parses the request body as JSON; anything else passes through unchanged.
3. Finds the client's caller scope (see below).
4. Masks every string of the request except the ones listed below, and writes the rest of the body back byte for byte.

What is masked:

- All conversation text of every client format: OpenAI Chat / Completions, OpenAI Responses, OpenAI image and video
  prompts, embeddings input, Claude, Gemini and the Gemini CLI `request` wrapper.
- Tool calls and tool results: OpenAI `arguments` (a JSON string, masked value by value so it stays valid JSON),
  Claude `tool_use.input` and `tool_result`, Gemini `functionCall.args` and `functionResponse.response`. Their keys
  belong to the tool, so every string under them is masked.
- The `description` of tool definitions and request settings, and nothing else under them.

What is left alone:

- Signed reasoning: Claude `thinking` and `redacted_thinking` blocks, OpenAI Responses `reasoning` items and Gemini
  parts marked `thought: true`. They must go back to the provider exactly as it signed them.
- Identifiers, names and protocol fields: `id` and anything ending in `_id`, `Id` or `_ids`, `name`, `model`, `type`,
  `role`, `signature`, `encrypted_content`, `url`, `image_url`, `media_type` and the like.
- Binary data: `data` and `file_data` (except a Claude document's plain-text source) and any `data:` URL.

Beyond what the rules find, Veil masks a value wherever it reappears:

- A value found anywhere in a request is masked everywhere in that request, so a secret recognised by its
  `password:` label is also masked where it appears on its own.
- A value of 8 bytes or more masked once stays known for that client and is masked in later requests too.
- Text a client already sent keeps the form it was sent in, even after Veil learns a new value that occurs in it,
  so the provider's cached prompt prefix still matches.

### Placeholders and caller scope

A placeholder is `{{KIND_xxxxxxxx}}`: the kind (`EMAIL`, `SECRET`, `PASSWORD`, ... see [Rules](#rules)) and eight
characters of an HMAC of the value. The same key and caller scope produce the same placeholder across restarts;
see [Keeping placeholders stable across restarts](#keeping-placeholders-stable-across-restarts) for key storage.
Treat both `key` and `veil.key` as sensitive: whoever holds the key can confirm a guessed value against a
placeholder. Rotating or losing it changes every placeholder.

Each client API key is its own caller scope: the same value gets a different placeholder for another key, and a
placeholder never restores for a client that did not cause it. Veil reads the key from `Authorization: Bearer`,
`x-api-key` or `x-goog-api-key` and keeps only its hash. Requests without one of these share the default scope; that
includes Gemini clients passing their key as the `?key=` query parameter, which plugins cannot see.

The mapping from placeholders back to values lives only in memory and holds the 200,000 most recently used values.
Even with a stable key, a restart loses these mappings. Re-sending original text rebuilds them with the same
placeholders; history kept only by the provider (including compaction or `previous_response_id`) cannot rebuild
them on its own, so old placeholders can reach the client unrestored. Keeping the key does not persist the Vault
or guarantee a prompt-cache hit; it avoids changing the placeholders solely because of a restart.

### Stand-ins for user names and public IP addresses

When the `home`, `userhost` or `ip` category is on, a user name goes upstream as eight made-up lowercase letters
(`/Users/qmzvkrta/project`) and a public IP address as `public-ip-` and eight letters (`ssh root@public-ip-kvxqmrtz`)
instead of a `{{KIND_…}}` placeholder. Models read `/Users/{{USERNAME_…}}` as a template or a temporary folder, and
asked for the real address of `{{IP_…}}` instead of using it; a home folder that still looks like one, and a host
name that reaches no one, they use as they are, and the value comes back restored in the tool call. Stand-ins are as
stable as placeholders, kept apart per client, restored in any case and only as whole words, and a value whose
stand-ins are all taken by other values goes as a placeholder. Host names and buckets use placeholders.

### Restoring responses

Before a response reaches the client, Veil puts the original values back wherever the model wrote a placeholder of
the same client: in text, in tool calls (OpenAI `arguments` are restored inside their JSON, with values escaped as
JSON needs), in Claude `tool_use.input` and in Gemini `functionCall.args`. A tool the client runs therefore gets the
real value, and when the client sends the conversation back, those values mask to the same placeholders again.

- Models do not always copy a placeholder exactly. Veil also restores it with its kind or hash in another case,
  with spaces inside the braces, or with one or both braces missing, as long as it names a placeholder the vault
  holds for that client.
- Signed reasoning (thinking blocks, reasoning items, Gemini thought parts) is not restored, so it goes back to the
  provider exactly as signed; the client may see placeholders there.
- A placeholder the vault no longer holds, for example one kept only in a provider-side conversation from before a
  restart, reaches the client unchanged.

Streamed responses are restored too. A model streams a placeholder in pieces, so when an event's text ends in what
may be the start of one (`{{`, `{{EMA`, `EMAIL_ab`...), Veil holds that event back until the next event of the same
block shows how it continues, then sends both with the value restored. Ping events pass by a held event; any other
event releases it unchanged, and the last event of a block is never held. Events go out whole and in order, so the
SSE framing, event names and sequence numbers the client sees are those the provider sent.

Veil knows a stream's chunks by the request's ID, so CLIProxyAPI does not send it the request bodies with every
chunk, and a long conversation costs a stream no more than a short one.

Common `skip_formats` values are the host's source format names, such as `openai`, `openai-response`, `claude`,
`gemini`, `gemini-cli`, `openai-image`, and `openai-video`.

Supported request shapes include:

```json
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Email me at user@example.com"
    }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

## Masking records

Veil keeps a Masking record of each request that had a value masked, warned about or blocked, and of each Stopped
request. A "脱敏记录" (Masking records) entry appears in management panels that show plugin menus, such as
CPA-Manager-Plus, and the page below can be opened directly too. It has:

- **Overview**: places with sensitive values and how many different values, requests and Stopped requests, places
  the responses restored and Placeholders they could not, values sent as written; requests per day; what Kinds, how
  they were found (each rule told in plain words), which callers and models; the values seen most often.
- **Requests**: newest first, each with its Kinds and counts, what the response restored and a line of context;
  filtered by Kind, caller, model or Action, or Stopped requests only. This is the default view; empty records show
  a single explanation and an entry to Try it. An empty overview hides its charts and breakdown cards.
- **A request**: a full-width detail page with safe context on the left and detected values on the right. Repeated
  snippets appear once; selecting a value highlights its occurrences. Each value shows its Kind, Action, hint,
  length, rule, places and restore count. Rule explanations, field paths and false-positive guidance can be expanded.
  Previous/next buttons move through loaded requests. **Show originals**
  reads available values from the current Vault and adds original snippets beside the safe preview; **Hide originals**
  removes them from the page. Snippets are reconstructed from current mappings, not a saved original request.
- **Live updates**: while visible, the page checks for new records and restore statistics every 3 seconds, including
  the open request. The switch pauses or resumes updates; hidden pages and Try it do not poll. Filters, loaded pages,
  selected values and expanded explanations are preserved. While reading older rows, new records wait behind a
  clickable notice so the list does not move. Original values are fetched only by Show originals, never by polling.
- **Clear records**: deletes the current directory’s records, including queued writes. Late restore counts cannot
  bring cleared records back; new requests continue recording and conversations in progress keep restoring.
- **Try it**: shows how a text would be masked under the current settings, keeping nothing and touching no
  conversation.

Record files and ordinary record responses **never hold original values**. The authenticated management API can
reveal a record's masked values from its own Caller scope on request (ADR-0005). The management key authorizes
viewing available originals across callers. Nothing is added to record files or browser storage; the page drops
revealed values when hidden, closed, cleared, or returned to login. Only mappings still in the Vault can be shown:
restart or eviction can make them unavailable even with a fixed key. Values only warned about or in Stopped requests
are not retained for this feature.

Callers are told apart by client API key: the page shows the alias CPA-Manager-Plus has for the key, else the key's
last four characters, and "Default caller" for requests without a key. Veil keeps no key.

### Storage

- Memory holds the newest 1000 records, the newest 400 of them with context (40 characters either side of each
  value's first Placeholder); context is in memory only. This safe preview hides every detected value, including
  values sent as written under `warn`, so it is not always the exact text sent upstream.
- With a persistent directory, records also go to `veil-records/` there, a file a day with mode 0600, kept 30 days and
  100 MB in all, without context. The directory is `base_dir`, or without it the plugin library's directory where
  CLIProxyAPI loads the library in place. Where it loads a temporary copy, records without `base_dir` live in memory
  and are gone when CPA restarts.
- Changing `base_dir` finishes records already accepted in the old directory; later records use the new one.
  Restore counts follow their original record, even if its response finishes after the switch. The page shows
  only the current directory. Old files stay in place, and clearing the page does not delete them. With a file
  key, changing directories still requires a new instance as described above.
- Restore counts find their record by caller and request ID.
- Records are written in the background and never make a request wait; when the queue is full a record is dropped,
  and the page says how many were.
- "First time" is judged from the mappings in memory and starts over when CPA restarts.

To keep no records, set `records: false`:

```yaml
plugins:
  configs:
    veil:
      records: false
```

### Page and API

The page is `/v0/resource/plugins/veil/index.html`. CLIProxyAPI does not authenticate plugin pages, so the page holds
no data and reads the records from Management API routes behind the management key:

| Route | What it does |
|---|---|
| `GET /v0/management/plugins/veil/summary?days=7` | A summary of the last days (1 to 30) |
| `GET /v0/management/plugins/veil/records` | The records, each with a `glimpse` of its context, with `before`, `limit`, `kind`, `caller`, `model`, `action`, `stopped=1` |
| `GET /v0/management/plugins/veil/record?key=` | One record, with its context and what was restored |
| `GET /v0/management/plugins/veil/record-values?key=` | Available originals for one existing record, as `{"values": {"placeholder": "original"}}`; missing mappings are omitted, responses use `Cache-Control: no-store` |
| `POST /v0/management/plugins/veil/clear` | Clears the records |
| `POST /v0/management/plugins/veil/preview` | Previews `{"text": "..."}`, up to 64 KB |

Opened from CPA-Manager-Plus, the page reads the management key the panel saved ("remember" on) and follows the
panel's theme and language; without a saved key it asks for one, kept for that tab only.

## Rules

### What Veil finds

Detections are grouped in categories, each switched on or off as a whole with `categories`:

| Category   | Kinds                                  | Default | Finds                                                                                     |
|------------|----------------------------------------|---------|-------------------------------------------------------------------------------------------|
| `secrets`  | `SECRET`, `PASSWORD`, `PRIVATE_KEY`    | on      | Vendor keys (gitleaks and known prefixes), passwords and keys written after their name, URL passwords, Authorization and Cookie headers, private keys, random strings next to a secret's name |
| `personal` | `EMAIL`, `PHONE`, `ID_CARD`, `BANK_CARD` | on    | Emails on a real domain, mainland mobile numbers outside an id's context, mainland ID numbers with a valid check digit, card numbers passing Luhn |
| `ssn`      | `SSN`                                  | on      | US Social Security numbers in the ranges the SSA issues                                   |
| `passport` | `PASSPORT`                             | on      | Passport numbers after "passport" / 护照                                                   |
| `iban`     | `IBAN`                                 | on      | IBANs with a valid checksum                                                               |
| `birthday` | `BIRTHDAY`                             | on      | Dates after "birthday", "DOB", 生日 and the like, over a year ago                          |
| `mac`      | `MAC`                                  | on      | MAC addresses, except documentation and broadcast ones                                    |
| `serial`   | `SERIAL`                               | on      | Serial numbers after "S/N", "serial", 序列号                                               |
| `home`     | `USERNAME`                             | off     | The user name in a home folder: `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`       |
| `userhost` | `USERNAME`, `HOSTNAME`                 | off     | `user@host` in shell prompts and ssh/scp/rsync commands, `hostname:` and `User:` lines    |
| `ip`       | `IP`                                   | off     | Public IPv4 and IPv6 addresses; never private, loopback, link-local, CGNAT, documentation addresses or public DNS resolvers |
| `bucket`   | `BUCKET`                               | off     | Cloud storage buckets in `s3://`, `gs://` and similar URLs and hosts                     |

The `home`, `userhost`, `ip` and `bucket` categories are off by default because home folders and hosts appear in
nearly every coding request and the model has to copy them exactly.

Beyond what a value looks like, Veil masks the whole value of a field named for a secret (`api_key`, `password`,
`client_secret`, `Authorization`, `db_pass`, ...) when it has 8 characters or more, whatever it looks like, unless the
value is in `allow` or the `secrets` category is off. To keep false positives down it leaves alone UUIDs, long hex ids and digests (and any piece of one), decimals, bare JSON
numbers, values of fields named for an id, code that names a secret (`token = get_token_v2`), versions, paths,
file positions and placeholders such as `${API_KEY}`. A random string with no secret's name near it is not a secret.

### Your own rules

```yaml
plugins:
  configs:
    veil:
      categories:
        ip: true          # turn a category on (or off)
      terms:              # always masked, as TERM
        - 烛龙
        - {term: Phoenix, any_case: true, whole_word: true}
      allow:              # never masked, compared whole and in any case
        - support@acme-corp.cn
      rules_toml: rules/extra.toml   # gitleaks rules added to the built-in ones
      disabled_rules:     # rule IDs to turn off
        - phone-cn
```

A rule in `rules_toml` may name its own kind, in upper case and at most 24 characters:

```toml
[[rules]]
id = "internal-ticket"
regex = '''TKT-[0-9]{6}'''
keywords = ["tkt-"]
kind = "TICKET"
```

`disabled_rules` takes gitleaks rule IDs and Veil's own: `email`, `phone-cn`, `id-card-cn`, `bank-card`,
`url-password`, `named-secret`, `env-secret`, `auth-header`, `key-field`, `cjk-password`, `cjk-secret`,
`copula-secret`, `context-secret`, `high-entropy`, the `vendor-*` key rules and each category's rules. An unknown
category or rule ID fails the config.

### Built-in gitleaks rules

Built-in rules are embedded into the shared library at build time from:

```text
rules/gitleaks.toml
```

As in gitleaks, a rule masks only its secret (its `secretGroup`, else its first capture group) and keeps its
allowlists, the file's own `[allowlist]` too: their `regexes` (on the secret, the match or the line, by
`regexTarget`), their `stopwords` and their `condition`. `paths` and `commits` never match, a request having neither.

At runtime the plugin resolves rules in this order:

1. `gitleaks_toml` config value, if set (it replaces the built-in rules; use `rules_toml` to add to them)
2. `rules/gitleaks.toml` under `base_dir`, or next to the original shared library when its directory is known
3. The rules embedded at build time (default)

Update embedded rules and rebuild:

```bash
make update-rules
make build
```

Relative paths are resolved from `base_dir`, or the original plugin directory when known. Set `base_dir` or use
absolute paths; see [External rule files](#external-rule-files).

## Migrating from privacyfilter

1. Delete the old library, `privacyfilter.so` / `privacyfilter.dylib` / `privacyfilter.dll`: under
   `plugins/<os>/<arch>/` if the plugin store installed it, usually under `plugins/` if you did. Do not skip this:
   with both plugins loaded, the old one may turn values into labels such as `[EMAIL]` first, and Veil cannot
   restore those.
2. Install Veil as in [Use with CLIProxyAPI](#use-with-cliproxyapi).
3. Rename the config key from `plugins.configs.privacyfilter` to `plugins.configs.veil`. `gitleaks_toml`,
   `skip_models` and `skip_formats` keep their meaning.
4. Delete `replacement` and `replacement_labels`. Veil ignores them and logs
   `veil ignores removed config field(s): ...` at startup until they are gone.
5. Restart CLIProxyAPI.

Expect different hits: values are now replaced by placeholders and restored in responses; IP addresses are no longer
masked by default (turn on the `ip` category for public ones); emails at documentation domains such as `example.com`,
ID numbers with a wrong check digit and phone numbers that read as order ids are left alone; tool call arguments and
tool results are masked too.

### Existing conversations

Conversations you had before keep working after the switch. The old plugin changed only the requests sent upstream,
never the responses, so your client's history holds the original text, and Veil replaces the values in it with
placeholders before it goes out. Two things to know:

- On the first request after the switch, the upstream sees `{{EMAIL_…}}` where the history used to say `[EMAIL]`, so
  that conversation misses the prompt cache once and its whole history is written to the cache again. From then on
  a value keeps its placeholder and the cache matches as usual.
- The old plugin never kept the values it replaced, so labels such as `[EMAIL]` in the model's earlier replies cannot
  be restored and stay in the history as they are. New replies are restored as usual.

## Development

Common commands:

```bash
go test ./...
make build
make clean
```

Main files:

```text
main.go                 Plugin metadata and build entry
abi.go                  CLIProxyAPI plugin ABI adapter
interceptor.go          Request interception and redaction logic
config.go               YAML configuration parsing
internal/detect/        Detection engine: PII patterns, gitleaks rules, keyword prefilter, hit cache
internal/jsontree/      Byte-preserving JSON parser that rewrites only the strings it changes
rules/gitleaks.toml     Built-in detection rules
```

Run the long-session benchmark (an 80-turn agent session, both hooks per request):

```bash
go test -run '^$' -bench LongSession .
```

### Performance

An agent re-sends its whole history every turn, so Veil is built for repeated text:

- One Aho-Corasick pass over each text finds which gitleaks rules' keywords occur, and only those rules run.
- Detection results of texts of 256 bytes or more are cached by hash (offsets only, never text), so history that was
  already scanned costs one hash per field.
- The request body is parsed into byte spans; only redacted strings are re-encoded and every other byte is copied
  through, so key order, number spelling and base64 payloads are untouched.
- The after-auth hook skips a body the before-auth hook already left clean.

## Credits

- Detection engine derived from [packyme/privacy-filter](https://github.com/packyme/privacy-filter) (MIT); see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
