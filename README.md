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

Place the shared library in your CLIProxyAPI plugin directory. The gitleaks
rules are embedded in the binary, so no extra files are required:

```text
veil/
└── veil.so        # or veil.dylib / veil.dll
```

Then enable the `veil` plugin in CLIProxyAPI.

Plugin metadata:

- Name: `veil`
- Capability: `RequestInterceptor`
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

| Field           | Type   | Default | Description                                                                            |
|-----------------|--------|---------|----------------------------------------------------------------------------------------|
| `gitleaks_toml` | string | `""`    | Custom gitleaks rule file path. Relative paths are resolved from the plugin directory. |
| `skip_models`   | array  | `[]`    | Models that should skip redaction.                                                     |
| `skip_formats`  | array  | `[]`    | Source formats that should skip redaction.                                             |

When `gitleaks_toml` is empty and no `rules/gitleaks.toml` sidecar file exists,
the plugin uses the rules embedded in the binary at build time.

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

A placeholder is `{{KIND_xxxxxxxx}}`: the kind (`EMAIL`, `PHONE`, `ID_CARD`, `BANK_CARD`, `IP`, `SECRET`) and eight
characters of an HMAC of the value. The HMAC key is generated on first start and kept in `veil.key` (mode 0600) in the
plugin directory, so placeholders survive restarts. Treat `veil.key` as sensitive: whoever holds it can confirm a
guessed value against a placeholder. Deleting it changes every placeholder.

Each client API key is its own caller scope: the same value gets a different placeholder for another key, and a
placeholder never restores for a client that did not cause it. Veil reads the key from `Authorization: Bearer`,
`x-api-key` or `x-goog-api-key` and keeps only its hash. Requests without one of these share the default scope; that
includes Gemini clients passing their key as the `?key=` query parameter, which plugins cannot see.

The mapping from placeholders back to values lives only in memory and holds the 200,000 most recently used values.

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

## Rules

Built-in rules are embedded into the shared library at build time from:

```text
rules/gitleaks.toml
```

At runtime the plugin resolves rules in this order:

1. `gitleaks_toml` config value, if set
2. `rules/gitleaks.toml` sidecar next to the shared library
3. The rules embedded at build time (default)

Update embedded rules and rebuild:

```bash
make update-rules
make build
```

You can also set `gitleaks_toml` to use your own rule file:

```yaml
gitleaks_toml: custom/gitleaks.toml
```

Relative paths are resolved from the plugin directory.

## Migrating from privacyfilter

1. Replace the `privacyfilter` shared library with `veil.so` / `veil.dylib` / `veil.dll` in its own `veil/` plugin
   directory.
2. Rename the config key from `plugins.configs.privacyfilter` to `plugins.configs.veil`. `gitleaks_toml`,
   `skip_models` and `skip_formats` keep their meaning.
3. Delete `replacement` and `replacement_labels`. Veil ignores them and logs
   `veil ignores removed config field(s): ...` at startup until they are gone.

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
