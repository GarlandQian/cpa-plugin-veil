# Veil

[English](README.md) | 简体中文

Veil 是 CLIProxyAPI 的隐私插件：在请求发送给模型前识别敏感值，把每个值换成 `{{EMAIL_ab12cd34}}` 这样的占位符。

Veil 源自 [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter) 的分支。
从 `privacyfilter` 迁移过来？请看[从 privacyfilter 迁移](#从-privacyfilter-迁移)。

学 AI 就上 L 站：[linux.do](https://linux.do/)。

检测引擎源自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)，运行在
[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的 CPA 插件 ABI 之上。

## 作用

当 CLIProxyAPI 收到请求时，Veil 会在请求离开本地进程前扫描其中的文本，把每个敏感值换成占位符。同一个客户端的同一个值始终得到同一个占位符，
所以每一轮重发的对话都掩码成相同的文本，上游的提示词缓存也能持续命中。

典型场景：

- 防止 API Key 和 Token 意外泄露
- 在提示词发送给模型前移除个人联系方式
- 对 LLM 请求流量应用 Gitleaks 风格的密钥检测
- 将过滤逻辑保留在 CLIProxyAPI 插件链路内

## 功能

- CLIProxyAPI 插件运行时的请求拦截器
- 用稳定的占位符掩码邮箱、手机号、密钥、连接串、证书等敏感内容，不同客户端 API key 之间相互隔离
- 把模型回复（包括工具调用）里的占位符还原成原值，客户端看到和执行的都是真实值
- 使用内置 Gitleaks 规则 `rules/gitleaks.toml`
- 支持自定义 Gitleaks 规则文件
- 支持 OpenAI Chat / Completions、OpenAI Responses、Claude、Gemini 和 Gemini CLI 请求体
- 可按模型名或来源格式跳过过滤
- 可构建为 Linux、macOS、Windows 原生共享库

## 环境要求

- Go 1.26+
- 启用 CGO
- 已安装 `make`

## 构建

克隆并构建插件：

```bash
git clone https://github.com/GarlandQian/cpa-plugin-veil.git
cd cpa-plugin-veil

make build
```

默认会在仓库根目录生成共享库：

- Linux: `veil.so`
- macOS: `veil.dylib`
- Windows: `veil.dll`

指定平台构建：

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

使用 `BUILD_DIR` 指定输出目录：

```bash
BUILD_DIR=dist make build
```

## 在 CLIProxyAPI 中使用

将共享库放入 CLIProxyAPI 的插件目录即可。Gitleaks 规则已内嵌到二进制中，无需额外文件：

```text
veil/
└── veil.so        # 或 veil.dylib / veil.dll
```

然后在 CLIProxyAPI 中启用 `veil` 插件。

插件注册信息：

- 名称：`veil`
- 能力：`RequestInterceptor`、`ResponseInterceptor`、`StreamChunkInterceptor`
- 作者：`GarlandQian`

## 配置

插件在 CLIProxyAPI 主配置文件（`config.yaml`）中配置。`plugins.configs.<id>` 下，
宿主字段（`enabled`、`priority`）由 CLIProxyAPI 处理，其余 YAML 子树原样透传给插件。

启用插件：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    veil:
      enabled: true
```

启用并自定义规则：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    veil:
      enabled: true
      gitleaks_toml: ""        # 为空时使用内嵌规则（或共享库旁的 rules/gitleaks.toml）
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

插件字段说明：

| 字段              | 类型     | 默认值  | 说明                                                        |
|-----------------|--------|------|-----------------------------------------------------------|
| `gitleaks_toml` | string | `""` | 替换内置规则的 gitleaks 规则文件，相对插件目录解析                            |
| `rules_toml`    | string | `""` | 追加到内置规则之后的 gitleaks 规则文件，见[规则](#规则)                         |
| `disabled_rules`| array  | `[]` | 要关闭的规则 ID                                                    |
| `categories`    | object | `{}` | 打开或关闭类别，见[规则](#规则)                                             |
| `terms`         | array  | `[]` | 始终掩码的用户词，类型为 `TERM`                                          |
| `allow`         | array  | `[]` | 永不掩码的值                                                       |
| `actions`       | object | `{}` | 按类型（`EMAIL`、`SECRET` 等）指定处理方式：`mask`（默认）、`block` 或 `warn` |
| `skip_models`   | array  | `[]` | 命中的模型不做掩码                                                 |
| `skip_formats`  | array  | `[]` | 命中的来源格式不做掩码                                               |

当 `gitleaks_toml` 为空、且共享库旁不存在 `rules/gitleaks.toml` 时，插件使用构建时内嵌到二进制中的规则。

### 拦截与告警

`actions` 可以改变某一类值的处理方式：

```yaml
plugins:
  configs:
    veil:
      actions:
        SECRET: block   # 只要含密钥就拦下请求
        EMAIL: warn     # 邮箱放行，但记录日志
```

- `mask`（默认）：把值换成占位符。
- `warn`：原样发出，同时记一条告警日志，只写类型和 JSON 路径，不写值。
- `block`：拦下整个请求。

被拦下的请求不会把原文带到上游。CLIProxyAPI 没有给插件提供让请求失败的接口，而且 Veil 运行时上游已经选好，
所以 Veil 会把请求体换成只保留模型和 stream 标志、清空所有对话字段的版本。任何厂商都会在推理前把它当作错误请求拒绝。
客户端看到的是这次拒绝，CLIProxyAPI 日志里会写明原因：`veil stopped a request, the upstream will reject it: ...`。

出错时 Veil 同样选择拒绝：如果无法掩码某个请求（例如请求体看起来是 JSON 却解析失败，或者掩码过程出错），
就拦下这个请求，而不是放行。插件返回错误会让 CLIProxyAPI 发出原始请求体，所以 Veil 从不返回错误。
完全不是 JSON 的请求体会原样放行。还原回复出错时，回复会带着占位符到达客户端。

### 配置错误

- 启动时（`plugin.register`）配置无效会导致注册失败。CLIProxyAPI 会在日志中给出原因，插件不会启用，
  可通过 `GET /v0/management/plugins` 确认 `effective_enabled: true`。
- 热更新时（`plugin.reconfigure`）配置无效会被拒绝，插件**继续使用上一份有效配置脱敏**，不会因为一处笔误静默停止过滤。
  宿主日志会输出类似 `veil rejected new config, still using the previous valid config: ...` 的错误，并指出出错字段。
  修正配置后再次保存即可生效。

### 日志

插件日志通过宿主的 `host.log` 回调输出，遵循 CLIProxyAPI 的日志级别、格式和输出位置，并带上请求 ID。
每次拦截只要有掩码就输出一行，包含各类型的数量和被掩码字段的 JSON 路径，例如
`veil masked 3 value(s) (EMAIL=2, SECRET=1) in 2 field(s): messages[0].content, system`。
不会记录原值、原值的任何片段或长度。

## 工作方式

Veil 在 before-auth 和 after-auth 两个请求拦截阶段都会掩码，两个阶段看到的都是客户端格式的请求体（executor 翻译之前）。
after-auth 这一遍用来拦住请求链后面其他插件加进来的文本，例如优先级更低的 before-auth 拦截器或优先级更高的 after-auth 拦截器。
掩码是幂等的，已经掩码过的请求体不会产生新的命中；before-auth 已经掩码过的请求体，after-auth 不会再扫一遍。

1. 检查 `skip_models` 和 `skip_formats`。
2. 将请求体解析为 JSON；不是 JSON 的请求原样放行。
3. 确定客户端的调用方范围（见下文）。
4. 掩码请求里的所有字符串（下面列出的除外），其余字节原样写回。

会被掩码的内容：

- 各客户端格式的全部对话文本：OpenAI Chat / Completions、OpenAI Responses、OpenAI 图片和视频的 prompt、
  embeddings 的 input、Claude、Gemini，以及 Gemini CLI 的 `request` 包装。
- 工具调用和工具结果：OpenAI 的 `arguments`（一个 JSON 字符串，逐个值掩码，结果仍是合法 JSON）、
  Claude 的 `tool_use.input` 和 `tool_result`、Gemini 的 `functionCall.args` 和 `functionResponse.response`。
  它们的键属于工具本身，所以其下的每个字符串都会掩码。
- 工具定义和请求参数里的 `description`，其下的其他内容不动。

不会改动的内容：

- 带签名的推理内容：Claude 的 `thinking` 和 `redacted_thinking` 块、OpenAI Responses 的 `reasoning` 条目，
  以及标记了 `thought: true` 的 Gemini 分段。它们必须按厂商签名时的原样发回。
- 标识符、名称和协议字段：`id` 以及以 `_id`、`Id`、`_ids` 结尾的键，`name`、`model`、`type`、`role`、
  `signature`、`encrypted_content`、`url`、`image_url`、`media_type` 等。
- 二进制数据：`data` 和 `file_data`（Claude 文档的纯文本来源除外），以及所有 `data:` URL。

除了规则检测到的位置，Veil 还会在以下情况掩码重复出现的值：

- 一个值在请求的任何位置被识别出来，整个请求里出现它的地方都会被掩码。例如靠 `password:` 标签识别出的密钥，
  在单独出现的地方也会被掩码。
- 不少于 8 字节、掩码过一次的值，会成为这个客户端的已知值，之后的请求里也会被掩码。
- 客户端已经发出过的文本保持当时发送的样子，即使 Veil 后来才学到其中某个值，这样上游缓存的提示词前缀依然能命中。

### 占位符与调用方范围

占位符的格式是 `{{KIND_xxxxxxxx}}`：类型（`EMAIL`、`SECRET`、`PASSWORD` 等，见[规则](#规则)）加上原值 HMAC 的 8 个字符。
HMAC 密钥在首次启动时生成，保存在插件目录的 `veil.key`（权限 0600）中，所以重启后占位符不变。请把 `veil.key` 当作敏感文件：
拿到它的人可以把猜测的值和占位符对照验证。删掉它，所有占位符都会改变。

每个客户端 API key 是一个独立的调用方范围：同一个值在另一个 key 下得到不同的占位符，占位符也不会为另一个客户端还原。
Veil 从 `Authorization: Bearer`、`x-api-key` 或 `x-goog-api-key` 读取 key，只保存它的哈希。没有这些请求头的请求共用默认范围，
其中包括用 `?key=` 查询参数传 key 的 Gemini 客户端，因为插件看不到查询参数。

占位符到原值的映射只保存在内存中，最多保留最近使用的 200,000 个值。

### 用户名和公网 IP 的替身

打开 `home`、`userhost` 或 `ip` 类别后，用户名会以 8 个小写字母的假名发往上游（`/Users/qmzvkrta/project`），
公网 IP 会以 `public-ip-` 加 8 个字母发往上游（`ssh root@public-ip-kvxqmrtz`），而不是 `{{KIND_…}}` 占位符。
模型会把 `/Users/{{USERNAME_…}}` 当成模板或临时目录，看到 `{{IP_…}}` 会去问真实地址而不是直接使用；
换成仍像主目录的路径、连不到任何主机的主机名后，模型会照常使用，工具调用里的值也会被还原回来。
替身和占位符一样稳定，不同客户端之间相互隔离，还原时不区分大小写、只按整个词匹配；如果一个值的候选替身都已被其他值占用，就改用占位符。
主机名和 bucket 仍使用占位符。

### 还原回复

回复到达客户端之前，只要模型写的是该客户端的占位符，Veil 都会换回原值：文本、工具调用（OpenAI 的 `arguments`
在其 JSON 内部还原，值按 JSON 要求转义）、Claude 的 `tool_use.input` 和 Gemini 的 `functionCall.args` 都包括在内。
因此客户端执行工具时拿到的是真实值；客户端把对话发回来时，这些值又会掩码成同样的占位符。

- 模型不一定原样照抄占位符。类型或哈希换了大小写、括号里多了空格、少了一边或两边括号，Veil 也会还原，
  前提是它对应 Vault 里该客户端确实存在的占位符。
- 带签名的推理内容（thinking 块、reasoning 条目、Gemini 的 thought 分段）不还原，这样才能按签名时的原样发回上游；
  客户端在这些地方可能会看到占位符。
- Vault 里已经没有的占位符会原样到达客户端，例如重启之前只保存在厂商侧对话里的占位符。

流式回复同样会还原。模型会把一个占位符分成几段输出，所以当某个事件的文本结尾可能是占位符的开头
（`{{`、`{{EMA`、`EMAIL_ab` 等）时，Veil 会先扣住这个事件，等同一个块的下一个事件到来、看清后续内容后，把两者一起发出并还原其中的值。
ping 事件可以越过被扣住的事件先发出；其他事件到来时，被扣住的事件原样放出；一个块的最后一个事件不会被扣住。
事件总是完整、按顺序发出，客户端看到的 SSE 分帧、事件名和序号都与上游发出的一致。
如果同一个客户端用完全相同的请求体同时开了两个流，Veil 无法区分它们的分块，只能逐块单独还原，
这时被切到不同分块里的占位符会原样到达客户端。

`skip_formats` 的常见取值是宿主的来源格式名，例如 `openai`、`openai-response`、`claude`、`gemini`、`gemini-cli`、`openai-image`、`openai-video`。

支持的请求体示例：

```json
{
  "model": "gpt-4",
  "messages": [
    { "role": "user", "content": "Email me at user@example.com" }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

## 规则

### Veil 会识别什么

检测按类别分组，可以用 `categories` 整组打开或关闭：

| 类别         | 类型                                     | 默认 | 识别内容                                                                    |
|------------|----------------------------------------|----|-------------------------------------------------------------------------|
| `secrets`  | `SECRET`、`PASSWORD`、`PRIVATE_KEY`      | 开  | 厂商密钥（gitleaks 规则和已知前缀）、写在名称后面的口令和密钥、URL 里的密码、Authorization 和 Cookie 请求头、私钥，以及紧挨着密钥名称的随机串 |
| `personal` | `EMAIL`、`PHONE`、`ID_CARD`、`BANK_CARD` | 开  | 真实域名的邮箱、不在编号语境里的大陆手机号、校验位正确的身份证号、通过 Luhn 校验的银行卡号 |
| `ssn`      | `SSN`                                  | 开  | 美国 SSA 实际签发号段内的社保号                                                |
| `passport` | `PASSPORT`                             | 开  | 写在 "passport" / 护照 后面的护照号                                          |
| `iban`     | `IBAN`                                 | 开  | 校验和正确的 IBAN                                                         |
| `birthday` | `BIRTHDAY`                             | 开  | 写在 "birthday"、"DOB"、生日等词后面、且早于一年前的日期                               |
| `mac`      | `MAC`                                  | 开  | MAC 地址（文档示例地址和广播地址除外）                                             |
| `serial`   | `SERIAL`                               | 开  | 写在 "S/N"、"serial"、序列号 后面的序列号                                      |
| `home`     | `USERNAME`                             | 关  | 主目录路径里的用户名：`/Users/<name>`、`/home/<name>`、`C:\Users\<name>`     |
| `userhost` | `USERNAME`、`HOSTNAME`                  | 关  | 命令提示符和 ssh/scp/rsync 命令里的 `user@host`，以及 `hostname:`、`User:` 行     |
| `ip`       | `IP`                                   | 关  | 公网 IPv4 和 IPv6；内网、回环、链路本地、CGNAT、文档地址和公共 DNS 永远不掩              |
| `bucket`   | `BUCKET`                               | 关  | `s3://`、`gs://` 等 URL 和域名里的云存储 bucket                                |

`home`、`userhost`、`ip`、`bucket` 默认关闭，因为主目录和主机名几乎出现在每个编程请求里，而且模型需要逐字照抄它们。

除了按值的样子识别，名字表明存放密钥的字段（`api_key`、`password`、`client_secret`、`Authorization`、`db_pass` 等），
只要值不少于 8 个字符，不论长什么样都整值掩码。为了减少误报，以下内容不会被掩码：UUID、长十六进制 id 和摘要（以及它们的任何片段）、
小数、JSON 里的裸数字、id 类字段的值、给密钥起名的代码（`token = get_token_v2`）、版本号、路径、文件行号，以及 `${API_KEY}` 这类占位写法。
附近没有密钥名称的随机串不算密钥。

### 自定义规则

```yaml
plugins:
  configs:
    veil:
      categories:
        ip: true          # 打开（或关闭）某个类别
      terms:              # 始终掩码，类型为 TERM
        - 烛龙
        - {term: Phoenix, any_case: true, whole_word: true}
      allow:              # 永不掩码，按整个值比较，不区分大小写
        - support@acme-corp.cn
      rules_toml: rules/extra.toml   # 追加到内置规则之后的 gitleaks 规则
      disabled_rules:     # 要关闭的规则 ID
        - phone-cn
```

`rules_toml` 里的规则可以自定类型，要求全大写、不超过 24 个字符：

```toml
[[rules]]
id = "internal-ticket"
regex = '''TKT-[0-9]{6}'''
keywords = ["tkt-"]
kind = "TICKET"
```

`disabled_rules` 可以填 gitleaks 规则 ID，也可以填 Veil 自己的规则 ID：`email`、`phone-cn`、`id-card-cn`、`bank-card`、
`url-password`、`named-secret`、`env-secret`、`auth-header`、`key-field`、`cjk-password`、`cjk-secret`、`copula-secret`、
`context-secret`、`high-entropy`、各个 `vendor-*` 密钥规则，以及各类别自己的规则。写了不存在的类别或规则 ID，配置会加载失败。

### 内置 gitleaks 规则

内置规则在构建时内嵌到共享库中，来源：

```text
rules/gitleaks.toml
```

运行时按以下顺序解析规则：

1. 配置项 `gitleaks_toml`（若设置；它会替换内置规则，想追加规则请用 `rules_toml`）
2. 共享库旁的 `rules/gitleaks.toml` 附带文件
3. 构建时内嵌的规则（默认）

更新内嵌规则并重新构建：

```bash
make update-rules
make build
```

相对路径会基于插件目录解析。

## 从 privacyfilter 迁移

1. 把 `privacyfilter` 共享库换成 `veil.so` / `veil.dylib` / `veil.dll`，放进单独的 `veil/` 插件目录。
2. 配置键从 `plugins.configs.privacyfilter` 改为 `plugins.configs.veil`。`gitleaks_toml`、`skip_models`、`skip_formats` 含义不变。
3. 删除 `replacement` 和 `replacement_labels`。Veil 会忽略这两项，并在启动时输出
   `veil ignores removed config field(s): ...`，直到删掉为止。
4. 命中结果会有变化：值现在换成占位符，并在回复里还原；IP 地址默认不再掩码（如需掩码公网地址，打开 `ip` 类别）；
   `example.com` 这类文档域名的邮箱、校验位不对的身份证号、看起来是订单号的手机号不再掩码；工具调用参数和工具结果也会掩码。

## 开发

常用命令：

```bash
go test ./...
make build
make clean
```

主要文件：

```text
main.go                 插件元数据和构建入口
abi.go                  CLIProxyAPI 插件 ABI 适配
interceptor.go          请求拦截和脱敏逻辑
config.go               YAML 配置解析
internal/detect/        检测引擎：PII 规则、gitleaks 规则、关键词预筛、命中缓存
internal/jsontree/      保留原始字节的 JSON 解析器，只重写改动过的字符串
rules/gitleaks.toml     内置检测规则
```

运行长会话基准测试（80 轮 agent 会话，每个请求跑两个拦截阶段）：

```bash
go test -run '^$' -bench LongSession .
```

### 性能

agent 每一轮都会重发完整历史，所以 Veil 针对重复文本做了优化：

- 对每段文本用 Aho-Corasick 扫一遍，找出出现了哪些 gitleaks 规则的关键词，只运行这些规则。
- 256 字节及以上的文本按哈希缓存检测结果（只存偏移，不存原文），已经扫过的历史每个字段只需算一次哈希。
- 请求体解析成字节区间，只重新编码被脱敏的字符串，其余字节原样复制，键顺序、数字写法和 base64 内容都不变。
- before-auth 已经确认干净的请求体，after-auth 直接跳过。

## 来源

- 检测引擎源自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)（MIT），见
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
