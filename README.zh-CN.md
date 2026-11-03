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
- 在管理面板的“脱敏记录”菜单里查看每个请求换掉了什么，从不显示原值，兼容 CPA-Manager-Plus
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

### 从插件商店安装

Veil 不在官方插件商店里，但 CLIProxyAPI v8 可以通过 `plugins.store-sources` 添加额外的插件源（v7 还不支持这个配置项）。
在 `config.yaml` 中加上 Veil 的源：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  store-sources:
    - "https://raw.githubusercontent.com/GarlandQian/cpa-plugin-veil/main/registry.json"
```

CLIProxyAPI 会自动重新加载配置，之后插件商店里就会出现 Veil。可以在管理面板的插件商店里安装，也可以调用管理接口：

```bash
curl -X POST "http://127.0.0.1:8317/v0/management/plugin-store/veil/install" \
  -H "Authorization: Bearer <管理密钥>"
```

商店会下载本仓库最新 Release 中对应平台的 zip，用 `checksums.txt` 校验后装到 `plugins/<系统>/<架构>/veil-v<版本>.dylib`
（Linux 为 `.so`，Windows 为 `.dll`），并把 `plugins.configs.veil.enabled` 设为 `true`，不需要重启。

### 手动安装

1. 从 [Releases](https://github.com/GarlandQian/cpa-plugin-veil/releases) 下载对应平台的 `veil_<版本>_<系统>_<架构>.zip`，
   例如 Apple 芯片的 Mac 用 `veil_0.5.0_darwin_arm64.zip`。可以用同一页的 `checksums.txt` 校验：

   ```bash
   shasum -a 256 -c checksums.txt --ignore-missing   # Linux 上用 sha256sum
   ```

2. 解压出 `veil.so` / `veil.dylib` / `veil.dll`，放进插件目录（`plugins.dir`，默认 `plugins`）下的 `<系统>/<架构>/`，
   和插件商店的安装位置相同：

   ```text
   plugins/
   └── darwin/
       └── arm64/
           └── veil.dylib   # Linux 为 veil.so，Windows 为 veil.dll
   ```

   也可以直接放在 `plugins/` 下。CLIProxyAPI 只在这两处查找插件，不会进入其他子目录。插件 ID 取自文件名，
   所以文件名要保持 `veil`，才能和配置键 `plugins.configs.veil` 对上。

3. 在 `config.yaml` 中启用插件（见[配置](#配置)），然后重启 CLIProxyAPI。启动日志里出现 `veil loaded ... rules`
   就表示加载成功，也可以通过 `GET /v0/management/plugins` 确认 `effective_enabled: true`。

Gitleaks 规则已内嵌到二进制中，无需额外规则文件。在 CLIProxyAPI v8 下，请按下文配置 `key`，让重启后的占位符保持稳定。
v8 从共享库的临时副本加载插件，不能用实际加载位置保存 `veil.key` 或查找安装目录旁的规则；需要这些文件时，设置 `base_dir`。
在 v7 下，Veil 默认仍在库文件旁生成并复用 `veil.key`。

`key` 和 `base_dir` 从 v0.4.1 起支持。v0.4.0 没有这两项，在 CPA v8 下每次重启都会改变占位符，请先升级。

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
      gitleaks_toml: ""        # 为空时使用内嵌规则（或基准目录下的 rules/gitleaks.toml）
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

插件字段说明：

| 字段              | 类型     | 默认值  | 说明                                                        |
|-----------------|--------|------|-----------------------------------------------------------|
| `key`          | string | `""` | 占位符密钥：32 个随机字节的 64 位十六进制编码，见下文                     |
| `base_dir`     | string | `""` | 相对规则路径、旁置规则和未设置 `key` 时的 `veil.key` 所在目录；相对 CPA 工作目录解析 |
| `gitleaks_toml` | string | `""` | 替换内置规则的 gitleaks 规则文件，相对 `base_dir` 或已知的原始插件目录解析     |
| `rules_toml`    | string | `""` | 追加到内置规则之后的 gitleaks 规则文件，见[规则](#规则)                         |
| `disabled_rules`| array  | `[]` | 要关闭的规则 ID                                                    |
| `categories`    | object | `{}` | 打开或关闭类别，见[规则](#规则)                                             |
| `terms`         | array  | `[]` | 始终掩码的用户词，类型为 `TERM`                                          |
| `allow`         | array  | `[]` | 永不掩码的值                                                       |
| `actions`       | object | `{}` | 按类型（`EMAIL`、`SECRET` 等）指定处理方式：`mask`（默认）、`block` 或 `warn` |
| `skip_models`   | array  | `[]` | 命中的模型不做掩码                                                 |
| `skip_formats`  | array  | `[]` | 命中的来源格式不做掩码                                               |
| `records`       | bool   | `true` | 为每个有值被掩码、告警或拦截的请求保留一条脱敏记录，从不包含原值；只在 `base_dir` 或 CPA v7 的插件目录下落盘 |

当 `gitleaks_toml` 为空、且解析出的基准目录下不存在 `rules/gitleaks.toml` 时，插件使用构建时内嵌到二进制中的规则。

### 让占位符在重启后保持稳定

用 `openssl rand -hex 32` 生成一次密钥，把结果保存在已经持久化的 CPA 配置里：

```yaml
plugins:
  enabled: true
  configs:
    veil:
      enabled: true
      key: "<在这里粘贴生成的 64 个十六进制字符>"
```

这把密钥应保密并保持不变。它独立于客户端 API key，不会发送给上游。使用内嵌规则时，Docker 只需保留已有的 CPA 配置挂载，
不需要额外挂载目录。

`key` 优先于 `veil.key`，设置后不读写密钥文件。未设置时，Veil 在 `base_dir` 或 v7 的原始库文件目录里读取或创建
`veil.key`（权限 0600）。如果无法确定持久目录（例如 v8 未设置 `base_dir`），或密钥文件不可用，Veil 会用内存中的临时密钥
继续脱敏，并输出警告或错误：这种情况下重启会改变占位符。Veil 不会向识别出的 CPA 影子目录写入密钥。

从 v7 上的 v0.4.0 迁移时，把已有 `veil.key` 的内容复制到 `key`，或让 `base_dir` 指向这个文件所在目录，
都能继续使用原密钥、保持占位符不变。迁移时不要重新生成密钥。v8 的旧密钥如果已随影子目录删除，则无法恢复。

热更新保留 Vault 和正在进行的流。同一把密钥从 `veil.key` 搬入 `key` 可以直接热更新；更换密钥、删除显式的 `key`，
或更换文件密钥所在目录，需要重启 CPA。这类热更新会被拒绝并记入日志，插件继续使用上一份有效配置。

### CPA v8 下的外部规则文件

通过 `base_dir` 指定规则原来所在的目录，例如：

```yaml
plugins:
  configs:
    veil:
      base_dir: plugins/darwin/arm64
      rules_toml: rules/extra.toml
```

`gitleaks_toml` 为空时，也会查找该目录下的 `rules/gitleaks.toml`。`base_dir` 必须存在，相对路径基于 CPA 进程的工作目录，
不是 `config.yaml` 所在目录。绝对路径的 `gitleaks_toml` 和 `rules_toml` 不需要 `base_dir`。
如果 v8 没有提供原始插件目录，未设置 `base_dir` 的相对规则路径会被拒绝；Veil 不猜测目录，也不会静默读取工作目录里的同名规则。
没有配置外部规则时，使用内嵌规则。

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
HMAC 密钥和调用方范围相同时，重启后的占位符保持不变；密钥保存方式见[让占位符在重启后保持稳定](#让占位符在重启后保持稳定)。
请把 `key` 和 `veil.key` 都当作敏感信息：拿到密钥的人可以把猜测的值和占位符对照验证。更换或丢失密钥，所有占位符都会改变。

每个客户端 API key 是一个独立的调用方范围：同一个值在另一个 key 下得到不同的占位符，占位符也不会为另一个客户端还原。
Veil 从 `Authorization: Bearer`、`x-api-key` 或 `x-goog-api-key` 读取 key，只保存它的哈希。没有这些请求头的请求共用默认范围，
其中包括用 `?key=` 查询参数传 key 的 Gemini 客户端，因为插件看不到查询参数。

占位符到原值的映射只保存在内存中，最多保留最近使用的 200,000 个值。
即使密钥不变，重启也会清空这些映射。客户端重发原文后，会用相同占位符重建映射；只保存在服务商侧的历史
（包括 compaction 和 `previous_response_id`）本身无法重建映射，旧占位符可能无法还原。
保留密钥不会持久化 Vault，也不保证 prompt cache 一定命中；它消除的是仅由重启更换密钥造成的占位符变化。

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

## 脱敏记录

Veil 会为每个有值被掩码、告警或拦截的请求，以及每个被拦请求，保留一条脱敏记录。支持插件菜单的管理面板（例如 CPA-Manager-Plus）里会出现“脱敏记录”菜单，也可以直接打开下文的页面地址。页面里有：

- **总览**：请求数、掩码次数、不同的值、告警放行、被拦请求、回复中已还原的次数和还原不了的占位符；每天的请求数；按类型、调用方、模型、规则的统计；掩码最多的值。
- **记录**：按时间倒序列出，可以按类型、调用方、模型、动作筛选，或只看被拦请求。
- **详情**：每个值的占位符或替身、类型、找到它的规则、提示（第一个字符，或密钥的前缀）、长度、次数、动作、字段路径、是否第一次出现；上游看到的上下文；回复里还原了几处、哪些占位符还原不了。
- **清空记录**：只删除记录，不影响正在进行的对话。
- **预览**：输入一段文字，看按当前配置会怎么掩码；结果不保存，也不影响任何对话。

记录和页面**从不包含原值**，也没有查看原值的入口（见 ADR-0005）：拿到管理密钥的人不应因此看到所有调用方的密钥和个人信息。

调用方按客户端 API key 区分：页面优先显示 CPA-Manager-Plus 里给这个 key 起的别名，其次显示 key 的末 4 位，没带 key 的请求显示“未识别调用方”。Veil 自己不保存任何 key。

### 存储

- 内存里保留最近 1000 条记录；其中最近 400 条带上下文（每个占位符前后各 40 个字符，即上游看到的已掩码文本），上下文只在内存里。
- 有持久目录时，记录还会按天写入 `veil-records/` 下的文件（权限 0600），保留 30 天、总共最多 100 MB，文件里不含上下文。持久目录是 `base_dir`；CPA v7 下没配 `base_dir` 时是插件库文件所在的目录。CPA v8 没配 `base_dir` 时记录只在内存里，重启后清空。
- 记录在后台写入，绝不让请求等待；写入队列满时丢弃新记录，页面上会显示丢弃了多少条。
- “新出现”按内存里的映射判断，CPA 重启后重新计算。

不需要记录时，设置 `records: false`：

```yaml
plugins:
  configs:
    veil:
      records: false
```

### 页面和接口

页面地址是 `/v0/resource/plugins/veil/index.html`。CLIProxyAPI 不对插件页面做认证，所以页面本身不带任何数据，记录都从需要管理密钥的接口读取：

| 接口 | 作用 |
|---|---|
| `GET /v0/management/plugins/veil/summary?days=7` | 最近若干天（1 到 30）的汇总 |
| `GET /v0/management/plugins/veil/records` | 记录列表，参数 `before`、`limit`、`kind`、`caller`、`model`、`action`、`stopped=1` |
| `GET /v0/management/plugins/veil/record?key=` | 一条记录，带上下文和还原情况 |
| `POST /v0/management/plugins/veil/clear` | 清空记录 |
| `POST /v0/management/plugins/veil/preview` | 预览 `{"text": "..."}`，最多 64 KB |

在 CPA-Manager-Plus 里打开时，页面会读取面板保存的管理密钥（需要勾选“记住密码”），并跟随面板的主题和语言；读不到密钥时会请你输入一次，只保存在当前标签页里。

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
2. `base_dir` 下的 `rules/gitleaks.toml`，或目录已知时原始共享库旁的同名文件
3. 构建时内嵌的规则（默认）

更新内嵌规则并重新构建：

```bash
make update-rules
make build
```

相对路径会基于 `base_dir` 或已知的原始插件目录解析。在 CPA v8 下，请设置 `base_dir` 或使用绝对路径，
见 [CPA v8 下的外部规则文件](#cpa-v8-下的外部规则文件)。

## 从 privacyfilter 迁移

1. 删掉旧插件的库文件 `privacyfilter.so` / `privacyfilter.dylib` / `privacyfilter.dll`。从插件商店安装的在
   `plugins/<系统>/<架构>/` 下，手动安装的一般在 `plugins/` 下。旧插件一定要删：两个插件同时加载时，
   旧插件可能先把值换成 `[EMAIL]` 这类标签，Veil 就无法还原了。
2. 按[在 CLIProxyAPI 中使用](#在-cliproxyapi-中使用)安装 Veil。
3. 配置键从 `plugins.configs.privacyfilter` 改为 `plugins.configs.veil`。`gitleaks_toml`、`skip_models`、`skip_formats` 含义不变。
4. 删除 `replacement` 和 `replacement_labels`。Veil 会忽略这两项，并在启动时输出
   `veil ignores removed config field(s): ...`，直到删掉为止。
5. 重启 CLIProxyAPI。

命中结果会有变化：值现在换成占位符，并在回复里还原；IP 地址默认不再掩码（如需掩码公网地址，打开 `ip` 类别）；
`example.com` 这类文档域名的邮箱、校验位不对的身份证号、看起来是订单号的手机号不再掩码；工具调用参数和工具结果也会掩码。

### 原来的对话

换成 Veil 后，原来的对话可以接着用。旧插件只改发往上游的请求，不改回复，所以客户端保存的历史一直是原文，
Veil 会在发出前把其中的原值换成占位符。有两点要知道：

- 切换后的第一次请求，上游看到的历史从 `[EMAIL]` 变成了 `{{EMAIL_…}}`，这段对话的 prompt cache 会失效一次，
  整段历史要重新写入缓存。之后同一个值的占位符保持不变，缓存照常命中。
- 旧插件没有记下被替换的原值，所以模型以前回复里的 `[EMAIL]` 这类标签无法还原，会原样留在历史里。之后的新回复会正常还原。

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
