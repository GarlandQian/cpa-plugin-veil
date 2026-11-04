# magpie 隐私脱敏界面：源码证据

研究日期：2026-11-04。来源为 [yetone/magpie](https://github.com/yetone/magpie) 的官方源码，固定在 commit [`0ee424e3ee61ae545d93160084a8d930b88a8193`](https://github.com/yetone/magpie/commit/0ee424e3ee61ae545d93160084a8d930b88a8193)（提交时间 `2026-11-04T15:12:08+08:00`）。这是该时刻的 `main`，不等同于某个发布版或用户已安装版本。本次只阅读公开源码，没有打开用户的 magpie 界面，没有读取配置、聊天、密钥或实际映射。

Veil 对照以本地 commit `79c31b835102aaf9078b1efbf0ee401fe2cc66a7` 为准。本文后半部分区分已有代码问题与建议增加的能力。

后续决定（2026-11-04）：用户已明确允许管理页按需查看原值，本分支据此修订 ADR-0005 并实现从当前 Vault 读取。下文关于“不能查看原值”的对照描述的是研究时的旧决策；原值仍不写入记录文件。

**直接结论：magpie 把脱敏作为可以解释的请求过程展示。** 用户先看到总体保护量与请求列表，再进入单条请求，看发生了什么、哪些内容被换成占位符、每个值由谁发现、回复里还原了多少次。设置与记录是两个入口。最值得 Veil 参考的是这套信息层级、上下文与值卡片的联动，以及数据缺失时的解释。原值揭示机制与 Veil 的 [ADR-0005](../adr/0005-masking-records-never-hold-values.md) 冲突，不能直接照搬。[页面入口与构成](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/client.js#L1-L45)；[详情构成](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L694-L769)。

以下除“对 Veil 的推断”外，均为固定 commit 的直接源码观察；布局来自 DOM/CSS，未作浏览器渲染验证。

## 1. 两个入口及职责

| 入口 | 源码确认的内容 | 证据 |
| --- | --- | --- |
| Settings → Privacy | 依次分为“如何发现”“脱敏什么”“发现之后怎么做”“试一下”“分享”，另有登录与会话相关隐私设置 | [设置分区](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/index.html#L439-L454) |
| Privacy 中“脱敏什么” | 密钥/令牌/密码开关、保留密钥形态、个人数据开关与细分类型、用户词、大小写/整词匹配、用户规则；有打开脱敏记录的入口 | [设置渲染](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L21761-L21830) |
| Insights → Masking | 独立页面：统计卡片、可折叠演示、请求/值列表、首次命中提醒设置、单条请求详情 | [注册及页面 DOM](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/client.js#L16-L45) |
| Routing 请求详情 | 请求标题旁显示盾牌与数量按钮；点击跳到独立 Masking 请求页。检查到的是这种跳转，并非在 Routing 中加入一个专门的脱敏 tab | [Routing 入口](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/routing/client.js#L2804-L2832)；[按钮与跳转](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L22056-L22077) |

最新源码中的用户词和放行值是逐行可编辑列表；Enter 或离焦保存，清空或 × 移除，下方可一次添加多项。用户词默认以圆点遮住，Show/Hide 状态仅保持至窗口重载。放行值位于动作设置下面。[词列表编辑](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/settings.js#L42-L106)；[显示控制与挂载](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/settings.js#L133-L173)。

动作按 Kind 设置为脱敏、警告或拦截；默认脱敏。个人数据类型可展开，已有的非默认动作即使对应检测关闭也留在页面中，方便撤销。设置里还可以选择本地检测模型与置信度阈值。[动作设置](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L22132-L22203)；[模型与阈值](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L21833-L21928)。

## 2. 总览、列表与筛选

- **总体统计**：默认 7 天，可切 30 天；主数字是替换的出现次数 `n`，另列不同值数量 `distinct`、请求数 `requests`，有拦截时附上 `blocked`；下方每日条形分布，旁边是 agent → 本机 → provider 的流向图。流向图最多展开前三个 agent/provider，余项合并，点击命名节点可筛选列表。[统计与周期](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L43-L67)；[统计卡片](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L119-L177)；[流向与筛选](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L300-L328)。
- **按请求**：按日期分组，每行显示时间、agent → provider、模型、最多三种 Kind 与次数、总命中次数；被拦请求有专门标记，非聊天请求会显示搜索、图片等用途。点击整行打开详情。[分组和行内容](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L551-L607)。
- **按值**：按脱敏次数排列，显示序号、提示形态、Kind、发现来源、比例条、次数；悬停可揭示原值。数据来自 summary 最多前 60 个值。**点击行只按该 Kind 筛选请求，不按该 Placeholder 精确筛选。**[按值列表](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L610-L634)；[summary 上限与排序](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/summary.go#L109-L138)；[排序与截断](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/summary.go#L199-L213)。
- **筛选与分页**：全部、秘密、规则、本地模型、被拦请求的分类按钮，以及 agent/provider 选择器；还支持 Kind 筛选。前端每次取 40 条，`before` 游标加载更多，后端允许最多 200 条。检查的页面 DOM、查询构造与后端过滤器没有自由文本搜索。**7/30 天只传给 summary；请求列表查询没有日期参数。**[列表查询](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L392-L410)；[工具条及筛选](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L455-L515)；[后端参数](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L113-L127)；[过滤器](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L420-L441)。

空状态按原因区分：未开启且没有记录时，解释功能并给开启入口；只开了秘密检测但没有命中时，解释邮件/电话需要开启个人数据；列表区分别显示加载中、没有任何命中、筛选无结果和错误，而不是统一的零。[未开启及未命中状态](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L180-L212)；[列表空状态](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L551-L554)。

## 3. 单条请求：过程、上下文、每个值

打开单条请求时隐藏总览和列表，保留返回、时间，以及已加载列表内的上一条/下一条。先显示路由与模型，再展示五步过程：收到请求、发现不同值、替换出现位置、已发送或被拦、回复中还原。发现步骤可以显示检测来源和耗时；还原步骤区分有还原、没有占位符、未发送、重启后未知。[打开及数据加载](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L637-L663)；[详情头与过程](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L694-L769)。

这套步骤显示也有局限：`maskSteps` 在还原数为零、但正文/原值/片段任一仍在内存时，就显示“回复没有占位符”；没有这些内存数据时显示“重启后未知”。这是前端根据数据可用性推断的文案，不能证明回复已经完成，也无法单独区分重启与内存淘汰。Veil 可以参考步骤的组织方式，但应由后端明确的状态或“暂无还原统计”支撑文案。[状态判断](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L744-L760)。

桌面布局为左侧请求内容、右侧最大 280px 的“如何脱敏”说明区；容器宽度不超过 760px 时上下排列。内容区提供原文、供应商收到的内容、左右对照三种视图，**默认左右对照**。JSON 被拆成字符串叶子，保留角色和字段路径；变化部分默认展开，未变化部分折叠。长文本默认只显示命中前后约 120 个字符，可展开全文。[默认视图](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L637-L660)；[JSON 上下文](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L676-L690)；[视图与折叠](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L825-L935)；[布局与窄屏](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/redact.css#L181-L237)。

每个值卡片显示 Kind、动作、出现次数、提示形态 → Placeholder/Stand-in、发现来源、首个字段路径及其他路径数量、回复还原次数。点选卡片会高亮内容区相同值的位置，其他命中淡化；点选已选值可取消。颜色用于统一同一 Kind 的点、标记和卡片。[值卡片与联动](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L938-L985)；[Kind 颜色](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L21968-L21986)；[高亮样式](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/redact.css#L199-L204)。

被拦请求另外解释原因，提供将相关 Kind 今后改回脱敏的按钮，以及跳转设置的入口。这一操作只更新动作设置，没有重发当前请求的实现。[被拦请求操作](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L772-L801)。

## 4. 值如何隐藏、何时揭示

| 位置 | 默认与交互 | 证据 |
| --- | --- | --- |
| 列表提示形态 | 首字符或密钥前缀，加 1–8 个圆点；圆点数被截断，不精确表达长值长度 | [提示形态](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L21977-L21981) |
| Placeholder/Stand-in 标记、按值列表 | 鼠标悬停或键盘聚焦时请求原值；tooltip 同时显示 Kind、发现来源；移开或失焦移除 tooltip | [原值 API 与 tooltip](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L21989-L22054) |
| 详情原文/对照左列 | 打开详情会批量请求该记录的原值；原文列把它们直接替换回内容；没取到的值退回提示形态。因此实际实现不局限于悬停后显示 | [批量读取](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L645-L660)；[原文渲染](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L803-L823) |
| 详情右侧值卡片 | 默认显示提示形态；选中且原值仍可用时显示原值 | [卡片选择](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L953-L978) |
| 已失去内存内容 | tooltip 说明原值不在内存、未写盘；完整请求失效时退回片段；片段也失效时解释仅剩 Kind、长度与首字符 | [tooltip 失效状态](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L22021-L22026)；[详情降级](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L845-L875) |

服务端原值接口包括单个 `GET /api/masking/value` 与批量 `POST /api/masking/values`，后者每次最多 2000 个占位符；原值和完整已发送内容接口设置 `Cache-Control: no-store`。记录返回值还附加 `known` 标记，但不把原值嵌入记录中。[known 字段](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L18-L55)；[原值与已发送内容接口](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L139-L180)。

原文列是把已发送内容中的占位符用映射替换回来，并非独立保存的一份原始请求。应用的 Hide accounts 显示处理还会遮住其中的邮箱等部分个人数据；源码测试同时断言左列确实包含恢复出的值、右列显示实际占位符，以及点选卡片后两列联动。因此“只有悬停才显示原值”不符合详情页实现，视觉遮盖也不意味着原值没有送到前端。[重建原文](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L803-L823)；[界面测试断言，仅阅读未执行](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/tests/masking-records.test.cjs#L297-L328)。

**与 Veil ADR 的冲突**：magpie 的前端可以调用在运行中揭示原值的服务端接口，并在默认对照视图中显示原值；Veil 的 ADR-0005 明确禁止脱敏记录保存值或让页面揭示值。即便都不把原值写盘，这一权限差异仍然存在。采用上述布局时，建议先做“安全上下文 + 命中值侧栏”，不引入原值读取 API；这属于对 Veil 的设计推断，不是 magpie 的现有行为。尤其不能直接保存真实发出的正文作为安全预览：`warn` 会原样发送命中值，而 Veil 的记录片段会额外隐藏这些值。[原值接口](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L139-L180)；[Veil ADR-0005](../adr/0005-masking-records-never-hold-values.md)；[Veil 的安全片段](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/mask/values.go#L120-L135)。

## 5. 数据字段、展示时机和保留边界

| 层 | 主要字段或约束 | 用途 / 证据 |
| --- | --- | --- |
| Record | `key`（接口输出字符串）、`t`、`route`、`what`、`agent`、`session`、`provider`、`model`、`n`、`values`、`blocked`、`took` | 请求身份、路由、数量和耗时。[记录结构](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L57-L96)；[key 避免 JS 精度损失](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L21-L34) |
| Value | `p`、`k`、`b`、`h`、`l`、`n`、`a` | 占位符/替身、Kind、发现来源、首字符/前缀、字符长度、出现次数、动作；一条记录按同一占位符合并。[值结构](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L57-L68)；[合并](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L267-L290) |
| Summary | `days`、`requests`、`n`、`distinct`、`warned`、`blocked`、`hours`、`kinds`、`by`、`agents`、`providers`、`values` | 统计和排行榜；warning 次数不计入已脱敏值排行榜。[统计结构](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/summary.go#L121-L138)；[warn 计数](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/summary.go#L36-L63) |
| 持久化记录 | 按天 JSONL；策略为 30 天及总量 100 MiB，按旧日文件清理 | 仅保留值的占位符与提示等元数据；写盘前去掉 `snips`、`back`，`Sent` 不参与 JSON。清理在写记录时按小时节流触发，非精确到秒的 TTL。[上限](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L1-L50)；[写盘](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L203-L242)；[清理](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L311-L333) |
| 片段与还原次数 | 最新 400 条记录保留 `snips`、`back`，仅内存 | 回复完成后写入按占位符计数的 `back`；重启或淘汰后丢失。[记录字段](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L85-L95)；[内存淘汰](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L192-L198)；[还原计数](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L378-L395)；[完成回调](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gateway/redact.go#L77-L89) |
| 完整已发送内容 | 最新 100 个完整请求；单个 ≤4 MiB；zstd 压缩后合计 ≤32 MiB | 仅内存，通过独立 `masking/sent` 获取，不在记录列表中；超限时可能只剩局部片段。[内容上限](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L34-L55)；[压缩与淘汰](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L170-L191)；[读取](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L398-L417) |

可见页面每 15 秒刷新 summary 和新记录；页面隐藏或切走时停止。summary 非强制读取有 10 秒缓存。刷新记录保留当前已加载列表和展开详情，不重新铺满整页。[缓存](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L53-L65)；[轮询](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L112-L117)；[增量列表刷新](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L441-L452)。

完整内容因条数或总预算淘汰后，片段可能仍在；单次请求本来就超过 4 MiB 则不同：`sentOf` 不捕获正文，依赖该正文的 `snipsOf` 也不会生成片段。两种缺失不能一概解释为“已经重启”。[捕获上限](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gateway/masked.go#L53-L61)；[片段来源](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gateway/masked.go#L82-L89)；[空正文不生成片段](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gateway/masked.go#L135-L138)。

要区别“已经在处理”与“进入列表/统计”：`Hold` 先把记录放入内存，实际 provider/model 确定后的 `done` 才写入文件；正常列表与 summary 主要读取文件。存在 provider 回退的请求在完成后才以最终 provider/model 纳入持久化记录。Routing 上的徽标可以早于这个时刻出现。[Hold 与 settle](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L155-L216)；[正常列表读取](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L444-L474)；[路由请求的完成回调](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gateway/masked.go#L74-L112)。

“清空记录”有二次确认，删除磁盘记录及内存片段/请求正文；脱敏继续工作，仍保留映射以便正在返回的回复能还原。[清空交互](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L517-L548)；[清空语义](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/maskrec/maskrec.go#L245-L264)。

## 6. 预览、纠正与提醒

- **试一下**：三行输入框，输入后 250 ms 防抖请求本机 `masking/preview`；显示供应商将收到的文本，逐值列 Kind、提示、发现来源、动作；有拦截时解释不会发送，无命中时明确说明。关闭脱敏时仍可演示启用秘密与个人数据检测后的结果，并标注这个区别。[预览界面](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/app.js#L22207-L22287)；[关闭时的预览语义](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/masking/masking.go#L370-L382)。
- **预览保留边界**：输入最多 64 KiB，返回 `text`、`hits`、`off`；hit 字段是 `kind/by/action/placeholder/head/len`。预览不把值加入还原映射，也不记成后续要重新脱敏的已知值。[接口及大小限制](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L15-L19)；[预览字段](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/masking.go#L80-L104)；[不记忆的实现](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/redact/redact.go#L976-L1004)。
- **纠正入口**：在检查的 Masking 页和值卡片中，没有找到“一键误报反馈”“这个值不敏感”或上报按钮；已有手段是设置中的放行值、用户规则、Kind 动作与模型阈值，及被拦详情的“以后改为脱敏”。这是一项限定于已检查组件的观察，不代表整个应用不存在通用反馈入口。[值卡片完整渲染](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L938-L985)；[被拦操作](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L772-L801)；[放行值](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/settings.js#L155-L173)。
- **首次命中提醒**：Masking 页底部可开关，默认关；只通知首次出现的值，通知仅含 Kind、数量和 agent。后端将 3 秒内的事件合并，通知最短间隔一分钟；gateway 模式不显示该桌面通知设置。[通知设置](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/assets/plugins/redact/page.js#L103-L110)；[通知内容与合并](https://github.com/yetone/magpie/blob/0ee424e3ee61ae545d93160084a8d930b88a8193/internal/gui/mask_alert.go#L14-L34)。

## 对 Veil 的推断

源码对照说明，Veil 目前的问题涉及内容组织、值的辨识度和统计语义；只改颜色或间距不足以解决。

| Veil 当前实现 | 用户会遇到的问题 | 改进建议与证据 |
| --- | --- | --- |
| `context()` 将同一 Kind 的所有占位符显示成相同的“邮箱”“密钥”；实际占位符只有悬停 title 或卡片的“技术细节”里可见 | 无法直接区分两个不同邮箱，或判断几个位置是否为同一个值 | 主视图保留实际 Placeholder/Stand-in，并与侧栏共用选中状态；Kind 作为辅助标签。[上下文渲染](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L690-L705)；[值卡片](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L934-L953) |
| 详情按值堆叠卡片，每张重复原因、位置、上下文、误报说明、技术细节 | 用户需要来回寻找同一个上下文，难以把请求读成完整的处理过程 | 改为详情主区域展示片段、侧栏展示不同值；将规则说明和纠正操作留到选中值后展开。[详情组装](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L934-L980) |
| `!r.restored` 直接显示“等待回复” | 请求即使已经结束，只要统计没有关联或没有入队，仍会显示等待 | 暂用“暂无还原统计”；只有收到明确状态才显示“等待/完成”。旧宿主关联歧义、关联容量耗尽和记录队列满都能导致缺少统计。[显示判断](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L859-L866)；[跳过歧义关联](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/record_links.go#L54-L119)；[队列丢弃](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/records/records.go#L198-L223) |
| 详情把所有 `v.n` 累加为已替换次数，包括 `warn`；片段中 `warn` 值也隐藏，却标注“上游看到的就是这样” | 页面可能声称原样发出的值已经脱敏，或把安全预览当作真实发送内容 | 分开统计已替换、原样发出、被拦；上下文标明是安全预览，并说明警告值实际原样发送。[计数](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L961-L979)；[文案](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L279-L285)；[warn 片段也隐藏值](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/mask/values.go#L120-L135) |
| 无法还原的说明把“重启且没有固定 key”列为常见原因 | 容易让人以为固定 key 就能保存还原映射 | 改为解释 Vault 仅在内存：固定 key 保持占位符稳定，不能让服务商保存的旧占位符在重启后自动还原。[当前说明](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/web/records.html#L298)；[ADR-0001](../adr/0001-scoped-deterministic-placeholders.md) |

建议分两步实施，以下尚未修改产品：

1. **先用现有数据改善判断与阅读。** 修正 `warn`、缺少还原统计及固定 key 的文案；请求列表作为主要入口，统计压缩为概要；详情采用“处理结果 → 安全上下文 + 命中值侧栏”，保留实际占位符、前后请求导航和选中联动。现有 snippets 可以去除完全重复片段，但不应拼装成声称完整的请求，联动也只能覆盖当前保留的片段。Kind、提示、路径、次数、Action 已足以支撑这一步。[现有记录数据](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/mask/values.go#L88-L135)。
2. **再补按字段定位所需的数据。** 目前每个值只取第一次出现的片段，左右各最多 40 个字符；后续出现仅增加次数和路径，列表还只拿第一个可用片段作为 `glimpse`。要像 magpie 那样按消息展开、准确定位每次出现，需新增有界的安全上下文及其 role、字段路径、命中位置，并明确截断、淘汰与不可用状态。应在采集时隐藏全部已识别的值，包括 `warn`，继续不保存原值；如果扩大到完整文本节点，需同步重新评估 ADR-0005 对短上下文和不保存完整请求的约束。这属于新的数据契约，不是前端样式改动。[首次片段与聚合](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/mask/values.go#L88-L135)；[片段范围](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/internal/mask/values.go#L148-L160)；[列表 glimpse](https://github.com/GarlandQian/cpa-plugin-veil/blob/79c31b835102aaf9078b1efbf0ee401fe2cc66a7/management.go#L158-L183)；[ADR-0005](../adr/0005-masking-records-never-hold-values.md)。

后续若增加按值筛选，应明确“按 Kind 查请求”和“查同一 Placeholder/Stand-in”是不同能力。magpie 现有按值列表点击只实现前者，不应把精确值筛选描述为它已经提供的功能。

## 核验范围

- 已完成：官方仓库来源读取、固定 commit 源码下载；交叉检查前端 DOM/CSS、API 处理器、记录结构、保留逻辑；逐条对照上面的文件与行号。
- 未运行：magpie 应用/浏览器、测试、构建；本任务是源码研究，没有修改其实现，也没有访问用户运行数据。布局与交互结论未经过视觉截图验证。
- 本地证据副本：`/private/tmp/veil-magpie-privacy-code`；仅新增本研究文件，不修改 Veil 行为、ADR 或全局设置。
