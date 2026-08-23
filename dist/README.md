# claudetoapi

专注 Claude 的订阅反代网关:把 Claude Code OAuth 订阅转成标准 Anthropic API(`/v1/messages`),并在**每一层**对齐真实 Claude Code CLI 的流量形态。

本项目基于两份素材构建:

- **sub2api**(LGPL-3.0)的公开行为模式——本项目为全新实现,未复制其代码;
- **claude.exe 2.1.241 的本地逆向成果**——所有伪装参数以真实 CLI payload 为准(指纹 salt、beta 注册表、billing 归因块、默认值表)。

## 相比 sub2api 修正的偏差(逆向验证)

| # | 修正 | 证据(claude.exe 2.1.241) |
|---|------|--------------------------|
| 1 | `max_tokens` 缺省补 **32000**(不是 128000) | payload `P3b=32000, D3b=128000`,抓包实测 32000 |
| 2 | **绝不注入** `temperature`(真实 CLI 不发送该字段) | 抓包无 temperature;payload 中仅出现于遥测 |
| 3 | cache_control 用**裸 `{"type":"ephemeral"}`**(无 ttl;仅 1h 模式带 ttl) | 抓包 system 块无 ttl 字段 |
| 4 | UA 与 SDK 版本**成对**:`claude-cli/2.1.241` ⇔ `X-Stainless-Package-Version: 0.208.0` | payload VERSION=2.1.241, packageVersion=0.208.0 |
| 5 | `effort-2025-11-24` 仅主线程携带;`extended-cache-ttl-2025-04-11` 仅 1h 缓存携带 | payload `KAE` / `re==="1h"` 条件推送 |
| 6 | **haiku 主线程请求不带** `claude-code-20250219` | payload `G3b: if(!haiku)` |
| 7 | billing 归因块带**请求链**:`cc_prev_req=req_*`(链上请求)+ `cc_prompt_id=<uuid>`(会话稳定) | payload 0x12445ab7 还原的完整字段序 |
| 8 | `cc_entrypoint` 与 system prompt **persona 联动**(cli / sdk-cli / claude-vscode) | 抓包 sdk-cli ⇔ Agent SDK 变体 |
| 9 | `thinking.budget_tokens ≤ max_tokens-1`,`display:"omitted"` | 抓包 `budget_tokens:31999, max_tokens:32000` |
| 10 | 模型 ID **透传**(不强制短→长映射) | 抓包直接发 `claude-sonnet-4-5` |
| 11 | 日期句水印归一化(4 种撇号码点 × 2 种分隔符)——对真 CC 流量也生效 | 防第三方客户端水印 |

## 防封层级(全部落地)

| 层 | 实现 | 代码 |
|---|------|------|
| TLS 指纹 | uTLS 复刻 Node.js 24.x ClientHello(JA3 `44f88fca…`,GREASE-ECH,http/1.1),HTTP/SOCKS5 隧道内保持 | `internal/tlsfp` |
| **header 顺序** | **手写 HTTP/1.1 序列化器**:Go 标准库按字母序发 header,真实 CLI 是固定顺序——绕过标准库按 wire 顺序输出,带连接复用池(真实 CLI 也复用连接) | `internal/gw/ordered.go` |
| header 大小写 | 每个 header 恢复抓包 wire casing(`X-Stainless-OS` 而非 `X-Stainless-Os`) | `internal/gw/headers.go` |
| 版本配对 | UA `claude-cli/2.1.241` ⇔ SDK `0.208.0` 成对锁定,Profile 整体切换 | `internal/profile` |
| billing 链 | `cc_version` 指纹(salt + chars[4,7,20] + sha256 前缀)+ `cc_prev_req`(轮次链)+ `cc_prompt_id`(会话稳定 UUID) | `internal/mimicry/billing.go` |
| entrypoint 联动 | `cli` / `sdk-cli` / `claude-vscode` 与 system prompt persona 变体对应 | `internal/mimicry/body.go` |
| 条件 beta | haiku 主线程不带 claude-code beta;effort 仅主线程;extended-cache-ttl 仅 1h 缓存;redact 默认关 | `internal/mimicry/betas.go` |
| body 形态 | max_tokens=32000、无 temperature、裸 ephemeral cache_control、thinking.display=omitted、budget≤max-1 | `internal/mimicry/body.go` |
| 真实扩充块 | 默认加载 `data/expansion_prompt.txt`(已预装本地抓包的 27KB 真实块) | `internal/mimicry/body.go` |
| 水印清洗 | 日期句隐写水印(4 撇号码点 × 2 分隔符)归一化,对真 CC 流量也生效 | `internal/mimicry/dateline.go` |
| **地理一致性** | **代理池带时区/语言:绑定后 accept-language、提示词内日期自动对齐出口 IP 的时区与地区** | `internal/gw/gateway.go` |
| 账号身份 | 每账号持久 ClientID/UA/entrypoint;UA 版本只升不降、偏移 >2 主版本拒收(防毒化) | `internal/gw/gateway.go` |
| 并发约束 | 每账号并发上限(默认 2,可调),贴近真实 CLI 1-3 并发会话 | `internal/gw/gateway.go` |
| **遥测旁路** | **复刻 CLI 的第一方后台流量**:flag 配置拉取(GrowthBook remote-eval)+ 事件批量上报,让账号有正常"生活轨迹" | `internal/telemetry` |
| 会话粘性 | 同对话固定同账号 + 同 `cc_prompt_id`,`cc_prev_req` 串成真实请求链 | `internal/gw/session.go` |

## 遥测旁路(协议逆向自 claude.exe 2.1.241)

真实 CLI 除了 `/v1/messages` 还有两条后台流量,中转账号完全没有——长期看是按账号维度的可区分信号。claudetoapi 已复刻:

**① flag 配置拉取(GrowthBook remote-eval)**
```
POST https://api.anthropic.com/api/eval-authed/sdk-zAZezfDKGoZuXXKe   (Bearer)
   ↓ 401/失败时回退
POST https://api.anthropic.com/api/eval/sdk-zAZezfDKGoZuXXKe
body: {attributes:{id,accountUUID,appVersion}, forcedVariations:{}, forcedFeatures:[], url}
```
节奏:每 360 分钟 ±10% 抖动(payload gate `tengu_gb_refresh_interval_minutes` 的钳制逻辑)。

**② 事件批量上报(OTLP 导出器)**
```
POST https://api.anthropic.com/api/event_logging/v2/batch
headers: Content-Type: application/json, User-Agent: <CLI UA>, x-service-name: claude-code, Authorization: Bearer <token>
body: {events:[{event_type:"ClaudeCodeInternalEvent", event_data:{event_name, event_id, timestamp, core_metadata:{cli_version}, user_metadata:{account_uuid}, user_id:<device>, event_metadata:{...}}}]}
```
- 每账号独立 runner,走**同一出口代理和有序传输层**(TLS/header 指纹一致);
- 账号首次被使用时启动:拉一次 eval + 发 `tengu_start`;
- 每次成功转发发 `tengu_api_query`(model/token 数,真实 CLI 每请求都记);
- 批量上限 200/批,失败重排队,每 60 秒冲刷,退出时强制 flush;
- 总开关 `mimicry.telemetry_bypass`(默认开),控制台概览卡片显示运行状态。

## 代理池配置(config.json)

```json
"proxies": [
  { "name": "us1", "url": "http://u:p@us.example.com:8080",
    "timezone": "America/New_York", "language": "en-US,en;q=0.9" },
  { "name": "jp1", "url": "socks5://jp.example.com:1080",
    "timezone": "Asia/Tokyo", "language": "ja-JP,ja;q=0.9,en-US;q=0.8" }
]
```

- 每个账号绑定一个池名(控制台「编辑」或添加时下拉选择)——可以一号一 IP,也可以几号共享一个 IP;
- 绑定后自动对齐:该账号所有请求的 `accept-language`、**系统提示词里的日期句**(改写为出口时区的"今天");
- 控制台「测试连通」按钮用真实 TLS 指纹经该代理拨 api.anthropic.com 验证可达性;
- 同一代理的连接在池内复用(与真实 CLI 的 keep-alive 行为一致),连接池统计显示在概览卡片。

## 架构

```
main.go                      入口/路由/后台 token 刷新
internal/
  config/      config.json + 环境变量
  store/       账号 JSON 存储(原子写、冷却状态持久化)
  oauth/       PKCE 浏览器流 + sessionKey 自动授权 + refresh_token 轮换
  profile/     CLI 版本 Profile(UA+SDK+默认值成对切换)
  mimicry/     billing 链 / beta 计算 / body 规范化 / 水印归一化 / user_id 重写
  tlsfp/       uTLS Node.js 24.x ClientHello(JA3 44f88fca…,含 GREASE-ECH,http/1.1)
  gw/          网关:鉴权→粘性会话→选号→转发→重试/故障转移→SSE 续传→限流解析
```

## 快速开始

```bash
# 构建(需 Go ≥1.22)
go build -o claudetoapi .

# 配置
cp config.example.json config.json   # 改 admin_key 与 api_keys

# 启动
./claudetoapi -c config.json
```

**强烈建议**把真实 CLI 抓包得到的 system 扩充块(约 27KB,见 `analysis/claude-code/dynamic_request_full.json` 的 system[2])保存为 `data/expansion_prompt.txt`——mimicry 的 system 第三块会自动加载它,达到与真实流量同量级;未提供时使用内置精简版。

## 添加账号

```bash
# 方式一:claude.ai sessionKey 自动授权(推荐)
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"mode":"session_key","session_key":"sk-ant-...","name":"acc1","proxy_url":"http://user:pass@host:port"}' \
  http://127.0.0.1:8082/admin/accounts

# 方式二:浏览器 OAuth
curl -H "X-Admin-Key: $ADMIN" "http://127.0.0.1:8082/admin/oauth/url"   # 打开返回的 URL
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"code":"<回调页的 code>","state":"<返回的 state>"}' \
  http://127.0.0.1:8082/admin/oauth/complete

# 方式三:手工导入已有 token
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"mode":"manual","refresh_token":"...","name":"acc2"}' \
  http://127.0.0.1:8082/admin/accounts
```

## 客户端接入

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8082
export ANTHROPIC_API_KEY=sk-ctapi-change-me   # 或 ANTHROPIC_AUTH_TOKEN
claude   # Claude Code 直接可用;其他 Anthropic SDK 客户端同理
```

- **真实 Claude Code 流量**:仅重写 `metadata.user_id` 设备身份(账号级稳定)+ 水印归一化,其余字节原样透传(保住 prompt cache);
- **第三方客户端**:完整 mimicry(3-block system、billing 链、条件 beta、参数补齐)。

## 行为要点

- **粘性会话**:同一对话固定同一账号(sessionHash = user_id.session_id,退化到内容哈希);同账号同 `cc_prompt_id`,轮次间以 `cc_prev_req` 链接——与真实 CLI 的会话链一致;
- **故障转移**:401 → 失效 token + 10 分钟冷却等刷新;403 → 永久禁用;429 → 解析 `anthropic-ratelimit-unified-{5h,7d,7d_oi}-*` 精确停到窗口重置,无重置头的 429 只做 5 秒兜底(那是第三方判定信号,不是真限流);529/5xx → 换号;
- **账号身份**:每账号持久化 ClientID(64hex)+ UA + entrypoint persona,版本只升不降,畸形 UA(如 `999.0.0-local`)拒收——sub2api 的教训:被毒化的 UA 会招来无重置头的持续 429;
- **代理**:每账号可绑独立代理(HTTP/SOCKS5),TLS 指纹在代理隧道内保持。

## 局限(与 sub2api 相比)

单节点、无计费/用户体系、无 Web 管理台;存储为 JSON 文件(适合 ≤ 数十账号);`anthropic-dispatch-id`、`x-cc-fallback-*` 等灰度头默认关闭(配置可开);遥测旁路(statsig)未实现——见《防封增强方案》P2 项。

## 合规提示

仅将**你自己拥有的** Claude 订阅用于个人 API 化;共享/转售订阅违反 Anthropic ToS,风险自负。

## 致谢

- [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api)(行为参考,LGPL-3.0,本项目未复制其代码)
- 本地逆向笔记:`D:\逆向\NOTES.md`、`analysis/claude-code/`
