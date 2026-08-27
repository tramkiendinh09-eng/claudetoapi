# claudetoapi 服务器部署指南

## 一、快速部署(Linux)

```bash
# 1. 上传并解压(按你的架构选 amd64 / arm64)
mkdir -p /opt/claudetoapi && cd /opt/claudetoapi
tar xzf claudetoapi-linux-amd64.tar.gz

# 2. 改配置(必改 admin_key 和 api_keys!)
cp config.example.json config.json
vim config.json

# 3. 测试运行
./claudetoapi-linux-amd64 -c config.json
# 看到 "claudetoapi listening addr=:8082" 即成功
# 浏览器打开 http://服务器IP:8082/ 进入控制台

# 4. (可选)装载真实扩充提示词(强烈建议,提升伪装质量)
#    把 data/expansion_prompt.txt 一并部署(压缩包已含)

# 5. systemd 常驻
sudo cp claudetoapi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now claudetoapi
sudo journalctl -u claudetoapi -f   # 看日志
```

## 二、配置说明(config.json)

```jsonc
{
  "listen": ":8082",              // 监听地址;公网部署务必套 nginx + TLS
  "admin_key": "强随机串",         // 控制台密钥,必改!
  "api_keys": ["sk-ctapi-xxx"],   // 客户端用的 API key,必改!
  "accounts_dir": "./data",       // 账号存储(自动创建)
  "default_proxy_url": "",        // 默认出口代理(全部账号走它)
  "proxies": [                    // 代理池:一号一 IP 或几号一 IP
    { "name": "us1", "url": "http://u:p@ip:port",
      "timezone": "America/New_York", "language": "en-US,en;q=0.9" }
  ],
  "profile": "2.1.247",           // 伪装 CLI 版本(与 SDK 版本成对锁定)
  "mimicry": {
    "default_entrypoint": "cli",  // cli / sdk-cli / claude-vscode
    "telemetry_bypass": true,     // 遥测旁路(默认开,建议保持)
    "dispatch_header": false,     // anthropic-dispatch-id 灰度头
    "redact_thinking": false,
    "max_attempts": 3             // 单请求最多换号次数
  }
}
```

环境变量覆盖:`CTAPI_LISTEN` / `CTAPI_ADMIN_KEY` / `CTAPI_API_KEYS`(逗号分隔) / `CTAPI_PROXY`。

## 三、添加账号(控制台或 curl)

```bash
ADMIN="你的admin_key"
HOST="http://127.0.0.1:8082"

# 方式一:sessionKey(推荐)——登录 claude.ai → F12 → Cookies → sessionKey
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"mode":"session_key","session_key":"sk-ant-sid01-...","name":"acc1","proxy":"us1"}' \
  $HOST/admin/accounts

# 方式二:浏览器 OAuth
curl -H "X-Admin-Key: $ADMIN" "$HOST/admin/oauth/url"    # 打开链接授权
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"code":"回调里的code","state":"返回的state"}' $HOST/admin/oauth/complete

# 方式三:导入已有 token
curl -X POST -H "X-Admin-Key: $ADMIN" -H "content-type: application/json" \
  -d '{"mode":"manual","refresh_token":"...","name":"acc2"}' $HOST/admin/accounts
```

## 四、客户端接入

```bash
export ANTHROPIC_BASE_URL=http://服务器IP:8082
export ANTHROPIC_API_KEY=sk-ctapi-xxx
claude    # Claude Code 直接可用
```

## 五、公网部署安全清单

- **必改** admin_key / api_keys(默认值=裸奔);
- 建议前面套 nginx 做 TLS 终结 + 只放行 `/v1/*` 和控制台路径加 IP 白名单;
- 控制台(`/:8082` 首页)有登录门,但 admin_key 强度就是唯一屏障;
- 服务器出站需能访问 api.anthropic.com 与 claude.ai(直连或走代理池);
- **服务器 IP 所在地区建议与代理出口地区一致**(或干脆用服务器本地直连则无需代理)——否则 messages 流量 IP 和遥测流量 IP 不在同一地区。

## 六、文件清单

| 文件 | 说明 |
|---|---|
| claudetoapi-linux-amd64 / -arm64 | Linux 二进制(内嵌 Web 控制台) |
| claudetoapi-windows-amd64.exe | Windows 二进制 |
| config.example.json | 配置模板 |
| data/expansion_prompt.txt | 真实 CLI 抓包的 27KB 系统提示词扩充块(部署到 data/ 下) |
| claudetoapi.service | systemd 模板 |
| DEPLOY.md | 本文件 |
