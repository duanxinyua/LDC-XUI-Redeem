# LDC-XUI-Redeem

LDC-XUI-Redeem 是一个基于 Linux.do Credit 的 3x-ui 节点积分兑换系统。用户可以通过 LDC 积分或兑换码自助兑换流量订阅，系统会自动在指定 3x-ui 面板中创建客户端，并生成可直接使用的订阅链接。

项目支持多 3x-ui 面板、节点白名单、LDC 支付订单、订单查询、退款记录、兑换总流量限制、Cloudflare Turnstile 防滥用验证、后台用户与订单管理等功能，适合个人节点服务、小型公益服务或积分兑换场景使用。

## 功能特性

- 支持兑换码兑换订阅。
- 支持 Linux.do Credit 积分支付兑换订阅。
- 支持多个 3x-ui 面板，避免不同面板入站 ID 重复导致串节点。
- 支持从 3x-ui 实时读取 vmess/ws 入站。
- 支持节点白名单，不勾选时默认展示全部可用节点。
- 支持 LDC 总兑换流量限制，`0` 表示不限制。
- 支持 LDC 订单查询、状态同步、退款记录和商户分发工具。
- 支持 Cloudflare Turnstile 保护前台兑换、支付、查询和后台登录。
- 支持后台管理兑换码、用户、LDC 订单、3x-ui 设置、LDC 设置和账号信息。

## 安全提醒

不要提交以下文件到公开仓库：

```text
.env
redeem.db
redeem.db.bak*
venv/
.venv/
*.log
```

`.gitignore` 已默认忽略这些文件。生产环境请务必设置固定的 `APP_SECRET_KEY`，否则服务重启后登录会话可能失效。

## 环境要求

- Python 3.10+
- SQLite
- 可访问的 3x-ui 面板
- Linux.do Credit 商户参数，用于启用 LDC 积分兑换

## 安装

```bash
git clone https://github.com/duanxinyua/LDC-XUI-Redeem.git
cd LDC-XUI-Redeem

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
```

编辑 `.env`，至少配置：

```env
APP_SECRET_KEY=change-to-a-long-random-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-this-password

XUI_HOST=http://127.0.0.1:2053
XUI_USERNAME=your-3x-ui-username
XUI_PASSWORD=your-3x-ui-password

NODE_DOMAIN=your-node-domain.com
SUB_DOMAIN=your-redeem-domain.com
PUBLIC_BASE_URL=https://your-redeem-domain.com

LDC_PID=your-ldc-pid
LDC_KEY=your-ldc-key
LDC_GATEWAY=https://credit.linux.do/epay
```

## 启动

```bash
./start.sh
```

默认监听：

```text
0.0.0.0:5000
```

首次启动会自动初始化 `redeem.db`。后台地址：

```text
/admin/login
```

## 配置说明

### 3x-ui

启动后进入后台 `设置 -> 3x-ui 面板设置`：

- 可以编辑默认 3x-ui 面板。
- 可以新增多个 3x-ui 面板。
- 可以启用或禁用某个面板。
- 可以勾选上架节点白名单。

前台节点使用复合标识：

```text
面板ID:入站ID
```

例如：

```text
1:14
2:14
```

这样多个 3x-ui 面板存在相同入站 ID 时也不会串节点。

### LDC

进入后台 `设置 -> LDC 兑换`：

- 开启或关闭 LDC 积分兑换。
- 设置总流量限制，`0` 表示不限制。
- 设置兑换比例，例如 `1` 表示 `1GB = 1 积分`。

### Turnstile

进入后台 `设置 -> Turnstile`：

- 配置 Cloudflare Turnstile Site Key。
- 配置 Cloudflare Turnstile Secret Key。
- 开启后会保护前台兑换、支付、查询和后台登录。

## 目录结构

```text
.
├── app.py
├── start.sh
├── requirements.txt
├── .env.example
├── .gitignore
└── templates/
```

## 生产部署建议

- 使用 Nginx 反向代理到 `127.0.0.1:5000`。
- 使用 systemd 或 supervisor 托管进程。
- 配置 HTTPS。
- 定期备份 `redeem.db`，但不要提交到 git。
- 不要在公开环境暴露 3x-ui 面板。

## License

MIT
