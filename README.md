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
ADMIN_PASSWORD=admin

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

参数含义：

| 参数 | 是否必填 | 说明 |
| --- | --- | --- |
| `APP_SECRET_KEY` | 必填 | Flask 会话密钥，用于保护后台登录状态和 CSRF Token。生产环境必须改成足够长的随机字符串，不能使用示例值。 |
| `ADMIN_USERNAME` | 必填 | 首次初始化数据库时创建的后台管理员用户名。数据库已存在后，修改该值不会覆盖现有管理员账号。 |
| `ADMIN_PASSWORD` | 必填 | 首次初始化数据库时创建的后台管理员密码。数据库已存在后，修改该值不会覆盖现有管理员密码，可在后台个人中心修改。 |
| `XUI_HOST` | 必填 | 默认 3x-ui 面板地址，末尾不需要 `/`，例如 `http://127.0.0.1:2053`。后续也可以在后台添加多个 3x-ui 面板。 |
| `XUI_USERNAME` | 必填 | 默认 3x-ui 面板登录用户名。 |
| `XUI_PASSWORD` | 必填 | 默认 3x-ui 面板登录密码。该值会写入本地数据库，生产环境不要提交 `.env` 和 `redeem.db`。 |
| `NODE_DOMAIN` | 必填 | 节点连接使用的域名，也就是订阅中 vmess `add` 字段。通常填写你的节点落地域名或 CDN 域名。 |
| `SUB_DOMAIN` | 必填 | 兑换系统自身的访问域名，用于生成订阅链接，例如 `redeem.example.com`。 |
| `PUBLIC_BASE_URL` | 必填 | 用户公网访问兑换系统的完整地址，用于 LDC 支付回调和返回地址，例如 `https://redeem.example.com`。 |
| `LDC_PID` | 使用 LDC 时必填 | Linux.do Credit 商户 PID。不开启 LDC 积分兑换时可留空。 |
| `LDC_KEY` | 使用 LDC 时必填 | Linux.do Credit 商户密钥，用于签名和验签。不开启 LDC 积分兑换时可留空。 |
| `LDC_GATEWAY` | 使用 LDC 时必填 | Linux.do Credit 易支付网关地址，默认是 `https://credit.linux.do/epay`。 |

常用可选参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `XUI_EXPIRE_DAYS` | `30` | 兑换成功后创建的 3x-ui 用户默认有效期，单位为天。 |
| `XUI_TRAFFIC_LIMIT` | `20` | 生成兑换码和 LDC 页面默认兑换流量，单位为 GB。 |
| `SUB_PORT` | `443` | 订阅中 vmess `port` 字段。 |
| `SUB_PROTOCOL` | `vmess` | 订阅协议，目前项目主要按 vmess 生成订阅。 |
| `SUB_SECURITY` | `tls` | 订阅中 vmess `tls` 字段。 |
| `SUB_NETWORK` | `ws` | 订阅中 vmess `net` 字段。 |
| `LDC_MIN_TRAFFIC` | `1` | LDC 单次最小兑换流量，单位为 GB。 |
| `LDC_MAX_TRAFFIC` | `200` | LDC 单次最大兑换流量，单位为 GB。 |
| `TURNSTILE_SITE_KEY` | 空 | Cloudflare Turnstile 前端 Site Key。 |
| `TURNSTILE_SECRET_KEY` | 空 | Cloudflare Turnstile 后端 Secret Key。 |

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

如果你的站点域名是 `https://redeem.example.com`，完整后台登录地址就是：

```text
https://redeem.example.com/admin/login
```

## 后台入口

后台登录入口：

```text
/admin/login
```

首次启动时，如果数据库中还没有管理员账号，系统会使用 `.env` 中的以下参数创建初始管理员：

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
```

登录后主要入口：

| 地址 | 功能 |
| --- | --- |
| `/admin` | 后台首页，查看兑换码、用户和最近兑换概览。 |
| `/admin/settings` | 设置中心，管理 3x-ui 面板、LDC 兑换、Turnstile 和管理员账号。 |
| `/admin/ldc-orders` | LDC 兑换记录，支持订单查询、同步、退款。 |
| `/admin/ldc-tools` | LDC 商户分发工具。 |
| `/admin/codes` | 兑换码列表和生成入口。 |
| `/admin/users` | 已生成的订阅用户列表。 |

注意事项：

- `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 只在首次初始化数据库时生效。
- 如果 `redeem.db` 已经存在，修改 `.env` 中的管理员账号密码不会覆盖数据库中的账号。
- 已部署后如需修改后台账号，请登录后台后进入 `设置 -> 管理员账号` 修改。
- 登录页、设置中心和个人中心的密码输入框支持点击“显示/隐藏”，便于确认正在输入的密码。
- 后台密码使用哈希存储，系统不会保存明文密码，因此不能查看数据库中已经保存的原始密码。
- 如果忘记后台密码，需要直接处理数据库中的 `admins` 表或删除数据库重新初始化；删除数据库会丢失兑换记录，不建议在生产环境这样做。

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
