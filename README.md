# Warden Worker

# 有问题？尝试 [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/afoim/warden-worker)

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端，使用 D1（SQLite）存储数据，Rust 编写，零服务器维护。

客户端在本地完成加密，服务端只保存密文。

> [!WARNING]
> 从旧版本升级：建议先在客户端导出密码库 → 全新部署 → 再导入，避免兼容问题。

## 功能

- **无服务器**：Cloudflare Workers + D1，免费额度即可运行
- **多端兼容**：官方 Bitwarden（浏览器扩展/桌面/安卓）及第三方客户端
- **密码管理**：密码项增删改查、软删除与恢复、收藏、文件夹、同步
- **文件附件**：支持 R2 或 KV 两种存储后端（可选）
- **Send 分享**：创建加密分享链接，支持密码保护与过期时间
- **二步验证（TOTP）**：Authenticator 绑定、remember-device 流程
- **账户管理**：修改密码、密钥轮换、删除账户
- **多管理员**：`ADMIN_EMAILS` 支持多个邮箱（逗号分隔）
- **登录速率限制**：基于 Cloudflare Rate Limiting，防暴力破解
- **管理后台**：`/wang` 面板查看统计、管理用户、从 Vaultwarden 导入数据
- **安全加固**：邮箱格式校验、KDF 参数范围检查、时序攻击防护、参数化查询

## 快速部署

### 0. 前置条件

- Cloudflare 账号
- Node.js + Wrangler：`npm i -g wrangler`
- Rust 工具链 + worker-build：`cargo install worker-build`

### 1. 创建 D1 数据库

```bash
wrangler d1 create vault1
```

将输出的 `database_id` 填入 `wrangler.toml` 的 `[[d1_databases]]` 部分。

### 2. 初始化数据库

> `sql/schema_full.sql` 会 DROP 所有表，仅用于全新部署。

```bash
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql
```

### 3. 配置密钥

```bash
wrangler secret put JWT_SECRET          # 访问令牌签名密钥
wrangler secret put JWT_REFRESH_SECRET  # 刷新令牌签名密钥
wrangler secret put ALLOWED_EMAILS      # 注册白名单（仅首次无用户时生效），多邮箱逗号分隔
```

**可选密钥：**

```bash
wrangler secret put TWO_FACTOR_ENC_KEY  # Base64 的 32 字节密钥，加密 TOTP 密钥（不设则明文存储）
wrangler secret put ADMIN_EMAILS        # 管理员邮箱，逗号分隔（启用 /wang 管理后台）
```

### 4. 部署

```bash
wrangler deploy
```

部署后将 Workers URL 或自定义域名填入 Bitwarden 客户端的「自托管服务器 URL」。

### 5. 附件存储（可选）

附件功能需要 R2 或 KV 作为文件存储后端，二选一即可。R2 优先级更高。

**方式 A：R2 存储桶**（无大小限制，需绑定信用卡）

```bash
wrangler r2 bucket create warden-attachments
```

取消 `wrangler.toml` 中 `[[r2_buckets]]` 的注释：

```toml
[[r2_buckets]]
binding = "ATTACHMENTS_BUCKET"
bucket_name = "warden-attachments"
```

**方式 B：KV 命名空间**（免费，单值最大 25MB）

```bash
wrangler kv namespace create ATTACHMENTS_KV
```

将输出的 `id` 填入 `wrangler.toml` 并取消 `[[kv_namespaces]]` 的注释：

```toml
[[kv_namespaces]]
binding = "ATTACHMENTS_KV"
id = "<你的 KV namespace id>"
```

配置完成后重新执行 `wrangler deploy`。

### 6. 速率限制

`wrangler.toml` 已预配置登录速率限制（每邮箱 60 秒内最多 5 次），无需额外操作：

```toml
[[ratelimits]]
name = "LOGIN_RATE_LIMITER"
namespace_id = "1001"
simple = { limit = 5, period = 60 }
```

### 7. 旧版升级

如果是在已有部署上新增附件功能，需执行迁移：

```bash
wrangler d1 execute vault1 --remote --file=migrations/20260214_add_attachments.sql
```

## 管理后台

访问 `https://<你的域名>/wang`，使用 `ADMIN_EMAILS` 中的邮箱登录，可以：

- 查看统计（用户数、密码项、文件夹、Send、2FA 启用率、存储后端）
- 管理用户（查看/创建/删除）
- 从 Vaultwarden 导入数据（上传 `.sql` 备份文件）

## 客户端使用建议

- 安卓客户端如曾指向其它自托管地址，建议清缓存后重新添加服务器。
- 首次启用 TOTP 后，在同一设备完成一次 TOTP 登录，后续会自动走 remember-device。

## 本地开发

```bash
wrangler d1 execute vault1 --local --file=sql/schema_full.sql
wrangler dev
```

本地通过 `.dev.vars` 注入 secrets：

```
JWT_SECRET=dev-secret
JWT_REFRESH_SECRET=dev-refresh-secret
ALLOWED_EMAILS=test@example.com
ADMIN_EMAILS=test@example.com
```

## 许可证

MIT
