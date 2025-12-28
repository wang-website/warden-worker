# 部署指南

本指南将帮助您将 Warden Worker 部署到 Cloudflare Workers。

## 前提条件

在开始之前，请确保您拥有：

1. **Cloudflare 账户** - 免费账户即可
2. **Wrangler CLI** - Cloudflare Workers 的命令行工具
3. **Rust 工具链** - 用于构建项目
4. **Git** - 用于克隆仓库

## 安装 Wrangler

如果尚未安装 Wrangler，请运行：

```bash
npm install -g wrangler
```

验证安装：

```bash
wrangler --version
```

## 登录 Cloudflare

```bash
wrangler login
```

这将在浏览器中打开 Cloudflare 授权页面。

## 部署步骤

### 1. 克隆仓库

```bash
git clone https://github.com/wang-website/warden-worker.git
cd warden-worker
```

### 2. 创建 D1 数据库

创建一个新的 D1 数据库来存储您的密码库数据：

```bash
wrangler d1 create warden-db
```

此命令将输出数据库 ID。记下这个 ID，您将在下一步中使用它。

示例输出：
```
✅ Successfully created DB 'warden-db'!

[[d1_databases]]
binding = "DB"
database_name = "warden-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 3. 配置数据库 ID

您有两个选项来配置数据库 ID：

#### 选项 A：使用 .env 文件（推荐）

在项目根目录创建一个 `.env` 文件：

```bash
echo 'D1_DATABASE_ID="your-database-id-here"' > .env
```

将 `your-database-id-here` 替换为第 2 步中的实际数据库 ID。

`.env` 文件已在 `.gitignore` 中，不会被提交到 Git。

#### 选项 B：使用环境变量

在部署前设置环境变量：

```bash
export D1_DATABASE_ID="your-database-id-here"
```

### 4. 初始化数据库架构

运行 SQL 架构文件来创建必要的表：

```bash
wrangler d1 execute warden-db --file=./sql/schema.sql
```

这将创建 `users`、`ciphers` 和 `folders` 表。

### 5. 配置环境变量

在 Cloudflare Worker 中设置必要的环境变量：

```bash
# JWT 访问令牌密钥（使用强随机字符串）
wrangler secret put JWT_SECRET

# JWT 刷新令牌密钥（使用不同的强随机字符串）
wrangler secret put JWT_REFRESH_SECRET

# 允许注册的邮箱地址（逗号分隔）
wrangler secret put ALLOWED_EMAILS
```

对于每个命令，系统会提示您输入值。

**生成强随机密钥的示例：**

```bash
# 在 Linux/macOS 上
openssl rand -base64 32

# 或使用 Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**ALLOWED_EMAILS 示例：**
```
your-email@example.com,another@example.com
```

### 6. 构建和部署

```bash
wrangler deploy
```

此命令将：
1. 构建 Rust 项目
2. 将其编译为 WebAssembly
3. 部署到 Cloudflare Workers

部署成功后，您将看到 Worker 的 URL：
```
Published warden-worker (0.1s)
  https://warden-worker.your-account.workers.dev
```

### 7. 验证部署

测试健康检查端点：

```bash
curl https://warden-worker.your-account.workers.dev/health
```

应该返回：
```json
{
  "status": "ok",
  "service": "warden-worker",
  "version": "0.1.0"
}
```

## 配置 Bitwarden 客户端

### 浏览器扩展

1. 打开 Bitwarden 浏览器扩展
2. 在登录页面，点击左上角的设置图标
3. 选择"自托管环境"
4. 在"服务器 URL"中输入您的 Worker URL：
   ```
   https://warden-worker.your-account.workers.dev
   ```
5. 保存设置
6. 使用您允许的邮箱地址注册或登录

### 移动应用

1. 打开 Bitwarden 移动应用
2. 在登录页面，点击地区选择器
3. 选择"自托管"
4. 输入您的服务器 URL
5. 保存并登录

## 更新部署

当您对代码进行更改后：

```bash
# 拉取最新代码
git pull origin main

# 重新部署
wrangler deploy
```

## 自定义域名（可选）

如果您想使用自定义域名：

1. 在 Cloudflare 中添加您的域名
2. 在 Workers 设置中添加自定义域：

```bash
wrangler domains add your-domain.com
```

或在 Cloudflare Dashboard 中手动配置。

## 备份

定期备份您的 D1 数据库非常重要：

```bash
# 导出数据库
wrangler d1 export warden-db --output=backup.sql
```

要恢复备份：

```bash
wrangler d1 execute warden-db --file=backup.sql
```

## 监控

### 查看日志

实时查看 Worker 日志：

```bash
wrangler tail
```

### 检查数据库

查询数据库：

```bash
wrangler d1 execute warden-db --command="SELECT * FROM users"
```

## 故障排除

### 问题：无法连接到数据库

**解决方案：**
- 验证 `D1_DATABASE_ID` 环境变量设置正确
- 确保数据库已创建且架构已初始化
- 检查 `wrangler.toml` 中的数据库绑定

### 问题：注册失败

**解决方案：**
- 确认邮箱地址在 `ALLOWED_EMAILS` 中
- 检查 JWT 密钥是否正确设置
- 查看 Worker 日志以了解详细错误

### 问题：认证失败

**解决方案：**
- 验证 `JWT_SECRET` 和 `JWT_REFRESH_SECRET` 已设置
- 确保令牌没有过期
- 清除浏览器缓存并重新登录

### 问题：构建失败

**解决方案：**
- 确保已安装 Rust 工具链
- 运行 `cargo clean` 并重试
- 检查 `worker-build` 是否已安装：`cargo install worker-build`

## 安全建议

1. **使用强 JWT 密钥**：至少 32 字符的随机字符串
2. **限制注册**：只在 `ALLOWED_EMAILS` 中添加信任的邮箱
3. **定期备份**：至少每周备份一次数据库
4. **监控日志**：定期检查异常活动
5. **保持更新**：定期更新到最新版本

## 成本

Cloudflare Workers 免费套餐包括：
- 每天 100,000 次请求
- 每次请求 10ms CPU 时间
- 无限的出站带宽

对于个人使用，这通常已经足够了。

## 获取帮助

如果遇到问题：

1. 查看 [故障排除](#故障排除) 部分
2. 检查 [GitHub Issues](https://github.com/wang-website/warden-worker/issues)
3. 创建新的 Issue 并提供：
   - 错误消息
   - 部署日志
   - 您的配置（不要分享密钥！）

## 下一步

- 阅读 [API 文档](API.md)
- 查看 [安全文档](SECURITY.md)
- 了解如何 [贡献](CONTRIBUTING.md)

祝您使用愉快！ 🎉
