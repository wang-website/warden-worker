# API 文档

本文档描述了 Warden Worker 的 API 端点。所有端点都兼容 Bitwarden API 规范。

## 基础信息

- **基础 URL**: `https://your-worker.workers.dev`
- **认证**: Bearer Token (JWT)
- **内容类型**: `application/json`

## 认证端点

### 预登录 (Prelogin)

获取用户的 KDF 设置。

```http
POST /identity/accounts/prelogin
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**响应:**
```json
{
  "kdf": 0,
  "kdf_iterations": 600000
}
```

### 注册 (Register)

创建新用户账户。

```http
POST /identity/accounts/register/finish
Content-Type: application/json

{
  "name": "用户名",
  "email": "user@example.com",
  "masterPasswordHash": "...",
  "masterPasswordHint": "提示（可选）",
  "userSymmetricKey": "...",
  "userAsymmetricKeys": {
    "publicKey": "...",
    "encryptedPrivateKey": "..."
  },
  "kdf": 0,
  "kdfIterations": 600000
}
```

**注意**: 只有在 `ALLOWED_EMAILS` 环境变量中列出的邮箱才能注册。

### 获取令牌 (Token)

使用密码或刷新令牌登录。

```http
POST /identity/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user@example.com&password=masterPasswordHash
```

或使用刷新令牌:

```http
POST /identity/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=...
```

**响应:**
```json
{
  "access_token": "...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "refresh_token": "...",
  "Key": "...",
  "PrivateKey": "...",
  "Kdf": 0,
  "ResetMasterPassword": false,
  "ForcePasswordReset": false,
  "UserDecryptionOptions": {
    "HasMasterPassword": true,
    "Object": "userDecryptionOptions"
  }
}
```

## 账户管理端点

所有账户管理端点需要认证（Bearer Token）。

### 获取用户资料 (Profile)

```http
GET /api/accounts/profile
Authorization: Bearer <access_token>
```

### 更改密码

```http
POST /api/accounts/password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "masterPasswordHash": "当前密码哈希",
  "newMasterPasswordHash": "新密码哈希",
  "key": "新加密密钥"
}
```

### 删除账户

```http
POST /api/accounts/delete
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "masterPasswordHash": "密码哈希确认"
}
```

**警告**: 此操作会永久删除账户和所有相关数据（密码项、文件夹等）。

### 获取修订日期

```http
GET /api/accounts/revision-date
Authorization: Bearer <access_token>
```

返回最后更新的时间戳，用于判断是否需要同步。

## 同步端点

### 获取同步数据

```http
GET /api/sync
Authorization: Bearer <access_token>
```

返回用户的所有数据，包括配置文件、密码项和文件夹。

**响应:**
```json
{
  "profile": { ... },
  "folders": [ ... ],
  "ciphers": [ ... ],
  "domains": null,
  "object": "sync"
}
```

## 密码项 (Cipher) 端点

### 创建密码项

```http
POST /api/ciphers/create
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "cipher": {
    "type": 1,
    "name": "加密的名称",
    "notes": "加密的笔记",
    "favorite": false,
    "folderId": null,
    "organizationId": null,
    "login": {
      "username": "加密的用户名",
      "password": "加密的密码",
      "totp": "TOTP 密钥"
    }
  },
  "collectionIds": []
}
```

### 获取单个密码项

```http
GET /api/ciphers/{id}
Authorization: Bearer <access_token>
```

### 更新密码项

```http
PUT /api/ciphers/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "type": 1,
  "name": "更新的名称",
  ...
}
```

### 软删除密码项

```http
POST /api/ciphers/{id}/delete
Authorization: Bearer <access_token>
```

将密码项标记为已删除，但不永久删除。

### 恢复密码项

```http
PUT /api/ciphers/{id}/restore
Authorization: Bearer <access_token>
```

恢复已软删除的密码项。

### 永久删除密码项

```http
DELETE /api/ciphers/{id}/delete-admin
Authorization: Bearer <access_token>
```

永久删除密码项，无法恢复。

## 文件夹端点

### 创建文件夹

```http
POST /api/folders
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "加密的文件夹名称"
}
```

### 更新文件夹

```http
PUT /api/folders/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "更新的文件夹名称"
}
```

### 删除文件夹

```http
DELETE /api/folders/{id}
Authorization: Bearer <access_token>
```

## 导入端点

### 导入数据

```http
POST /api/ciphers/import
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "ciphers": [ ... ],
  "folders": [ ... ],
  "folderRelationships": [ ... ]
}
```

批量导入密码项和文件夹。

## 配置端点

### 获取服务器配置

```http
GET /api/config
```

返回服务器配置和功能标志，无需认证。

## 密码项类型

- `1`: 登录 (Login)
- `2`: 安全笔记 (Secure Note)
- `3`: 银行卡 (Card)
- `4`: 身份信息 (Identity)

## 错误响应

所有错误都返回 JSON 格式：

```json
{
  "error": "错误消息"
}
```

常见 HTTP 状态码：

- `200 OK`: 成功
- `400 Bad Request`: 无效的请求
- `401 Unauthorized`: 未认证或令牌无效
- `404 Not Found`: 资源不存在
- `500 Internal Server Error`: 服务器错误

## 安全注意事项

1. 所有密码项数据在客户端加密
2. 服务器只存储加密数据
3. 使用 HTTPS 保护传输中的数据
4. 定期轮换 JWT 密钥
5. 使用强主密码

## 速率限制

⚠️ **当前未实施**: 此 API 目前没有速率限制。建议在 Cloudflare Worker 层面配置速率限制。
