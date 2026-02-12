use axum::{extract::State, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::{auth::Claims, db, error::AppError, handlers::verify_admin};

/// vaultwarden 用户数据（前端从 SQLite 读取后发送）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultwardenUser {
    /// vaultwarden uses "uuid" as primary key
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub salt: String,
    pub password_iterations: i64,
    pub password_hint: Option<String>,
    pub key: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_recover: Option<String>,
    pub security_stamp: String,
    pub equivalent_domains: String,
    pub excluded_globals: String,
    pub created_at: String,
    pub updated_at: String,
    /// akey column was added later in vaultwarden
    pub akey: Option<String>,
    /// avatar_color
    pub avatar_color: Option<String>,
    /// kdf_type - 0=PBKDF2, 1=Argon2id
    #[serde(default)]
    pub client_kdf_type: i32,
    /// client_kdf_iter
    #[serde(default = "default_kdf_iterations")]
    pub client_kdf_iter: i32,
    /// client_kdf_memory (Argon2)
    pub client_kdf_memory: Option<i32>,
    /// client_kdf_parallelism (Argon2)
    pub client_kdf_parallelism: Option<i32>,
}

fn default_kdf_iterations() -> i32 {
    600_000
}

/// vaultwarden cipher 数据
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultwardenCipher {
    pub uuid: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub folder_uuid: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    pub favorite: bool,
    pub password_history: Option<String>,
    pub reprompt: Option<i32>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// vaultwarden folder 数据
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultwardenFolder {
    pub uuid: String,
    pub user_uuid: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// 完整迁移请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrateRequest {
    pub users: Vec<VaultwardenUser>,
    #[serde(default)]
    pub folders: Vec<VaultwardenFolder>,
    #[serde(default)]
    pub ciphers: Vec<VaultwardenCipher>,
    /// 是否覆盖已存在的用户（根据邮箱匹配）
    #[serde(default)]
    pub overwrite_existing: bool,
}

/// 迁移结果
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrateResult {
    pub users_imported: usize,
    pub users_skipped: usize,
    pub folders_imported: usize,
    pub ciphers_imported: usize,
    pub errors: Vec<String>,
}

/// POST /api/wang/migrate - 从 vaultwarden SQLite 数据库迁移数据
///
/// 前端使用 sql.js 在浏览器中读取 vaultwarden 的 SQLite 数据库文件，
/// 将用户、文件夹、密码项等数据提取后通过 JSON 发送到后端写入 D1。
///
/// 安全说明：
/// - 仅管理员可执行此操作
/// - 密码哈希按原样迁移（vaultwarden 和 bitwarden 使用相同的哈希方案）
/// - 加密密钥（key, private_key, public_key）按原样迁移
/// - 前端读取，后端写入，数据库文件不会上传到服务器
#[worker::send]
pub async fn migrate_from_vaultwarden(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<MigrateRequest>,
) -> Result<Json<MigrateResult>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;
    let mut result = MigrateResult {
        users_imported: 0,
        users_skipped: 0,
        folders_imported: 0,
        ciphers_imported: 0,
        errors: Vec::new(),
    };

    // 构建 uuid -> new_id 映射（用于外键关系）
    let mut user_id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut folder_id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // 1. 导入用户
    for vw_user in &payload.users {
        let email = vw_user.email.to_lowercase();

        // 检查邮箱是否已存在
        let existing: Option<Value> = db
            .prepare("SELECT id FROM users WHERE email = ?1")
            .bind(&[email.clone().into()])
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        if let Some(existing_row) = existing {
            if !payload.overwrite_existing {
                let existing_id = existing_row
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                user_id_map.insert(vw_user.uuid.clone(), existing_id);
                result.users_skipped += 1;
                continue;
            }
            // 覆盖模式：先删除旧用户的数据
            let existing_id = existing_row
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let _ = query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", &existing_id)
                .map_err(|_| AppError::Database)?
                .run()
                .await;

            let _ = query!(&db, "DELETE FROM folders WHERE user_id = ?1", &existing_id)
                .map_err(|_| AppError::Database)?
                .run()
                .await;

            let _ = query!(&db, "DELETE FROM users WHERE id = ?1", &existing_id)
                .map_err(|_| AppError::Database)?
                .run()
                .await;
        }

        let new_id = Uuid::new_v4().to_string();
        user_id_map.insert(vw_user.uuid.clone(), new_id.clone());

        // 将 vaultwarden 的 password_hash（BLOB/hex）直接迁移
        // vaultwarden 使用 Argon2id 或 PBKDF2-SHA256 哈希，
        // 我们按原样保存，并标记为旧方案（无 password_salt）
        // 用户下次登录时会自动迁移到新方案
        let password_hash = &vw_user.password_hash;

        let now = Utc::now().to_rfc3339();
        let private_key = vw_user.private_key.clone().unwrap_or_default();
        let public_key = vw_user.public_key.clone().unwrap_or_default();

        let insert_result = query!(
            &db,
            "INSERT INTO users (id, name, email, email_verified, master_password_hash, master_password_hint, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, equivalent_domains, excluded_globals, totp_recover, avatar_color, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            new_id,
            vw_user.name,
            email,
            1,  // email_verified = true for migrated users
            password_hash,
            vw_user.password_hint,
            vw_user.key,
            private_key,
            public_key,
            vw_user.client_kdf_type,
            vw_user.client_kdf_iter,
            vw_user.client_kdf_memory,
            vw_user.client_kdf_parallelism,
            vw_user.security_stamp,
            vw_user.equivalent_domains,
            vw_user.excluded_globals,
            vw_user.totp_recover,
            vw_user.avatar_color,
            vw_user.created_at,
            now
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await;

        match insert_result {
            Ok(_) => result.users_imported += 1,
            Err(e) => {
                result.errors.push(format!(
                    "用户 {} ({}) 导入失败: {}",
                    vw_user.name, vw_user.email, e
                ));
            }
        }
    }

    // 2. 导入文件夹
    for vw_folder in &payload.folders {
        let user_id = match user_id_map.get(&vw_folder.user_uuid) {
            Some(id) => id.clone(),
            None => {
                result.errors.push(format!(
                    "文件夹 {} 的所属用户 {} 未找到，跳过",
                    vw_folder.uuid, vw_folder.user_uuid
                ));
                continue;
            }
        };

        let new_folder_id = Uuid::new_v4().to_string();
        folder_id_map.insert(vw_folder.uuid.clone(), new_folder_id.clone());

        let insert_result = query!(
            &db,
            "INSERT INTO folders (id, user_id, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            new_folder_id,
            user_id,
            vw_folder.name,
            vw_folder.created_at,
            vw_folder.updated_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await;

        match insert_result {
            Ok(_) => result.folders_imported += 1,
            Err(e) => {
                result.errors.push(format!(
                    "文件夹 {} 导入失败: {}",
                    vw_folder.name, e
                ));
            }
        }
    }

    // 3. 导入密码项
    for vw_cipher in &payload.ciphers {
        let user_id = vw_cipher
            .user_uuid
            .as_ref()
            .and_then(|uuid| user_id_map.get(uuid))
            .cloned();

        if user_id.is_none() && vw_cipher.user_uuid.is_some() {
            result.errors.push(format!(
                "密码项 {} 的所属用户未找到，跳过",
                vw_cipher.uuid
            ));
            continue;
        }

        let folder_id = vw_cipher
            .folder_uuid
            .as_ref()
            .and_then(|uuid| folder_id_map.get(uuid))
            .cloned();

        let new_cipher_id = Uuid::new_v4().to_string();

        // vaultwarden 的 data 字段直接存储完整的加密 JSON
        // 我们可以直接迁移
        let data = &vw_cipher.data;

        let insert_result = query!(
            &db,
            "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, deleted_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            new_cipher_id,
            user_id,
            vw_cipher.organization_uuid,
            vw_cipher.r#type,
            data,
            vw_cipher.favorite,
            folder_id,
            vw_cipher.deleted_at,
            vw_cipher.created_at,
            vw_cipher.updated_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await;

        match insert_result {
            Ok(_) => result.ciphers_imported += 1,
            Err(e) => {
                result.errors.push(format!(
                    "密码项 {} 导入失败: {}",
                    vw_cipher.uuid, e
                ));
            }
        }
    }

    Ok(Json(result))
}
