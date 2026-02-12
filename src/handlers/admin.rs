use axum::{extract::State, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::{
    auth::Claims,
    crypto::{generate_salt, hash_password_for_storage},
    db,
    error::AppError,
    handlers::{server_password_iterations, verify_admin},
};

/// GET /api/wang/users - 获取所有用户列表
#[worker::send]
pub async fn list_users(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    let rows: Vec<Value> = db
        .prepare(
            "SELECT id, name, email, email_verified, avatar_color, kdf_type, kdf_iterations, created_at, updated_at FROM users ORDER BY created_at DESC",
        )
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    // 统计每个用户的 cipher 数量
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let user_id = row.get("id").and_then(|v| v.as_str()).unwrap_or("");

        let cipher_count: Option<Value> = db
            .prepare("SELECT COUNT(*) as cnt FROM ciphers WHERE user_id = ?1")
            .bind(&[user_id.into()])
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let count = cipher_count
            .and_then(|v| v.get("cnt").and_then(|c| c.as_i64()))
            .unwrap_or(0);

        let folder_count: Option<Value> = db
            .prepare("SELECT COUNT(*) as cnt FROM folders WHERE user_id = ?1")
            .bind(&[user_id.into()])
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let f_count = folder_count
            .and_then(|v| v.get("cnt").and_then(|c| c.as_i64()))
            .unwrap_or(0);

        users.push(json!({
            "id": row.get("id"),
            "name": row.get("name"),
            "email": row.get("email"),
            "emailVerified": row.get("email_verified"),
            "avatarColor": row.get("avatar_color"),
            "kdfType": row.get("kdf_type"),
            "kdfIterations": row.get("kdf_iterations"),
            "cipherCount": count,
            "folderCount": f_count,
            "createdAt": row.get("created_at"),
            "updatedAt": row.get("updated_at"),
        }));
    }

    Ok(Json(json!({
        "data": users,
        "total": users.len(),
        "object": "list"
    })))
}

/// GET /api/wang/users/:id - 获取单个用户详情
#[worker::send]
pub async fn get_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    let row: Option<Value> = db
        .prepare("SELECT id, name, email, email_verified, avatar_color, master_password_hint, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, equivalent_domains, excluded_globals, created_at, updated_at FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let row = row.ok_or_else(|| AppError::NotFound("用户不存在".to_string()))?;

    let cipher_count: Option<Value> = db
        .prepare("SELECT COUNT(*) as cnt FROM ciphers WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let c_count = cipher_count
        .and_then(|v| v.get("cnt").and_then(|c| c.as_i64()))
        .unwrap_or(0);

    let folder_count: Option<Value> = db
        .prepare("SELECT COUNT(*) as cnt FROM folders WHERE user_id = ?1")
        .bind(&[user_id.into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let f_count = folder_count
        .and_then(|v| v.get("cnt").and_then(|c| c.as_i64()))
        .unwrap_or(0);

    Ok(Json(json!({
        "id": row.get("id"),
        "name": row.get("name"),
        "email": row.get("email"),
        "emailVerified": row.get("email_verified"),
        "avatarColor": row.get("avatar_color"),
        "masterPasswordHint": row.get("master_password_hint"),
        "kdfType": row.get("kdf_type"),
        "kdfIterations": row.get("kdf_iterations"),
        "kdfMemory": row.get("kdf_memory"),
        "kdfParallelism": row.get("kdf_parallelism"),
        "securityStamp": row.get("security_stamp"),
        "cipherCount": c_count,
        "folderCount": f_count,
        "createdAt": row.get("created_at"),
        "updatedAt": row.get("updated_at"),
        "object": "user"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

/// PUT /api/wang/users/:id - 更新用户信息（管理员）
#[worker::send]
pub async fn update_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    // 确认用户存在
    let exists: Option<Value> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    if exists.is_none() {
        return Err(AppError::NotFound("用户不存在".to_string()));
    }

    let now = Utc::now().to_rfc3339();

    // 逐字段更新
    if let Some(ref name) = payload.name {
        query!(
            &db,
            "UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3",
            name,
            now,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    if let Some(ref email) = payload.email {
        let new_email = email.to_lowercase();
        query!(
            &db,
            "UPDATE users SET email = ?1, updated_at = ?2 WHERE id = ?3",
            new_email,
            now,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                AppError::BadRequest("邮箱已被使用".to_string())
            } else {
                AppError::Database
            }
        })?;
    }

    if let Some(verified) = payload.email_verified {
        let v = if verified { 1 } else { 0 };
        query!(
            &db,
            "UPDATE users SET email_verified = ?1, updated_at = ?2 WHERE id = ?3",
            v,
            now,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(Json(json!({ "success": true })))
}

/// DELETE /api/wang/users/:id - 删除用户（管理员）
#[worker::send]
pub async fn delete_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    // 禁止删除自己
    if claims.sub == user_id {
        return Err(AppError::BadRequest(
            "不能删除自己的账户".to_string(),
        ));
    }

    // 确认用户存在
    let exists: Option<Value> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    if exists.is_none() {
        return Err(AppError::NotFound("用户不存在".to_string()));
    }

    // 级联删除用户数据（先删附件存储对象）
    if let Ok(keys) =
        crate::handlers::attachments::list_attachment_keys_for_user(&db, &user_id).await
    {
        if !keys.is_empty() {
            let _ = crate::handlers::attachments::delete_storage_objects(&env, &keys).await;
        }
    }

    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    query!(&db, "DELETE FROM users WHERE id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    Ok(Json(json!({ "success": true })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminResetPasswordRequest {
    pub new_password_hash: String,
    pub new_key: String,
}

/// POST /api/wang/users/:id/reset-password - 重置用户密码（管理员）
#[worker::send]
pub async fn reset_user_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(payload): Json<AdminResetPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    let exists: Option<Value> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    if exists.is_none() {
        return Err(AppError::NotFound("用户不存在".to_string()));
    }

    let new_salt = generate_salt()?;
    let password_iterations = server_password_iterations(&env) as i32;
    let new_hashed_password = hash_password_for_storage(
        &payload.new_password_hash,
        &new_salt,
        password_iterations as u32,
    )
    .await?;

    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, key = ?4, security_stamp = ?5, updated_at = ?6 WHERE id = ?7",
        new_hashed_password,
        new_salt,
        password_iterations,
        payload.new_key,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({ "success": true, "message": "密码已重置" })))
}

/// GET /api/wang/stats - 管理后台统计数据
#[worker::send]
pub async fn admin_stats(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    verify_admin(&env, &claims)?;

    let db = db::get_db(&env)?;

    // 总用户数
    let total_users: i64 = db
        .prepare("SELECT COUNT(*) as cnt FROM users")
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?
        .unwrap_or(0);

    // 总密码项数
    let total_ciphers: i64 = db
        .prepare("SELECT COUNT(*) as cnt FROM ciphers")
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?
        .unwrap_or(0);

    // 总文件夹数
    let total_folders: i64 = db
        .prepare("SELECT COUNT(*) as cnt FROM folders")
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?
        .unwrap_or(0);

    // 总 Send 数
    let total_sends: i64 = db
        .prepare("SELECT COUNT(*) as cnt FROM sends")
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?
        .unwrap_or(0);

    // 已启用 2FA 的用户数
    let tfa_users: i64 = db
        .prepare("SELECT COUNT(DISTINCT user_id) as cnt FROM two_factor_authenticator")
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?
        .unwrap_or(0);

    // 每用户统计
    let user_stats: Vec<Value> = db
        .prepare(
            "SELECT u.id, u.email, u.name,
                COALESCE(c.cnt, 0) as cipher_count,
                COALESCE(f.cnt, 0) as folder_count,
                COALESCE(s.cnt, 0) as send_count,
                COALESCE(c.data_bytes, 0) as cipher_bytes,
                COALESCE(s.data_bytes, 0) as send_bytes,
                LENGTH(u.email) + LENGTH(COALESCE(u.name, '')) + LENGTH(u.master_password_hash) + LENGTH(COALESCE(u.master_password_hint, '')) + LENGTH(u.key) + LENGTH(u.private_key) + LENGTH(u.public_key) as user_bytes,
                u.created_at
             FROM users u
             LEFT JOIN (SELECT user_id, COUNT(*) as cnt, COALESCE(SUM(LENGTH(data)), 0) as data_bytes FROM ciphers GROUP BY user_id) c ON u.id = c.user_id
             LEFT JOIN (SELECT user_id, COUNT(*) as cnt FROM folders GROUP BY user_id) f ON u.id = f.user_id
             LEFT JOIN (SELECT user_id, COUNT(*) as cnt, COALESCE(SUM(LENGTH(data)), 0) as data_bytes FROM sends GROUP BY user_id) s ON u.id = s.user_id
             ORDER BY cipher_bytes DESC",
        )
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    // 存储后端
    let storage_backend = if crate::handlers::attachments::attachments_enabled(&env) {
        match crate::handlers::attachments::get_storage_backend(&env) {
            Some(crate::handlers::attachments::StorageBackend::R2) => "R2",
            Some(crate::handlers::attachments::StorageBackend::KV) => "KV",
            None => "未配置",
        }
    } else {
        "未配置"
    };

    Ok(Json(json!({
        "totalUsers": total_users,
        "totalCiphers": total_ciphers,
        "totalFolders": total_folders,
        "totalSends": total_sends,
        "tfaUsers": tfa_users,
        "storageBackend": storage_backend,
        "userStats": user_stats,
    })))
}
