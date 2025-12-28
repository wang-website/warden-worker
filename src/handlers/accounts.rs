use axum::{extract::State, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::user::{PreloginResponse, RegisterRequest, User},
};

// Email validation helper - more thorough validation
fn is_valid_email(email: &str) -> bool {
    // Basic checks
    if email.len() < 3 || email.len() > 254 {
        return false;
    }
    
    // Must contain exactly one @ symbol
    let at_count = email.matches('@').count();
    if at_count != 1 {
        return false;
    }
    
    // Split into local and domain parts
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let local = parts[0];
    let domain = parts[1];
    
    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    
    // Validate domain part
    if domain.is_empty() || domain.len() < 3 {
        return false;
    }
    
    // Domain must contain at least one dot
    if !domain.contains('.') {
        return false;
    }
    
    // Basic character validation
    let valid_chars = |c: char| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+';
    if !local.chars().all(valid_chars) {
        return false;
    }
    
    let domain_valid_chars = |c: char| c.is_alphanumeric() || c == '.' || c == '-';
    if !domain.chars().all(domain_valid_chars) {
        return false;
    }
    
    // Domain can't start or end with dot or dash
    if domain.starts_with('.') || domain.ends_with('.') 
        || domain.starts_with('-') || domain.ends_with('-') {
        return false;
    }
    
    true
}

// Validate KDF iterations are within reasonable bounds
fn is_valid_kdf_iterations(iterations: i32) -> bool {
    iterations >= 100_000 && iterations <= 2_000_000
}

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&env)?;

    let stmt = db.prepare("SELECT kdf_iterations FROM users WHERE email = ?1");
    let query = stmt.bind(&[email.into()])?;
    let kdf_iterations: Option<i32> = query
        .first(Some("kdf_iterations"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(PreloginResponse {
        kdf: 0, // PBKDF2
        kdf_iterations: kdf_iterations.unwrap_or(600_000),
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    // Validate email format
    if !is_valid_email(&payload.email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Validate KDF iterations
    if !is_valid_kdf_iterations(payload.kdf_iterations) {
        return Err(AppError::BadRequest("KDF iterations must be between 100,000 and 2,000,000".to_string()));
    }

    // Validate KDF type (only PBKDF2 supported)
    if payload.kdf != 0 {
        return Err(AppError::BadRequest("Only PBKDF2 (kdf=0) is supported".to_string()));
    }

    // Check password hash is not empty
    if payload.master_password_hash.is_empty() {
        return Err(AppError::BadRequest("Master password hash cannot be empty".to_string()));
    }

    // Check keys are not empty
    if payload.user_symmetric_key.is_empty() 
        || payload.user_asymmetric_keys.encrypted_private_key.is_empty()
        || payload.user_asymmetric_keys.public_key.is_empty() {
        return Err(AppError::BadRequest("Encryption keys cannot be empty".to_string()));
    }

    let allowed_emails = env
        .secret("ALLOWED_EMAILS")
        .map_err(|_| AppError::Internal)?;
    let allowed_emails = allowed_emails
        .as_ref()
        .as_string()
        .ok_or_else(|| AppError::Internal)?;
    if allowed_emails
        .split(",")
        .all(|email| email.trim() != payload.email)
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        email: payload.email.to_lowercase(),
        email_verified: false,
        master_password_hash: payload.master_password_hash,
        master_password_hint: payload.master_password_hint,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        security_stamp: Uuid::new_v4().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, key, private_key, public_key, kdf_iterations, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
         user.id,
         user.name,
         user.email,
         user.master_password_hash,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_iterations,
         user.security_stamp,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn send_verification_email() -> String {
    "fixed-token-to-mock".to_string()
}

/// Get user profile
#[worker::send]
pub async fn get_profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let profile = json!({
        "Id": user.id,
        "Name": user.name,
        "Email": user.email,
        "EmailVerified": user.email_verified,
        "Premium": true,
        "MasterPasswordHint": user.master_password_hint,
        "Culture": "en-US",
        "TwoFactorEnabled": false,
        "Key": user.key,
        "PrivateKey": user.private_key,
        "SecurityStamp": user.security_stamp,
        "Organizations": [],
        "Object": "profile"
    });

    Ok(Json(profile))
}

/// Get revision date (for checking if sync is needed)
#[worker::send]
pub async fn get_revision_date(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    
    // Get the most recent update time from user, ciphers, or folders
    let user: User = db
        .prepare("SELECT updated_at FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let mut latest_date = user.updated_at.clone();

    // Check ciphers
    if let Ok(Some(cipher_date)) = db
        .prepare("SELECT updated_at FROM ciphers WHERE user_id = ?1 ORDER BY updated_at DESC LIMIT 1")
        .bind(&[claims.sub.clone().into()])?
        .first::<String>(Some("updated_at"))
        .await 
    {
        if cipher_date > latest_date {
            latest_date = cipher_date;
        }
    }

    // Check folders
    if let Ok(Some(folder_date)) = db
        .prepare("SELECT updated_at FROM folders WHERE user_id = ?1 ORDER BY updated_at DESC LIMIT 1")
        .bind(&[claims.sub.clone().into()])?
        .first::<String>(Some("updated_at"))
        .await 
    {
        if folder_date > latest_date {
            latest_date = folder_date;
        }
    }

    Ok(Json(json!(latest_date)))
}

/// Change password endpoint
#[derive(serde::Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "masterPasswordHash")]
    pub master_password_hash: String,
    #[serde(rename = "newMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(rename = "key")]
    pub key: String,
}

#[worker::send]
pub async fn change_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, AppError> {
    // Validate new password hash is not empty
    if payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest("New password hash cannot be empty".to_string()));
    }

    // Validate key is not empty
    if payload.key.is_empty() {
        return Err(AppError::BadRequest("Encryption key cannot be empty".to_string()));
    }

    let db = db::get_db(&env)?;
    
    // Verify current password
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Verify old password hash
    use constant_time_eq::constant_time_eq;
    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let new_security_stamp = Uuid::new_v4().to_string();

    // Update password and keys
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, key = ?2, security_stamp = ?3, updated_at = ?4 WHERE id = ?5",
        payload.new_master_password_hash,
        payload.key,
        new_security_stamp,
        now,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}

/// Delete account endpoint
#[derive(serde::Deserialize)]
pub struct DeleteAccountRequest {
    #[serde(rename = "masterPasswordHash")]
    pub master_password_hash: String,
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DeleteAccountRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    
    // Verify password before deleting
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    use constant_time_eq::constant_time_eq;
    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Delete user (CASCADE will delete ciphers and folders)
    query!(
        &db,
        "DELETE FROM users WHERE id = ?1",
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}
