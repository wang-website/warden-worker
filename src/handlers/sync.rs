use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    handlers::two_factor_enabled,
    models::{
        cipher::{Cipher, CipherDBModel},
        folder::{Folder, FolderResponse},
        sync::Profile,
        user::User,
    },
};

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let two_factor_enabled = two_factor_enabled(&db, &user_id).await?;

    let has_master_password = !user.master_password_hash.is_empty();

    let master_password_unlock = if has_master_password {
        json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": user.kdf_memory,
                "parallelism": user.kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user.key,
            "masterKeyWrappedUserKey": user.key,
            "salt": user.email
        })
    } else {
        Value::Null
    };

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch ciphers
    let ciphers: Vec<Value> = db
        .prepare("SELECT * FROM ciphers WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let ciphers = ciphers
        .into_iter()
        .filter_map(
            |cipher| match serde_json::from_value::<CipherDBModel>(cipher.clone()) {
                Ok(cipher) => Some(cipher),
                Err(err) => {
                    log::warn!("Cannot parse {err:?} {cipher:?}");
                    None
                }
            },
        )
        .map(|cipher| cipher.into())
        .collect::<Vec<Cipher>>();

    let mut profile = Profile::from_user(user, two_factor_enabled)?;
    profile.status = if has_master_password { 0 } else { 1 };

    let equivalent_domains: Value = json!([]);

    let response = json!({
        "profile": profile,
        "folders": folders,
        "collections": [],
        "policies": [],
        "ciphers": ciphers,
        "domains": {
            "equivalentDomains": equivalent_domains,
            "globalEquivalentDomains": [],
            "object": "domains"
        },
        "sends": [],
        "userDecryption": {
            "masterPasswordUnlock": master_password_unlock
        },
        "object": "sync"
    });

    Ok(Json(response))
}
