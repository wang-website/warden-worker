use axum::{extract::State, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::{query, Env};

use crate::{auth::Claims, db, error::AppError};

/// GET /api/settings/domains
#[worker::send]
pub async fn get_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let row: Option<Value> = db
        .prepare("SELECT equivalent_domains, excluded_globals FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let equivalent_domains = row
        .get("equivalent_domains")
        .and_then(|v| v.as_str())
        .unwrap_or("[]");
    let _excluded_globals = row
        .get("excluded_globals")
        .and_then(|v| v.as_str())
        .unwrap_or("[]");

    let equivalent_domains_parsed: Value =
        serde_json::from_str(equivalent_domains).unwrap_or(json!([]));

    Ok(Json(json!({
        "equivalentDomains": equivalent_domains_parsed,
        "globalEquivalentDomains": [],
        "object": "domains"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivDomainData {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

/// POST /api/settings/domains
#[worker::send]
pub async fn post_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let excluded_globals = payload
        .excluded_global_equivalent_domains
        .unwrap_or_default();
    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();

    let excluded_globals_json = serde_json::to_string(&excluded_globals)
        .map_err(|_| AppError::BadRequest("Invalid excluded globals".to_string()))?;
    let equivalent_domains_json = serde_json::to_string(&equivalent_domains)
        .map_err(|_| AppError::BadRequest("Invalid equivalent domains".to_string()))?;

    let now = Utc::now().to_rfc3339();
    query!(
        &db,
        "UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2, updated_at = ?3 WHERE id = ?4",
        equivalent_domains_json,
        excluded_globals_json,
        now,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

/// PUT /api/settings/domains
#[worker::send]
pub async fn put_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    payload: Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    post_domains(claims, State(env), payload).await
}
