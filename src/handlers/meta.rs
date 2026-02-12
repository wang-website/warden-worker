use axum::{extract::State, Json};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{db, error::AppError};

/// GET /api/now
#[worker::send]
pub async fn now() -> Json<String> {
    Json(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// GET /api/alive
#[worker::send]
pub async fn alive(State(env): State<Arc<Env>>) -> Result<Json<String>, AppError> {
    let db = db::get_db(&env)?;
    db.prepare("SELECT 1 as ok")
        .first::<i32>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(now().await)
}

/// GET /api/version
#[worker::send]
pub async fn version() -> Json<&'static str> {
    Json("2025.12.0")
}

#[derive(Debug, Deserialize)]
pub struct HibpBreachQuery {
    #[allow(dead_code)]
    pub username: String,
}

/// GET /api/hibp/breach?username=...
#[worker::send]
pub async fn hibp_breach(_query: axum::extract::Query<HibpBreachQuery>) -> Json<Value> {
    Json(json!([]))
}
