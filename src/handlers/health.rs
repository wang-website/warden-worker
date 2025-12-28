use axum::Json;
use serde_json::{json, Value};

/// Health check endpoint
#[worker::send]
pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "warden-worker",
        "version": "0.1.0"
    }))
}

/// Alive check endpoint (for monitoring)
#[worker::send]
pub async fn alive() -> &'static str {
    "OK"
}
