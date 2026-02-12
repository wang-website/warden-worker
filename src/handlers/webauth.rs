use axum::Json;
use serde_json::{json, Value};

/// GET /webauthn
#[worker::send]
pub async fn get_webauthn_credentials() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}
