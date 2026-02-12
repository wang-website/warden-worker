use axum::Json;
use serde_json::{json, Value};

/// GET /emergency-access/trusted
#[worker::send]
pub async fn get_trusted_contacts() -> Json<Value> {
    Json(json!({
        "data": [],
        "object": "list",
        "continuationToken": null
    }))
}

/// GET /emergency-access/granted
#[worker::send]
pub async fn get_granted_access() -> Json<Value> {
    Json(json!({
        "data": [],
        "object": "list",
        "continuationToken": null
    }))
}
