use axum::Json;
use serde_json::{json, Value};

/// GET /api/webauthn
#[worker::send]
pub async fn get_webauthn_credentials() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}

/// POST /api/webauthn
#[worker::send]
pub async fn post_webauthn_credentials() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}

/// PUT /api/webauthn
#[worker::send]
pub async fn put_webauthn_credentials() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}

/// POST /api/webauthn/attestation-options
#[worker::send]
pub async fn post_attestation_options() -> Json<Value> {
    Json(json!({}))
}

/// POST /api/webauthn/assertion-options
#[worker::send]
pub async fn post_assertion_options() -> Json<Value> {
    Json(json!({}))
}

/// GET /api/accounts/webauthn/assertion-options
#[worker::send]
pub async fn get_assertion_options() -> Json<Value> {
    Json(json!({}))
}

/// POST /api/two-factor/get-webauthn
#[worker::send]
pub async fn get_webauthn_two_factor() -> Json<Value> {
    Json(json!({
        "enabled": false,
        "keys": [],
        "object": "twoFactorWebAuthn"
    }))
}

/// POST /api/two-factor/get-webauthn-challenge
#[worker::send]
pub async fn get_webauthn_challenge() -> Json<Value> {
    Json(json!({}))
}

/// PUT /api/two-factor/webauthn
#[worker::send]
pub async fn put_webauthn_two_factor() -> Json<Value> {
    Json(json!({
        "enabled": false,
        "keys": [],
        "object": "twoFactorWebAuthn"
    }))
}

/// DELETE /api/two-factor/webauthn
#[worker::send]
pub async fn delete_webauthn_two_factor() -> Json<Value> {
    Json(json!({
        "enabled": false,
        "keys": [],
        "object": "twoFactorWebAuthn"
    }))
}
