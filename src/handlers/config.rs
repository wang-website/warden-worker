use axum::{extract::State, Extension, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::BaseUrl;

/// Get the disable_user_registration setting from environment variable.
fn get_disable_user_registration(env: &Env) -> bool {
    env.var("DISABLE_USER_REGISTRATION")
        .ok()
        .map(|v| v.to_string().to_lowercase() != "false")
        .unwrap_or(true)
}

#[worker::send]
pub async fn config(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(domain)): Extension<BaseUrl>,
) -> Json<Value> {
    let disable_user_registration = get_disable_user_registration(&env);

    Json(json!({
        "version": "2025.12.0",
        "gitHash": "5d84f176",
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": disable_user_registration,
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!(""),
          "sso": format!(""),
          "cloudRegion": null,
        },
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": {},
        "object": "config",
    }))
}
