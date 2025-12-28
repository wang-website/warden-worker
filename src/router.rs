use axum::{
    routing::{get, post, put, delete},
    Router,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{accounts, ciphers, config, identity, sync, folders, import, health};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // Health check endpoints
        .route("/health", get(health::health))
        .route("/alive", get(health::alive))
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Account management
        .route("/api/accounts/password", post(accounts::change_password))
        .route("/api/accounts/delete", post(accounts::delete_account))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/revision-date", get(accounts::get_revision_date))
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // Ciphers CRUD
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", get(ciphers::get_cipher))
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        .route("/api/ciphers/{id}/delete", post(ciphers::delete_cipher))
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        .route("/api/ciphers/{id}/delete-admin", delete(ciphers::hard_delete_cipher))
        .route("/api/ciphers/{id}/favorite", put(ciphers::toggle_favorite))
        .route("/api/ciphers/{id}/move", post(ciphers::move_to_folder))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/config", get(config::config))
        .with_state(app_state)
}
