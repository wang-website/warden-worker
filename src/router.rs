use axum::{
    routing::{delete, get, post, put},
    Router,
    response::Html,
};
use axum::extract::DefaultBodyLimit;
use std::sync::Arc;
use worker::Env;

use crate::handlers::{
    accounts, admin, ciphers, config, devices, domains, emergency_access, folders, identity,
    import, meta, migrate, sends, two_factor, usage, webauth,
};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // /wang 管理界面
        .route("/wang", get(|| async { Html(include_str!("../static/wang/index.html")) }))
        .route("/wang/", get(|| async { Html(include_str!("../static/wang/index.html")) }))
        .route("/wang/demo", get(|| async { Html(include_str!("../static/wang/demo.html")) }))
        .route("/wang/demo.html", get(|| async { Html(include_str!("../static/wang/demo.html")) }))
        // 保留旧的 demo.html 路径的兼容性
        .route("/demo.html", get(|| async { Html(include_str!("../static/wang/demo.html")) }))
        // 管理 API - 用户增删改查
        .route("/api/wang/users", get(admin::list_users))
        .route("/api/wang/users/{id}", get(admin::get_user).put(admin::update_user).delete(admin::delete_user))
        .route("/api/wang/users/{id}/reset-password", post(admin::reset_user_password))
        // 管理 API - 数据迁移
        .route("/api/wang/migrate", post(migrate::migrate_from_vaultwarden)
            .layer(DefaultBodyLimit::max(50 * 1024 * 1024)))
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route("/api/accounts/prelogin", post(accounts::prelogin))
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Main data sync route
        .route("/api/sync", get(crate::handlers::sync::get_sync_data))
        // Account management
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/password-hint", post(accounts::password_hint))
        .route("/api/accounts/tasks", get(accounts::get_tasks))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/profile", post(accounts::post_profile))
        .route("/api/accounts/profile", put(accounts::put_profile))
        .route("/api/accounts/avatar", put(accounts::put_avatar))
        // Delete account
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        // Set KDF
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        // Change password
        .route("/api/accounts/password", post(accounts::post_password))
        .route("/api/accounts/password", put(accounts::post_password))
        // Rotate encryption keys
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey),
        )
        // Auth requests (login with device) - stub
        .route("/api/auth-requests", get(accounts::get_auth_requests))
        .route(
            "/api/auth-requests/pending",
            get(accounts::get_auth_requests_pending),
        )
        // Device management
        .route("/api/devices/knowndevice", get(devices::knowndevice))
        .route(
            "/api/devices/identifier/{id}/token",
            put(devices::device_token).post(devices::device_token),
        )
        // Two-factor authentication
        .route("/api/two-factor", get(two_factor::two_factor_status))
        .route("/api/two-factor/get-authenticator", post(two_factor::get_authenticator))
        .route(
            "/api/two-factor/authenticator",
            post(two_factor::activate_authenticator)
                .put(two_factor::activate_authenticator_put)
                .delete(two_factor::disable_authenticator_vw),
        )
        .route("/api/two-factor/authenticator/request", post(two_factor::authenticator_request))
        .route("/api/two-factor/authenticator/enable", post(two_factor::authenticator_enable))
        .route("/api/two-factor/authenticator/disable", post(two_factor::authenticator_disable))
        // Sends
        .route("/api/sends", get(sends::get_sends).post(sends::post_send))
        .route("/api/sends/file/v2", post(sends::post_send_file_v2))
        .route("/api/sends/access/{access_id}", post(sends::post_access))
        .route(
            "/api/sends/{send_id}",
            get(sends::get_send).delete(sends::delete_send),
        )
        .route(
            "/api/sends/{send_id}/access/file/{file_id}",
            post(sends::post_access_file),
        )
        .route("/api/sends/{send_id}/{file_id}", get(sends::download_send))
        .route(
            "/api/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route(
            "/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        // Ciphers CRUD
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route(
            "/api/ciphers",
            post(ciphers::post_ciphers).delete(ciphers::hard_delete_ciphers_delete),
        )
        .route("/api/ciphers/import", post(import::import_data))
        .route(
            "/api/ciphers/{id}",
            put(ciphers::update_cipher).delete(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/delete",
            put(ciphers::soft_delete_cipher).post(ciphers::hard_delete_cipher_post),
        )
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers).post(ciphers::hard_delete_ciphers),
        )
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers))
        // Purge vault
        .route("/api/ciphers/purge", post(ciphers::purge_vault))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        // Config & Meta endpoints
        .route("/api/config", get(config::config))
        .route("/api/alive", get(meta::alive))
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        // Settings
        .route("/api/settings/domains", get(domains::get_domains))
        .route("/api/settings/domains", post(domains::post_domains))
        .route("/api/settings/domains", put(domains::put_domains))
        // Emergency access (stub)
        .route(
            "/api/emergency-access/trusted",
            get(emergency_access::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency_access::get_granted_access),
        )
        // WebAuthn (stub)
        .route("/api/webauthn", get(webauth::get_webauthn_credentials))
        // D1 Usage
        .route("/api/d1/usage", get(usage::d1_usage))
        .with_state(app_state)
}
