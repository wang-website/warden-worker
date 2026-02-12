pub mod accounts;
pub mod admin;
pub mod attachments;
pub mod ciphers;
pub mod config;
pub mod devices;
pub mod domains;
pub mod emergency_access;
pub mod folders;
pub mod identity;
pub mod import;
pub mod meta;
pub mod migrate;
pub mod purge;
pub mod sends;
pub mod sync;
pub mod two_factor;
pub mod usage;
pub mod webauth;

/// Shared helper for reading an environment variable into usize.
pub(crate) fn get_env_usize(env: &worker::Env, var_name: &str, default: usize) -> usize {
    env.var(var_name)
        .ok()
        .and_then(|value| value.to_string().parse::<usize>().ok())
        .unwrap_or(default)
}

/// Convenience helper for cipher batch size using IMPORT_BATCH_SIZE.
pub(crate) fn get_batch_size(env: &worker::Env) -> usize {
    get_env_usize(env, "IMPORT_BATCH_SIZE", 30)
}

/// Per-user server-side PBKDF2 iterations (PASSWORD_ITERATIONS).
pub(crate) fn server_password_iterations(env: &worker::Env) -> u32 {
    let min = crate::crypto::MIN_SERVER_PBKDF2_ITERATIONS;

    match env.var("PASSWORD_ITERATIONS") {
        Ok(v) => {
            let raw = v.to_string();
            match raw.parse::<u32>() {
                Ok(iter) if iter >= min => iter,
                Ok(iter) => {
                    log::warn!(
                        "PASSWORD_ITERATIONS={} is below the minimum {}; clamping to {}",
                        iter, min, min
                    );
                    min
                }
                Err(err) => {
                    log::warn!(
                        "Invalid PASSWORD_ITERATIONS='{}' ({}); using minimum {}",
                        raw, err, min
                    );
                    min
                }
            }
        }
        Err(_) => min,
    }
}

/// Whether TOTP validation should allow ±1 time step drift.
pub(crate) fn allow_totp_drift(env: &worker::Env) -> bool {
    env.var("AUTHENTICATOR_DISABLE_TIME_DRIFT")
        .ok()
        .map(|value| value.to_string().to_lowercase())
        .map(|value| !matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Whether the user has 2FA enabled.
pub(crate) async fn two_factor_enabled(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<bool, crate::error::AppError> {
    crate::two_factor::is_authenticator_enabled(db, user_id).await
}

/// 管理员权限验证（共享函数）。
///
/// 检查当前登录用户的邮箱是否在 `ADMIN_EMAILS` 环境变量配置的管理员列表中。
/// 支持逗号分隔的多个邮箱，不区分大小写。
/// 为保持向后兼容，也读取旧的 `ADMIN_EMAIL` 变量。
///
/// # 环境变量
/// - `ADMIN_EMAILS`：管理员邮箱列表，逗号分隔（推荐）
/// - `ADMIN_EMAIL`：单个管理员邮箱（向后兼容，若 ADMIN_EMAILS 未设置则使用此值）
pub(crate) fn verify_admin(
    env: &worker::Env,
    claims: &crate::auth::Claims,
) -> Result<(), crate::error::AppError> {
    let admin_emails_str = env
        .var("ADMIN_EMAILS")
        .ok()
        .map(|v| v.to_string())
        .or_else(|| env.var("ADMIN_EMAIL").ok().map(|v| v.to_string()))
        .unwrap_or_default();

    if admin_emails_str.trim().is_empty() {
        return Err(crate::error::AppError::Unauthorized(
            "管理员功能未启用：请在环境变量中设置 ADMIN_EMAILS".to_string(),
        ));
    }

    let is_admin = admin_emails_str
        .split(',')
        .any(|email| email.trim().eq_ignore_ascii_case(&claims.email));

    if !is_admin {
        return Err(crate::error::AppError::Unauthorized(
            "需要管理员权限".to_string(),
        ));
    }

    Ok(())
}
