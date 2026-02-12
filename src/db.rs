use crate::error::AppError;
use std::sync::Arc;
use worker::{D1Database, D1PreparedStatement, Env};

pub fn get_db(env: &Arc<Env>) -> Result<D1Database, AppError> {
    env.d1("vault1").map_err(AppError::Worker)
}

/// Update the user's `updated_at` timestamp to trigger sync.
pub async fn touch_user_updated_at(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2")
        .bind(&[now.into(), user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

/// Map D1 JSON errors (e.g. SQLITE_TOOBIG) to our AppError.
pub fn map_d1_json_error(e: worker::Error) -> AppError {
    let msg = e.to_string();
    if msg.contains("SQLITE_TOOBIG") {
        log::warn!("D1 SQLITE_TOOBIG error: {}", msg);
    }
    AppError::Database
}

/// Execute a list of D1 statements in batches.
pub async fn execute_in_batches(
    db: &D1Database,
    statements: Vec<D1PreparedStatement>,
    batch_size: usize,
) -> Result<(), AppError> {
    if statements.is_empty() {
        return Ok(());
    }

    let effective_batch_size = if batch_size == 0 {
        statements.len()
    } else {
        batch_size
    };

    for chunk in statements.chunks(effective_batch_size) {
        db.batch(chunk.to_vec())
            .await
            .map_err(|_| AppError::Database)?;
    }

    Ok(())
}
