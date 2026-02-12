use crate::error::AppError;
use std::sync::Arc;
use worker::{D1Database, D1PreparedStatement, Env};

pub fn get_db(env: &Arc<Env>) -> Result<D1Database, AppError> {
    env.d1("vault1").map_err(AppError::Worker)
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
