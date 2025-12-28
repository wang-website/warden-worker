use chrono::Utc;

/// Get current timestamp in standard format
pub fn now_timestamp() -> String {
    let now = Utc::now();
    now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Format a chrono DateTime to standard timestamp string
pub fn format_timestamp(dt: chrono::DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
