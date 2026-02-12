-- Add new columns needed by enhanced features
-- These columns may already exist if using schema_full.sql, so we use ALTER TABLE with IF NOT EXISTS pattern

-- Add password_salt for server-side PBKDF2 hashing
ALTER TABLE users ADD COLUMN password_salt TEXT;

-- Add password_iterations for server-side PBKDF2 iterations
ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 0;

-- Add avatar_color for user profile
ALTER TABLE users ADD COLUMN avatar_color TEXT;

-- Add kdf_memory for Argon2id support
ALTER TABLE users ADD COLUMN kdf_memory INTEGER;

-- Add kdf_parallelism for Argon2id support
ALTER TABLE users ADD COLUMN kdf_parallelism INTEGER;

-- Add equivalent_domains for domain settings
ALTER TABLE users ADD COLUMN equivalent_domains TEXT NOT NULL DEFAULT '[]';

-- Add excluded_globals for domain settings
ALTER TABLE users ADD COLUMN excluded_globals TEXT NOT NULL DEFAULT '[]';

-- Add totp_recover for 2FA recovery code
ALTER TABLE users ADD COLUMN totp_recover TEXT;
