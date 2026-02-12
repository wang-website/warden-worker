-- 附件（attachments）表：存储文件附件元数据
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);

-- 待上传附件（attachments_pending）表：追踪正在上传的附件
CREATE TABLE IF NOT EXISTS attachments_pending (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachments_pending_cipher ON attachments_pending(cipher_id);
CREATE INDEX IF NOT EXISTS idx_attachments_pending_created_at ON attachments_pending(created_at);
