CREATE TABLE IF NOT EXISTS app_json_store (
    chave TEXT PRIMARY KEY NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_app_json_store_updated_at
ON app_json_store (updated_at);

