-- Open onboarding + Telegram command sync support
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY,
  value TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_app_state_key ON app_state(key);

-- Migrate old pending operators to active for open onboarding UX.
UPDATE operators
SET status = 'active', updated_at = datetime('now')
WHERE status = 'pending';
