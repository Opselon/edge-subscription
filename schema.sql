PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY,
  telegram_user_id INTEGER NOT NULL UNIQUE,
  display_name TEXT,
  role TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('admin','operator')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','removed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS operator_settings (
  operator_id TEXT PRIMARY KEY,
  upstream_url TEXT,
  branding TEXT,
  active_domain_id TEXT,
  channel_id TEXT,
  preferences_json TEXT,
  notify_fetches INTEGER NOT NULL DEFAULT 1 CHECK (notify_fetches IN (0,1)),
  last_fetch_notify_at TEXT,
  last_upstream_status TEXT CHECK (last_upstream_status IN ('ok','invalid')),
  last_upstream_at TEXT,
  pending_action TEXT,
  pending_meta TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operator_domains (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0,1)),
  verification_token TEXT,
  is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,
  UNIQUE(operator_id, domain),
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS extra_configs (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  title TEXT,
  content TEXT NOT NULL,
  is_enabled INTEGER NOT NULL DEFAULT 1 CHECK (is_enabled IN (0,1)),
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subscription_rules (
  operator_id TEXT PRIMARY KEY,
  merge_policy TEXT NOT NULL DEFAULT 'append' CHECK (merge_policy IN ('append','append_dedupe','replace','upstream_only','extras_only')),
  dedupe INTEGER NOT NULL DEFAULT 1 CHECK (dedupe IN (0,1)),
  sanitize INTEGER NOT NULL DEFAULT 1 CHECK (sanitize IN (0,1)),
  naming_prefix TEXT,
  naming_mode TEXT NOT NULL DEFAULT 'keep' CHECK (naming_mode IN ('keep','prefix','rewrite')),
  blocked_keywords TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS share_links (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  public_token TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS last_known_good (
  operator_id TEXT NOT NULL,
  public_token TEXT NOT NULL,
  body_b64 TEXT NOT NULL,
  body_format TEXT NOT NULL DEFAULT 'base64_text',
  headers_json TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (operator_id, public_token),
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  operator_id TEXT,
  event_type TEXT NOT NULL,
  ip TEXT,
  country TEXT,
  user_agent TEXT,
  request_path TEXT,
  response_status INTEGER,
  meta_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_operators_telegram ON operators(telegram_user_id);
CREATE INDEX IF NOT EXISTS idx_operators_role ON operators(role);
CREATE INDEX IF NOT EXISTS idx_domains_operator ON operator_domains(operator_id, is_active);
CREATE INDEX IF NOT EXISTS idx_extra_configs_operator ON extra_configs(operator_id, is_enabled, sort_order);
CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links(public_token);
CREATE INDEX IF NOT EXISTS idx_last_known_good_operator ON last_known_good(operator_id, public_token);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operator_time ON audit_logs(operator_id, created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);

COMMIT;
