PRAGMA foreign_keys = ON;

ALTER TABLE subscription_rules ADD COLUMN sub_links_policy TEXT NOT NULL DEFAULT 'append' CHECK (sub_links_policy IN ('append','upstream_only','subs_only','round_robin','weighted'));

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  label TEXT,
  public_token TEXT UNIQUE NOT NULL,
  panel_token_enc TEXT,
  upstream_override_enc TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  overrides_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subscription_links (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  title TEXT,
  url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  headers_json TEXT,
  priority INTEGER NOT NULL DEFAULT 0,
  weight INTEGER NOT NULL DEFAULT 1,
  scope TEXT NOT NULL DEFAULT 'operator' CHECK (scope IN ('operator','customer')),
  customer_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,
  FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_customers_operator ON customers(operator_id, enabled, created_at);
CREATE INDEX IF NOT EXISTS idx_customers_public_token ON customers(public_token);
CREATE INDEX IF NOT EXISTS idx_subscription_links_operator ON subscription_links(operator_id, enabled, priority);
CREATE INDEX IF NOT EXISTS idx_subscription_links_customer ON subscription_links(customer_id, enabled);
