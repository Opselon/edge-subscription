/**
 * Cloudflare Worker: Operator Subscription Manager
 * Required env vars:
 * TELEGRAM_TOKEN, TELEGRAM_SECRET(optional), ADMIN_IDS, SESSION_SECRET
 * Optional: TELEGRAM_BOT_USERNAME, LOG_CHANNEL_ID, BASE_URL
 */

const APP = {
  name: "Operator Subscription Manager",
  version: "3.0.0",
  cacheTtlMs: 60_000,
  cacheMaxEntries: 1000,
  rateLimitWindowMs: 10_000,
  rateLimitMax: 20,
  maxWebhookBytes: 256 * 1024,
  maxRedirectTargetBytes: 2048,
  maxLineBytes: 10 * 1024,
  maxOutputBytes: 2 * 1024 * 1024,
  maxOutputLines: 5000,
  notifyFetchIntervalMs: 5 * 60 * 1000,
  upstreamTimeoutMs: 8000,
  maxRedirects: 2,
  sessionTtlSec: 60 * 60 * 24,
};

// =============================
// Types & Constants
// =============================
const GLASS = "🧊";
const GLASS_BTN = (label) => `${GLASS} ${label}`;
const SAFE_REDIRECT_SCHEMES = ["v2rayng", "sn", "streisand", "v2box", "https"];
const ALLOWED_CONFIG_SCHEMES = [
  "vmess://",
  "vless://",
  "trojan://",
  "ss://",
  "ssr://",
  "hysteria://",
  "hy2://",
  "tuic://",
  "wireguard://",
];
const DEFAULT_HEADERS = {
  "content-type": "text/plain; charset=utf-8",
  "cache-control": "no-store",
};
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

const SUB_CACHE = new Map();
const LAST_GOOD_MEM = new Map();
const RATE_LIMIT = new Map();

const Logger = {
  info: (msg, data = {}) => console.log(JSON.stringify({ level: "INFO", msg, ...data, ts: new Date().toISOString() })),
  warn: (msg, data = {}) => console.warn(JSON.stringify({ level: "WARN", msg, ...data, ts: new Date().toISOString() })),
  error: (msg, err, data = {}) =>
    console.error(
      JSON.stringify({ level: "ERROR", msg, error: err?.message || String(err), ...data, ts: new Date().toISOString() })
    ),
};

// =============================
// Utilities (encoding, validation, safe HTML)
// =============================
const utf8SafeEncode = (str) => {
  try {
    return btoa(new TextEncoder().encode(str).reduce((data, byte) => data + String.fromCharCode(byte), ""));
  } catch {
    return btoa(unescape(encodeURIComponent(str)));
  }
};

const utf8SafeDecode = (b64) => {
  try {
    const clean = b64.replace(/[\n\r\s]/g, "");
    return new TextDecoder().decode(Uint8Array.from(atob(clean), (c) => c.charCodeAt(0)));
  } catch {
    return decodeURIComponent(escape(atob(b64)));
  }
};

const safeHtml = (text) =>
  String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");

const nowIso = () => new Date().toISOString();

const parseCommaList = (value) =>
  String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const isAdmin = (userId, env) => {
  const allow = new Set(parseCommaList(env.ADMIN_IDS));
  return allow.has(String(userId));
};

const rateLimit = (key) => {
  const now = Date.now();
  const entry = RATE_LIMIT.get(key) || { count: 0, ts: now };
  if (now - entry.ts > APP.rateLimitWindowMs) {
    RATE_LIMIT.set(key, { count: 1, ts: now });
    return true;
  }
  entry.count += 1;
  RATE_LIMIT.set(key, entry);
  return entry.count <= APP.rateLimitMax;
};

const getBaseUrl = (request, env) => {
  if (env.BASE_URL) return env.BASE_URL.replace(/\/$/, "");
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
};

const isValidDomain = (value) => {
  if (!/^[a-z0-9.-]+$/i.test(value)) return false;
  if (!/\.[a-z]{2,}$/i.test(value)) return false;
  if (value.includes("xn--")) return false;
  return true;
};

const getCachedSub = (key) => {
  const entry = SUB_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > APP.cacheTtlMs) {
    SUB_CACHE.delete(key);
    return null;
  }
  return entry;
};

const setCachedSub = (key, body, headers) => {
  if (SUB_CACHE.size > APP.cacheMaxEntries) SUB_CACHE.clear();
  SUB_CACHE.set(key, { body, headers, timestamp: Date.now() });
};

const setLastGoodMem = (key, body, headers) => {
  if (LAST_GOOD_MEM.size > APP.cacheMaxEntries) LAST_GOOD_MEM.clear();
  LAST_GOOD_MEM.set(key, { body, headers, timestamp: Date.now() });
};

const getLastGoodMem = (key) => LAST_GOOD_MEM.get(key);

const parseMessageText = (message) => message?.text?.trim() || "";

const decodeCallbackData = (data) => {
  try {
    return JSON.parse(utf8SafeDecode(data));
  } catch {
    return { action: data };
  }
};

const parseRulesArgs = (text) => {
  const args = text.split(" ").slice(1);
  const patch = {};
  for (const arg of args) {
    const [key, ...rest] = arg.split("=");
    const value = rest.join("=");
    if (!key || value === undefined) continue;
    if (key === "merge") patch.merge_policy = value;
    if (key === "dedupe") patch.dedupe = value === "1" ? 1 : 0;
    if (key === "sanitize") patch.sanitize = value === "1" ? 1 : 0;
    if (key === "prefix") {
      patch.naming_prefix = value;
      patch.naming_mode = value ? "prefix" : "keep";
    }
    if (key === "keywords") patch.blocked_keywords = value;
    if (key === "format") patch.output_format = value;
  }
  return patch;
};

const looksLikeBase64 = (value) => /^[A-Za-z0-9+/=\n\r]+$/.test(value.trim());

const isValidSubscriptionText = (text) => {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (/error|not\s+found|invalid/i.test(trimmed)) return false;
  return /:\/\//.test(trimmed);
};

const redactUrlForLog = (url) => {
  try {
    const parsed = new URL(url);
    const sensitive = ["token", "key", "pass", "auth", "jwt"];
    for (const key of sensitive) {
      if (parsed.searchParams.has(key)) parsed.searchParams.set(key, "***");
    }
    return parsed.toString();
  } catch {
    return url;
  }
};

const stableDedupe = (items) => {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
};

const sanitizeLines = (lines, blockedKeywords = []) => {
  const blockedSet = blockedKeywords.map((item) => item.toLowerCase());
  return lines.filter((line) => {
    if (!line) return false;
    if (line.startsWith("#")) return false;
    if (line.length > APP.maxLineBytes) return false;
    if (!ALLOWED_CONFIG_SCHEMES.some((scheme) => line.startsWith(scheme))) return false;
    const lower = line.toLowerCase();
    if (blockedSet.some((kw) => kw && lower.includes(kw))) return false;
    return true;
  });
};

const limitOutput = (lines, maxLines = APP.maxOutputLines, maxBytes = APP.maxOutputBytes) => {
  const encoder = new TextEncoder();
  const limited = [];
  let bytes = 0;
  for (const line of lines) {
    if (limited.length >= maxLines) break;
    const lineBytes = encoder.encode(line + "\n").length;
    if (bytes + lineBytes > maxBytes) break;
    bytes += lineBytes;
    limited.push(line);
  }
  return limited;
};

const hasCRLF = (value) => /\r|\n/.test(value);

const isPrivateIp = (host) => {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    if (host === "127.0.0.1" || host === "0.0.0.0") return true;
    if (host.startsWith("10.")) return true;
    if (host.startsWith("192.168.")) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
    if (host.startsWith("169.254.")) return true;
  }
  if (host === "localhost" || host === "::1") return true;
  return false;
};

const isBlockedHost = (hostname) => {
  const lower = hostname.toLowerCase();
  if (["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "::1"].includes(lower)) return true;
  if (/^10\./.test(lower)) return true;
  if (/^192\.168\./.test(lower)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(lower)) return true;
  if (/^169\.254\./.test(lower)) return true;
  return false;
};

const parseAddExtra = (text) => {
  const raw = text.replace("/add_extra", "").trim();
  if (!raw) return { title: null, content: null };
  if (raw.includes("|")) {
    const [title, ...rest] = raw.split("|");
    const content = rest.join("|").trim();
    return { title: title.trim(), content };
  }
  return { title: "افزودنی", content: raw };
};

const jsonResponse = (payload, status = 200, headers = {}) =>
  new Response(JSON.stringify(payload), { status, headers: { ...JSON_HEADERS, ...headers } });

const parseJsonBody = async (request) => {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const safeParseJson = (value, fallback = {}) => {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
};

const base64UrlEncode = (data) =>
  btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const base64UrlDecode = (data) => {
  const padded = data.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? padded : padded + "=".repeat(4 - (padded.length % 4));
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
};

const signSession = async (payload, secret) => {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${base64UrlEncode(signature)}`;
};

const verifySession = async (token, secret) => {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("HMAC", key, base64UrlDecode(signature), new TextEncoder().encode(data));
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedPayload)));
  } catch {
    return null;
  }
};

const hashApiKey = async (value) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

const validateTelegramLogin = async (data, botToken) => {
  if (!data || !data.hash) return false;
  const secret = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(botToken));
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const checkString = Object.keys(data)
    .filter((key) => key !== "hash")
    .sort()
    .map((key) => `${key}=${data[key]}`)
    .join("\n");
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(checkString));
  const hash = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hash === data.hash;
};

const assertSafeUpstream = (url, allowlist = [], denylist = []) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: "invalid_url" };
  }
  if (parsed.protocol !== "https:") return { ok: false, error: "https_only" };
  if (isPrivateIp(parsed.hostname) || isBlockedHost(parsed.hostname)) return { ok: false, error: "blocked_host" };
  const host = parsed.hostname.toLowerCase();
  if (denylist.length && denylist.some((item) => host.includes(item.toLowerCase()))) return { ok: false, error: "denylisted" };
  if (allowlist.length && !allowlist.some((item) => host.includes(item.toLowerCase()))) return { ok: false, error: "not_allowlisted" };
  return { ok: true };
};

const fetchWithRedirects = async (url, options, maxRedirects, validateUrl) => {
  let currentUrl = url;
  for (let i = 0; i <= maxRedirects; i += 1) {
    const res = await fetch(currentUrl, { ...options, redirect: "manual" });
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const nextUrl = new URL(res.headers.get("location"), currentUrl).toString();
      if (validateUrl) {
        const check = validateUrl(nextUrl);
        if (!check.ok) return new Response("blocked", { status: 403 });
      }
      currentUrl = nextUrl;
      continue;
    }
    return res;
  }
  return new Response("redirect limit", { status: 429 });
};

// =============================
// Data Access Layer (D1 queries)
// =============================
const D1 = {
  async getOperatorByTelegramId(db, telegramUserId) {
    return db.prepare("SELECT * FROM operators WHERE telegram_user_id = ?").bind(telegramUserId).first();
  },
  async getOperatorById(db, operatorId) {
    return db.prepare("SELECT * FROM operators WHERE id = ?").bind(operatorId).first();
  },
  async listOperators(db) {
    return db.prepare("SELECT * FROM operators ORDER BY created_at DESC").all();
  },
  async createOperator(db, telegramUserId, displayName, role = "operator", status = "pending") {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO operators (id, telegram_user_id, display_name, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(id, telegramUserId, displayName || null, role, status, nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO operator_settings (operator_id, created_at, updated_at) VALUES (?, ?, ?)")
      .bind(id, nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO subscription_rules (operator_id, created_at, updated_at) VALUES (?, ?, ?)")
      .bind(id, nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO customer_links (id, operator_id, public_token, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
      .bind(crypto.randomUUID(), id, crypto.randomUUID(), nowIso(), nowIso())
      .run();
    return this.getOperatorByTelegramId(db, telegramUserId);
  },
  async updateOperatorStatus(db, operatorId, status) {
    await db.prepare("UPDATE operators SET status = ?, updated_at = ? WHERE id = ?").bind(status, nowIso(), operatorId).run();
  },
  async removeOperator(db, telegramUserId) {
    await db
      .prepare("UPDATE operators SET status = 'removed', updated_at = ? WHERE telegram_user_id = ?")
      .bind(nowIso(), telegramUserId)
      .run();
  },
  async touchOperator(db, operatorId) {
    await db.prepare("UPDATE operators SET updated_at = ? WHERE id = ?").bind(nowIso(), operatorId).run();
  },
  async getSettings(db, operatorId) {
    return db.prepare("SELECT * FROM operator_settings WHERE operator_id = ?").bind(operatorId).first();
  },
  async updateSettings(db, operatorId, patch) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await db
      .prepare(`UPDATE operator_settings SET ${setClause}, updated_at = ? WHERE operator_id = ?`)
      .bind(...values, nowIso(), operatorId)
      .run();
  },
  async setPendingAction(db, operatorId, action, meta = null) {
    await db
      .prepare("UPDATE operator_settings SET pending_action = ?, pending_meta = ?, updated_at = ? WHERE operator_id = ?")
      .bind(action, meta ? JSON.stringify(meta) : null, nowIso(), operatorId)
      .run();
  },
  async listDomains(db, operatorId) {
    return db.prepare("SELECT * FROM domains WHERE operator_id = ? AND deleted_at IS NULL ORDER BY created_at DESC").bind(operatorId).all();
  },
  async createDomain(db, operatorId, domain) {
    await db
      .prepare(
        "INSERT INTO domains (id, operator_id, domain, verified, token, active, created_at, updated_at) VALUES (?, ?, ?, 0, ?, 1, ?, ?)"
      )
      .bind(crypto.randomUUID(), operatorId, domain, crypto.randomUUID(), nowIso(), nowIso())
      .run();
  },
  async setDomainActive(db, operatorId, domainId) {
    await db
      .prepare("UPDATE operator_settings SET active_domain_id = ?, updated_at = ? WHERE operator_id = ?")
      .bind(domainId, nowIso(), operatorId)
      .run();
    await db.prepare("UPDATE domains SET active = 0 WHERE operator_id = ?").bind(operatorId).run();
    await db.prepare("UPDATE domains SET active = 1 WHERE id = ? AND operator_id = ?").bind(domainId, operatorId).run();
  },
  async updateDomainVerified(db, domainId, verified) {
    await db.prepare("UPDATE domains SET verified = ?, updated_at = ? WHERE id = ?").bind(verified ? 1 : 0, nowIso(), domainId).run();
  },
  async getDomainById(db, domainId) {
    return db.prepare("SELECT * FROM domains WHERE id = ? AND deleted_at IS NULL").bind(domainId).first();
  },
  async listExtraConfigs(db, operatorId, limit = 5, offset = 0) {
    return db
      .prepare("SELECT * FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL ORDER BY sort_order, created_at LIMIT ? OFFSET ?")
      .bind(operatorId, limit, offset)
      .all();
  },
  async listEnabledExtras(db, operatorId) {
    return db
      .prepare("SELECT * FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL AND enabled = 1 ORDER BY sort_order, created_at")
      .bind(operatorId)
      .all();
  },
  async countExtraConfigs(db, operatorId) {
    return db.prepare("SELECT COUNT(*) as count FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL").bind(operatorId).first();
  },
  async createExtraConfig(db, operatorId, title, content) {
    await db
      .prepare(
        "INSERT INTO extra_configs (id, operator_id, title, content, enabled, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, ?, ?)"
      )
      .bind(crypto.randomUUID(), operatorId, title || null, content, nowIso(), nowIso())
      .run();
  },
  async updateExtraConfig(db, operatorId, configId, content) {
    await db
      .prepare("UPDATE extra_configs SET content = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
      .bind(content, nowIso(), configId, operatorId)
      .run();
  },
  async setExtraEnabled(db, operatorId, configId, enabled) {
    await db
      .prepare("UPDATE extra_configs SET enabled = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
      .bind(enabled ? 1 : 0, nowIso(), configId, operatorId)
      .run();
  },
  async deleteExtraConfig(db, operatorId, configId) {
    await db
      .prepare("UPDATE extra_configs SET deleted_at = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
      .bind(nowIso(), nowIso(), configId, operatorId)
      .run();
  },
  async getRules(db, operatorId) {
    return db.prepare("SELECT * FROM subscription_rules WHERE operator_id = ?").bind(operatorId).first();
  },
  async updateRules(db, operatorId, patch) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await db
      .prepare(`UPDATE subscription_rules SET ${setClause}, updated_at = ? WHERE operator_id = ?`)
      .bind(...values, nowIso(), operatorId)
      .run();
  },
  async listUpstreams(db, operatorId) {
    return db
      .prepare("SELECT * FROM operator_upstreams WHERE operator_id = ? AND enabled = 1 ORDER BY priority DESC, created_at DESC")
      .bind(operatorId)
      .all();
  },
  async listUpstreamsAll(db, operatorId) {
    return db.prepare("SELECT * FROM operator_upstreams WHERE operator_id = ? ORDER BY priority DESC, created_at DESC").bind(operatorId).all();
  },
  async createUpstream(db, operatorId, payload) {
    await db
      .prepare(
        "INSERT INTO operator_upstreams (id, operator_id, url, enabled, weight, priority, headers_json, format_hint, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        crypto.randomUUID(),
        operatorId,
        payload.url,
        payload.enabled ? 1 : 0,
        payload.weight ?? 1,
        payload.priority ?? 0,
        payload.headers_json || null,
        payload.format_hint || null,
        nowIso(),
        nowIso()
      )
      .run();
  },
  async updateUpstream(db, operatorId, upstreamId, patch) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await db
      .prepare(`UPDATE operator_upstreams SET ${setClause}, updated_at = ? WHERE id = ? AND operator_id = ?`)
      .bind(...values, nowIso(), upstreamId, operatorId)
      .run();
  },
  async listCustomerLinks(db, operatorId) {
    return db.prepare("SELECT * FROM customer_links WHERE operator_id = ? ORDER BY created_at DESC").bind(operatorId).all();
  },
  async getCustomerLinkByToken(db, token) {
    return db.prepare("SELECT * FROM customer_links WHERE public_token = ? AND enabled = 1 AND revoked_at IS NULL").bind(token).first();
  },
  async getCustomerLinkById(db, operatorId, id) {
    return db.prepare("SELECT * FROM customer_links WHERE id = ? AND operator_id = ?").bind(id, operatorId).first();
  },
  async getPrimaryCustomerLink(db, operatorId) {
    return db
      .prepare("SELECT * FROM customer_links WHERE operator_id = ? AND enabled = 1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
      .bind(operatorId)
      .first();
  },
  async createCustomerLink(db, operatorId, label, overrides) {
    const id = crypto.randomUUID();
    const token = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO customer_links (id, operator_id, public_token, label, enabled, overrides_json, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)"
      )
      .bind(id, operatorId, token, label || null, overrides ? JSON.stringify(overrides) : null, nowIso(), nowIso())
      .run();
    return this.getCustomerLinkById(db, operatorId, id);
  },
  async rotateCustomerLink(db, operatorId, id) {
    const now = nowIso();
    await db
      .prepare("UPDATE customer_links SET enabled = 0, revoked_at = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
      .bind(now, now, id, operatorId)
      .run();
    return this.createCustomerLink(db, operatorId, null, null);
  },
  async updateCustomerLinkOverrides(db, operatorId, id, overrides) {
    await db
      .prepare("UPDATE customer_links SET overrides_json = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
      .bind(overrides ? JSON.stringify(overrides) : null, nowIso(), id, operatorId)
      .run();
  },
  async upsertLastKnownGood(db, operatorId, token, bodyB64, headersJson) {
    await db
      .prepare(
        "INSERT INTO last_known_good (operator_id, public_token, body_b64, body_format, headers_json, updated_at) VALUES (?, ?, ?, 'base64_text', ?, ?) ON CONFLICT(operator_id, public_token) DO UPDATE SET body_b64 = excluded.body_b64, body_format = excluded.body_format, headers_json = excluded.headers_json, updated_at = excluded.updated_at"
      )
      .bind(operatorId, token, bodyB64, headersJson, nowIso())
      .run();
  },
  async getLastKnownGood(db, operatorId, token) {
    return db.prepare("SELECT * FROM last_known_good WHERE operator_id = ? AND public_token = ?").bind(operatorId, token).first();
  },
  async createApiKey(db, operatorId, keyHash, scopesJson) {
    await db
      .prepare("INSERT INTO api_keys (id, operator_id, key_hash, scopes_json, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), operatorId, keyHash, scopesJson || null, nowIso())
      .run();
  },
  async getApiKeyByHash(db, keyHash) {
    return db.prepare("SELECT * FROM api_keys WHERE key_hash = ?").bind(keyHash).first();
  },
  async touchApiKey(db, keyHash) {
    await db.prepare("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?").bind(nowIso(), keyHash).run();
  },
  async createInviteCode(db, code, operatorId) {
    await db
      .prepare("INSERT INTO invite_codes (code, created_by, created_at) VALUES (?, ?, ?)")
      .bind(code, operatorId, nowIso())
      .run();
  },
  async getInviteCode(db, code) {
    return db.prepare("SELECT * FROM invite_codes WHERE code = ?").bind(code).first();
  },
  async useInviteCode(db, code, operatorId) {
    await db
      .prepare("UPDATE invite_codes SET used_by = ?, used_at = ? WHERE code = ? AND used_at IS NULL")
      .bind(operatorId, nowIso(), code)
      .run();
  },
  async logAudit(db, payload) {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO audit_logs (id, operator_id, event_type, ip, country, user_agent, request_path, response_status, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        id,
        payload.operator_id || null,
        payload.event_type,
        payload.ip || null,
        payload.country || null,
        payload.user_agent || null,
        payload.request_path || null,
        payload.response_status || null,
        payload.meta_json || null,
        nowIso()
      )
      .run();
  },
  async listAuditLogs(db, operatorId, limit = 5) {
    return db.prepare("SELECT * FROM audit_logs WHERE operator_id = ? ORDER BY created_at DESC LIMIT ?").bind(operatorId, limit).all();
  },
  async bumpRateLimit(db, key, windowMs, max) {
    const now = Date.now();
    const existing = await db.prepare("SELECT * FROM rate_limits WHERE key = ?").bind(key).first();
    if (!existing || now - existing.window_start > windowMs) {
      await db
        .prepare(
          "INSERT INTO rate_limits (key, count, window_start, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count, window_start = excluded.window_start, updated_at = excluded.updated_at"
        )
        .bind(key, 1, now, nowIso())
        .run();
      return true;
    }
    const nextCount = existing.count + 1;
    await db.prepare("UPDATE rate_limits SET count = ?, updated_at = ? WHERE key = ?").bind(nextCount, nowIso(), key).run();
    return nextCount <= max;
  },
};

// =============================
// Domain Services
// =============================
const OperatorService = {
  async ensureOperator(db, telegramUser, env) {
    let operator = await D1.getOperatorByTelegramId(db, telegramUser.id);
    if (!operator && isAdmin(telegramUser.id, env)) {
      operator = await D1.createOperator(db, telegramUser.id, telegramUser.first_name || telegramUser.username, "admin", "active");
    }
    if (!operator) return null;
    if (operator.status !== "active") return operator;
    await D1.touchOperator(db, operator.id);
    return operator;
  },
  async getShareLink(db, operator, baseUrl) {
    const settings = await D1.getSettings(db, operator.id);
    const share = await D1.getPrimaryCustomerLink(db, operator.id);
    let hostBase = baseUrl;
    if (settings?.active_domain_id) {
      const domain = await D1.getDomainById(db, settings.active_domain_id);
      if (domain?.domain) hostBase = `https://${domain.domain}`;
    }
    return `${hostBase.replace(/\/$/, "")}/sub/${share?.public_token || ""}`;
  },
};

const SubscriptionAssembler = {
  async assemble(env, db, operatorId, token, request, requestId, customerLink) {
    const settings = await D1.getSettings(db, operatorId);
    const baseRules = await D1.getRules(db, operatorId);
    const overrides = safeParseJson(customerLink?.overrides_json, {});
    const rules = { ...baseRules, ...overrides };
    const extras = await D1.listEnabledExtras(db, operatorId);
    const selectedExtras = overrides?.extras?.length
      ? (extras?.results || []).filter((item) => overrides.extras.includes(item.id))
      : (extras?.results || []);

    const upstreams = await D1.listUpstreams(db, operatorId);
    const allowlist = parseCommaList(settings?.upstream_allowlist);
    const denylist = parseCommaList(settings?.upstream_denylist);

    const upstreamPayloads = await this.fetchUpstreams(upstreams?.results || [], allowlist, denylist);
    const selected = this.selectUpstreamsByPolicy(upstreamPayloads, rules?.merge_policy || "append");
    const extrasContent = selectedExtras.map((item) => item.content).join("\n");

    if (!selected.ok) {
      await D1.updateSettings(db, operatorId, { last_upstream_status: "invalid", last_upstream_at: nowIso() });
      await D1.logAudit(db, {
        operator_id: operatorId,
        event_type: "upstream_invalid",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 502,
        meta_json: JSON.stringify({ reason: "upstream_invalid", request_id: requestId }),
      });
      await AuditService.notifyOperator(env, settings, `⚠️ آپ‌استریم نامعتبر بود برای <b>${safeHtml(settings?.branding || "اپراتور")}</b>`);
      return { body: "", headers: { ...DEFAULT_HEADERS, "x-sub-status": "upstream_invalid" }, valid: false };
    }

    await D1.updateSettings(db, operatorId, { last_upstream_status: "ok", last_upstream_at: nowIso() });

    const merged = this.mergeContent(selected.text, extrasContent, rules);
    const processed = this.applyRules(merged, rules);
    const limited = limitOutput(processed.split("\n"), rules?.limit_lines || APP.maxOutputLines, rules?.limit_bytes || APP.maxOutputBytes);
    const outputBody = limited.join("\n");
    const formatted = rules?.output_format === "plain" ? outputBody : utf8SafeEncode(outputBody);

    return {
      body: formatted,
      headers: {
        ...DEFAULT_HEADERS,
        ...(selected.subscriptionUserinfo ? { "subscription-userinfo": selected.subscriptionUserinfo } : {}),
      },
      valid: true,
    };
  },
  async fetchUpstreams(upstreams, allowlist, denylist) {
    const results = [];
    for (const upstream of upstreams) {
      const validation = assertSafeUpstream(upstream.url, allowlist, denylist);
      if (!validation.ok) {
        results.push({ ok: false, status: 400, body: "", subscriptionUserinfo: null, isBase64: false, error: validation.error, upstream });
        continue;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), APP.upstreamTimeoutMs);
      try {
        const headers = upstream.headers_json ? JSON.parse(upstream.headers_json) : { "user-agent": "v2rayNG" };
        const res = await fetchWithRedirects(
          upstream.url,
          { cf: { cacheTtl: 0 }, signal: controller.signal, headers },
          APP.maxRedirects,
          (nextUrl) => assertSafeUpstream(nextUrl, allowlist, denylist)
        );
        const text = await res.text();
        if (new TextEncoder().encode(text).length > APP.maxOutputBytes) {
          results.push({ ok: false, status: 413, body: "", subscriptionUserinfo: null, isBase64: false, error: "too_large", upstream });
          continue;
        }
        clearTimeout(timeout);
        results.push({
          ok: res.ok,
          status: res.status,
          body: text,
          subscriptionUserinfo: res.headers.get("subscription-userinfo"),
          isBase64: looksLikeBase64(text),
          upstream,
        });
      } catch (err) {
        clearTimeout(timeout);
        Logger.warn("Upstream fetch failed", { error: err?.message, upstream: redactUrlForLog(upstream.url) });
        results.push({ ok: false, status: 502, body: "", subscriptionUserinfo: null, isBase64: false, error: "fetch_failed", upstream });
      }
    }
    return results;
  },
  selectUpstreamsByPolicy(results, policy) {
    const valid = results.filter((item) => item.ok && isValidSubscriptionText(this.decodeSubscription(item.body, item.isBase64)));
    if (!valid.length) return { ok: false, text: "", subscriptionUserinfo: null };
    if (policy === "upstream_only") {
      const first = valid[0];
      return { ok: true, text: this.decodeSubscription(first.body, first.isBase64), subscriptionUserinfo: first.subscriptionUserinfo };
    }
    if (policy === "failover") {
      const first = valid[0];
      return { ok: true, text: this.decodeSubscription(first.body, first.isBase64), subscriptionUserinfo: first.subscriptionUserinfo };
    }
    if (policy === "round_robin") {
      const lists = valid.map((item) => this.decodeSubscription(item.body, item.isBase64).split("\n").filter(Boolean));
      const max = Math.max(...lists.map((list) => list.length));
      const merged = [];
      for (let i = 0; i < max; i += 1) {
        for (const list of lists) {
          if (list[i]) merged.push(list[i]);
        }
      }
      return { ok: true, text: merged.join("\n"), subscriptionUserinfo: valid[0].subscriptionUserinfo };
    }
    if (policy === "weighted") {
      const weightedLists = [];
      for (const item of valid) {
        const weight = Math.max(1, item.upstream.weight || 1);
        const list = this.decodeSubscription(item.body, item.isBase64).split("\n").filter(Boolean);
        for (let i = 0; i < weight; i += 1) weightedLists.push(list);
      }
      const max = Math.max(...weightedLists.map((list) => list.length));
      const merged = [];
      for (let i = 0; i < max; i += 1) {
        for (const list of weightedLists) {
          if (list[i]) merged.push(list[i]);
        }
      }
      return { ok: true, text: merged.join("\n"), subscriptionUserinfo: valid[0].subscriptionUserinfo };
    }
    const combined = valid.map((item) => this.decodeSubscription(item.body, item.isBase64)).join("\n");
    return { ok: true, text: combined, subscriptionUserinfo: valid[0].subscriptionUserinfo };
  },
  decodeSubscription(body, isBase64) {
    if (!body) return "";
    if (!isBase64) return body;
    try {
      return utf8SafeDecode(body);
    } catch {
      return body;
    }
  },
  mergeContent(upstream, extras, rules) {
    const policy = rules?.merge_policy || "append";
    if (policy === "upstream_only") return upstream || "";
    if (policy === "extras_only") return extras || "";
    if (policy === "replace") return extras || "";
    return [upstream, extras].filter(Boolean).join("\n");
  },
  applyRules(content, rules) {
    const lines = content
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const blocked = (rules?.blocked_keywords || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    let processed = lines;
    if (rules?.sanitize !== 0) processed = sanitizeLines(processed, blocked);
    if (rules?.dedupe !== 0) processed = stableDedupe(processed);
    if (rules?.naming_mode === "prefix" && rules?.naming_prefix) {
      processed = processed.map((line) => `${rules.naming_prefix}${line}`);
    }
    return processed.join("\n");
  },
};

const AuditService = {
  async notifyOperator(env, settings, messageHtml) {
    const channelId = settings?.channel_id || env.LOG_CHANNEL_ID;
    if (!channelId || !env.TELEGRAM_TOKEN) return;
    try {
      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: channelId,
          text: messageHtml,
          parse_mode: "HTML",
          disable_web_page_preview: true,
        }),
      });
    } catch (err) {
      Logger.warn("Notify Telegram failed", { error: err?.message });
    }
  },
};

const AuthService = {
  async getAuthContext(request, env, db) {
    const authHeader = request.headers.get("authorization") || "";
    if (authHeader.startsWith("Bearer ")) {
      const token = authHeader.replace("Bearer ", "").trim();
      if (!token || !env.SESSION_SECRET) return null;
      const payload = await verifySession(token, env.SESSION_SECRET);
      if (!payload || payload.exp < Math.floor(Date.now() / 1000)) return null;
      const operator = await D1.getOperatorById(db, payload.sub);
      if (!operator || operator.status !== "active") return null;
      return { operator, tokenType: "session" };
    }
    const apiKey = request.headers.get("x-api-key");
    if (apiKey) {
      const hash = await hashApiKey(apiKey);
      const key = await D1.getApiKeyByHash(db, hash);
      if (!key) return null;
      const operator = await D1.getOperatorById(db, key.operator_id);
      if (!operator || operator.status !== "active") return null;
      await D1.touchApiKey(db, hash);
      return { operator, tokenType: "api_key" };
    }
    return null;
  },
};

// =============================
// Telegram Adapter
// =============================
const Telegram = {
  async handleWebhook(request, env) {
    if (env.TELEGRAM_SECRET) {
      const secret = request.headers.get("x-telegram-bot-api-secret-token");
      if (secret !== env.TELEGRAM_SECRET) return new Response("unauthorized", { status: 401 });
    }
    if (!request.headers.get("content-type")?.includes("application/json")) {
      return new Response("unsupported", { status: 415 });
    }
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength && contentLength > APP.maxWebhookBytes) {
      return new Response("payload too large", { status: 413 });
    }

    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (!rateLimit(`tg:${ip}`)) {
      const ok = await D1.bumpRateLimit(env.DB, `tg:${ip}`, APP.rateLimitWindowMs, APP.rateLimitMax * 2);
      if (!ok) return new Response("rate limit", { status: 429 });
    }

    const bodyBuf = await request.arrayBuffer();
    if (bodyBuf.byteLength > APP.maxWebhookBytes) {
      return new Response("payload too large", { status: 413 });
    }
    const update = JSON.parse(new TextDecoder().decode(bodyBuf));
    const message = update.message || update.callback_query?.message;
    const user = update.message?.from || update.callback_query?.from;
    if (!user) return new Response("ok");
    if (!rateLimit(`tg-user:${user.id}`)) return new Response("rate limit", { status: 429 });

    const db = env.DB;
    const operator = await OperatorService.ensureOperator(db, user, env);
    if (!operator) {
      await this.sendMessage(env, user.id, "⚠️ این ربات فقط برای اپراتورها فعال است.");
      return new Response("ok");
    }

    if (operator.status === "pending") {
      await this.sendMessage(env, user.id, "⏳ حساب شما در انتظار تایید مدیر است.");
      return new Response("ok");
    }

    if (update.message) {
      return this.handleMessage(env, db, operator, update.message);
    }
    if (update.callback_query) {
      return this.handleCallback(env, db, operator, update.callback_query);
    }
    return new Response("ok");
  },
  async handleMessage(env, db, operator, message) {
    const text = parseMessageText(message);
    const settings = await D1.getSettings(db, operator.id);

    if (text === "/cancel") {
      await D1.setPendingAction(db, operator.id, null, null);
      await this.sendMessage(env, message.chat.id, "✅ عملیات لغو شد.");
      return new Response("ok");
    }

    if (!text.startsWith("/") && settings?.pending_action) {
      const action = settings.pending_action;
      if (action === "set_upstream") {
        await D1.createUpstream(db, operator.id, { url: text, enabled: true, weight: 1, priority: 1 });
        await D1.setPendingAction(db, operator.id, null, null);
        await D1.logAudit(db, {
          operator_id: operator.id,
          event_type: "settings_update:upstream_url",
          meta_json: JSON.stringify({ upstream: redactUrlForLog(text) }),
        });
        await AuditService.notifyOperator(env, settings, "🧊 آپ‌استریم بروزرسانی شد.");
        await this.sendMessage(env, message.chat.id, "✅ لینک آپ‌استریم ذخیره شد.");
        return new Response("ok");
      }
      if (action === "set_domain") {
        if (!isValidDomain(text)) {
          await this.sendMessage(env, message.chat.id, "❗️دامنه معتبر نیست.");
          return new Response("ok");
        }
        await D1.createDomain(db, operator.id, text);
        const domains = await D1.listDomains(db, operator.id);
        const latest = domains?.results?.[0];
        if (latest) await D1.setDomainActive(db, operator.id, latest.id);
        await D1.setPendingAction(db, operator.id, null, null);
        await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:domain" });
        await AuditService.notifyOperator(env, settings, "🧊 دامنه بروزرسانی شد.");
        const token = latest?.token ? `\nتوکن تایید: <code>${safeHtml(latest.token)}</code>` : "";
        await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد.${token}`);
        return new Response("ok");
      }
      if (action === "set_channel") {
        await D1.updateSettings(db, operator.id, { channel_id: text });
        await D1.setPendingAction(db, operator.id, null, null);
        await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:channel" });
        await AuditService.notifyOperator(env, { channel_id: text }, "✅ اتصال کانال تایید شد.");
        await this.sendMessage(env, message.chat.id, "✅ کانال اطلاع‌رسانی ذخیره شد.");
        return new Response("ok");
      }
    }

    if (text.startsWith("/start") || text.startsWith("/panel")) {
      const payload = await this.buildPanel(db, operator, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/set_upstream")) {
      const value = text.replace("/set_upstream", "").trim();
      if (!value) {
        await D1.setPendingAction(db, operator.id, "set_upstream");
        await this.sendMessage(env, message.chat.id, "📌 لطفاً لینک آپ‌استریم را بفرستید.");
        return new Response("ok");
      }
      await D1.createUpstream(db, operator.id, { url: value, enabled: true, weight: 1, priority: 1 });
      await D1.logAudit(db, {
        operator_id: operator.id,
        event_type: "settings_update:upstream_url",
        meta_json: JSON.stringify({ upstream: redactUrlForLog(value) }),
      });
      await AuditService.notifyOperator(env, settings, "🧊 آپ‌استریم بروزرسانی شد.");
      await this.sendMessage(env, message.chat.id, "✅ لینک آپ‌استریم ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/set_domain")) {
      const domain = text.replace("/set_domain", "").trim();
      if (!domain) {
        await D1.setPendingAction(db, operator.id, "set_domain");
        await this.sendMessage(env, message.chat.id, "📌 لطفاً دامنه را بفرستید.");
        return new Response("ok");
      }
      if (!isValidDomain(domain)) {
        await this.sendMessage(env, message.chat.id, "❗️دامنه معتبر نیست.");
        return new Response("ok");
      }
      await D1.createDomain(db, operator.id, domain);
      const domains = await D1.listDomains(db, operator.id);
      const latest = domains?.results?.[0];
      if (latest) await D1.setDomainActive(db, operator.id, latest.id);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:domain", meta_json: JSON.stringify({ domain }) });
      await AuditService.notifyOperator(env, settings, "🧊 دامنه بروزرسانی شد.");
      const token = latest?.token ? `\nتوکن تایید: <code>${safeHtml(latest.token)}</code>` : "";
      await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد.${token}`);
      return new Response("ok");
    }
    if (text.startsWith("/set_channel")) {
      const channelId = text.replace("/set_channel", "").trim();
      if (!channelId) {
        await D1.setPendingAction(db, operator.id, "set_channel");
        await this.sendMessage(env, message.chat.id, "📌 لطفاً شناسه کانال را بفرستید.");
        return new Response("ok");
      }
      await D1.updateSettings(db, operator.id, { channel_id: channelId });
      await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:channel" });
      await AuditService.notifyOperator(env, { channel_id: channelId }, "✅ اتصال کانال تایید شد.");
      await this.sendMessage(env, message.chat.id, "✅ کانال اطلاع‌رسانی ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/extras")) {
      const payload = await this.buildExtrasPanel(db, operator, 0);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/add_extra")) {
      const { title, content } = parseAddExtra(text);
      if (!content) {
        await this.sendMessage(env, message.chat.id, "❗️بعد از دستور متن کانفیگ را بفرستید. مثال: /add_extra عنوان | متن");
        return new Response("ok");
      }
      await D1.createExtraConfig(db, operator.id, title, content);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:add" });
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ اضافی ثبت شد.");
      return new Response("ok");
    }
    if (text.startsWith("/edit_extra")) {
      const parts = text.split(" ").slice(1);
      const [configId, ...contentParts] = parts;
      const content = contentParts.join(" ").trim();
      if (!configId || !content) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /edit_extra شناسه متن_جدید");
        return new Response("ok");
      }
      await D1.updateExtraConfig(db, operator.id, configId, content);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:edit" });
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ ویرایش شد.");
      return new Response("ok");
    }
    if (text.startsWith("/rules")) {
      const payload = await this.buildRulesPanel(db, operator);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/set_rules")) {
      const patch = parseRulesArgs(text);
      if (!Object.keys(patch).length) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /set_rules merge=append dedupe=1 sanitize=1 prefix=VIP_ keywords=ads,spam format=base64");
        return new Response("ok");
      }
      await D1.updateRules(db, operator.id, patch);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "rules_update", meta_json: JSON.stringify(patch) });
      await this.sendMessage(env, message.chat.id, "✅ قوانین ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/link")) {
      const payload = await this.buildLinkPanel(db, operator, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/rotate")) {
      const primary = await D1.getPrimaryCustomerLink(db, operator.id);
      const share = primary ? await D1.rotateCustomerLink(db, operator.id, primary.id) : await D1.createCustomerLink(db, operator.id, null, null);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "link_rotate" });
      const link = await OperatorService.getShareLink(db, operator, env.BASE_URL || "");
      await this.sendMessage(env, message.chat.id, `✅ لینک جدید: <code>${safeHtml(link)}</code>`);
      return new Response("ok");
    }
    if (text.startsWith("/logs")) {
      const payload = await this.buildLogsPanel(db, operator);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }

    if (text.startsWith("/admin_list_operators")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const operators = await D1.listOperators(db);
      const list = (operators?.results || [])
        .map((item) => `• ${safeHtml(item.display_name || item.telegram_user_id)} (${safeHtml(item.telegram_user_id)}) - ${safeHtml(item.status)} - ${safeHtml(item.role)}`)
        .join("\n");
      await this.sendMessage(env, message.chat.id, list || "لیست خالی است.");
      return new Response("ok");
    }
    if (text.startsWith("/admin_add_operator")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const targetId = text.replace("/admin_add_operator", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه تلگرام را وارد کنید.");
        return new Response("ok");
      }
      const existing = await D1.getOperatorByTelegramId(db, targetId);
      if (!existing) {
        await D1.createOperator(db, targetId, "Operator", "operator", "active");
      }
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_add_operator" });
      await this.sendMessage(env, message.chat.id, "✅ اپراتور اضافه شد.");
      return new Response("ok");
    }
    if (text.startsWith("/admin_remove_operator")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const targetId = text.replace("/admin_remove_operator", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه تلگرام را وارد کنید.");
        return new Response("ok");
      }
      await D1.removeOperator(db, targetId);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_remove_operator" });
      await this.sendMessage(env, message.chat.id, "✅ اپراتور غیرفعال شد.");
      return new Response("ok");
    }
    if (text.startsWith("/admin_broadcast")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const messageBody = text.replace("/admin_broadcast", "").trim();
      if (!messageBody) {
        await this.sendMessage(env, message.chat.id, "❗️متن پیام را بنویسید.");
        return new Response("ok");
      }
      const operators = await D1.listOperators(db);
      for (const item of operators?.results || []) {
        const opSettings = await D1.getSettings(db, item.id);
        await AuditService.notifyOperator(env, opSettings, `📣 پیام مدیر: ${safeHtml(messageBody)}`);
      }
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_broadcast" });
      await this.sendMessage(env, message.chat.id, "✅ پیام ارسال شد.");
      return new Response("ok");
    }
    if (text.startsWith("/admin_health")) {
      await this.sendMessage(env, message.chat.id, `🟢 سلامت سیستم: ${APP.name} v${APP.version}`);
      return new Response("ok");
    }

    await this.sendMessage(env, message.chat.id, "❓ دستور ناشناخته. /panel را بزنید.");
    return new Response("ok");
  },
  async handleCallback(env, db, operator, callback) {
    const data = decodeCallbackData(callback.data || "");
    const action = data.action || "";
    const chatId = callback.message?.chat?.id;
    if (!chatId) return new Response("ok");

    if (action === "toggle_extra" && data.id) {
      await D1.setExtraEnabled(db, operator.id, data.id, data.enabled);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:toggle" });
      await this.sendMessage(env, chatId, "✅ وضعیت افزودنی تغییر کرد.");
      return new Response("ok");
    }
    if (action === "delete_extra" && data.id) {
      await D1.deleteExtraConfig(db, operator.id, data.id);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:delete" });
      await this.sendMessage(env, chatId, "🗑️ کانفیگ حذف شد.");
      return new Response("ok");
    }
    if (action === "set_rules") {
      await D1.updateRules(db, operator.id, data.patch || {});
      await D1.logAudit(db, { operator_id: operator.id, event_type: "rules_update" });
      await this.sendMessage(env, chatId, "✅ قوانین اشتراک ذخیره شد.");
      return new Response("ok");
    }
    if (action === "panel_extras") {
      const page = Number(data.page || 0);
      const payload = await this.buildExtrasPanel(db, operator, page);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_rules") {
      const payload = await this.buildRulesPanel(db, operator);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_channel") {
      await D1.setPendingAction(db, operator.id, "set_channel");
      await this.sendMessage(env, chatId, "📌 شناسه کانال را ارسال کنید.");
      return new Response("ok");
    }
    if (action === "panel_upstream") {
      await D1.setPendingAction(db, operator.id, "set_upstream");
      await this.sendMessage(env, chatId, "📌 لینک آپ‌استریم را ارسال کنید.");
      return new Response("ok");
    }
    if (action === "panel_domain") {
      await D1.setPendingAction(db, operator.id, "set_domain");
      await this.sendMessage(env, chatId, "📌 دامنه را ارسال کنید.");
      return new Response("ok");
    }
    if (action === "show_link") {
      const payload = await this.buildLinkPanel(db, operator, env);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }

    await this.sendMessage(env, chatId, "✅ انجام شد.");
    return new Response("ok");
  },
  async buildPanel(db, operator, env) {
    const settings = await D1.getSettings(db, operator.id);
    const domains = await D1.listDomains(db, operator.id);
    const activeDomain = (domains?.results || []).find((item) => item.active);
    const shareLink = await OperatorService.getShareLink(db, operator, env.BASE_URL || "");
    const text = `
${GLASS} <b>پنل اپراتور</b>

👤 اپراتور: <code>${safeHtml(operator.display_name || operator.telegram_user_id)}</code>
🌐 دامنه فعال: <code>${safeHtml(activeDomain?.domain || "ثبت نشده")}</code>
🔗 لینک اشتراک: <code>${safeHtml(shareLink)}</code>

دستورات اصلی:
/set_upstream لینک_پنل
/set_domain example.com
/set_channel -100xxxxxxxxxx
/extras
/rules
/link
/rotate
/logs
/cancel
    `.trim();

    const keyboard = {
      inline_keyboard: [
        [
          { text: GLASS_BTN("تنظیم آپ‌استریم"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_upstream" })) },
          { text: GLASS_BTN("تنظیم دامنه"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_domain" })) },
        ],
        [
          { text: GLASS_BTN("مشاهده لینک"), callback_data: utf8SafeEncode(JSON.stringify({ action: "show_link" })) },
          { text: GLASS_BTN("افزودنی‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_extras" })) },
        ],
        [
          { text: GLASS_BTN("قوانین"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_rules" })) },
          { text: GLASS_BTN("کانال"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_channel" })) },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildLinkPanel(db, operator, env) {
    let baseUrl = env.BASE_URL || "";
    const link = await OperatorService.getShareLink(db, operator, baseUrl);
    if (!baseUrl && link.startsWith("http")) {
      baseUrl = new URL(link).origin;
    }
    const settings = await D1.getSettings(db, operator.id);
    const activeDomain = settings?.active_domain_id ? await D1.getDomainById(db, settings.active_domain_id) : null;
    const extrasCount = await D1.countExtraConfigs(db, operator.id);
    const rules = await D1.getRules(db, operator.id);
    const text = `
${GLASS} <b>لینک اشتراک برند شما</b>

<code>${safeHtml(link)}</code>

دامنه فعال: ${safeHtml(activeDomain?.domain || "-")}
وضعیت آپ‌استریم: ${safeHtml(settings?.last_upstream_status || "-")} (${safeHtml(settings?.last_upstream_at || "-")})
افزودنی‌ها: ${extrasCount?.count || 0}
Merge policy: ${safeHtml(rules?.merge_policy || "append")}
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [
          { text: GLASS_BTN("کپی لینک"), url: `https://t.me/share/url?url=${encodeURIComponent(link)}` },
          { text: GLASS_BTN("پیش‌نمایش"), url: link },
        ],
        [
          { text: GLASS_BTN("v2rayNG"), url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2rayng://install-config?url=${link}#${operator.display_name || "Sub"}`)}` },
          { text: GLASS_BTN("NekoBox"), url: `${baseUrl}/redirect?target=${encodeURIComponent(`sn://subscription?url=${link}&name=${operator.display_name || "Sub"}`)}` },
        ],
        [
          { text: GLASS_BTN("Streisand"), url: `${baseUrl}/redirect?target=${encodeURIComponent(`streisand://import/${link}`)}` },
          { text: GLASS_BTN("v2Box"), url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2box://install-sub?url=${link}&name=${operator.display_name || "Sub"}`)}` },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildExtrasPanel(db, operator, page = 0) {
    const limit = 5;
    const offset = page * limit;
    const extras = await D1.listExtraConfigs(db, operator.id, limit, offset);
    const total = await D1.countExtraConfigs(db, operator.id);
    const list = (extras?.results || [])
      .map((item) => `• ${safeHtml(item.title || "افزودنی")} (${safeHtml(item.id)}) ${item.enabled ? "✅" : "⛔️"}`)
      .join("\n");
    const text = `
${GLASS} <b>افزودنی‌ها</b>

${list || "فعلاً موردی ثبت نشده."}

صفحه: ${page + 1}
برای افزودن:
<code>/add_extra عنوان | متن</code>
برای ویرایش:
<code>/edit_extra شناسه متن_جدید</code>
    `.trim();
    const keyboard = {
      inline_keyboard: [
        ...(extras?.results || []).map((item) => [
          { text: GLASS_BTN(item.enabled ? "غیرفعال" : "فعال"), callback_data: utf8SafeEncode(JSON.stringify({ action: "toggle_extra", id: item.id, enabled: !item.enabled })) },
          { text: GLASS_BTN("حذف"), callback_data: utf8SafeEncode(JSON.stringify({ action: "delete_extra", id: item.id })) },
        ]),
        [
          ...(page > 0 ? [{ text: GLASS_BTN("قبلی"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_extras", page: page - 1 })) }] : []),
          ...(offset + limit < (total?.count || 0)
            ? [{ text: GLASS_BTN("بعدی"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_extras", page: page + 1 })) }]
            : []),
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildRulesPanel(db, operator) {
    const rules = await D1.getRules(db, operator.id);
    const text = `
${GLASS} <b>قوانین اشتراک</b>

سیاست ادغام: ${safeHtml(rules?.merge_policy || "append")}
حذف تکراری: ${rules?.dedupe ? "فعال" : "غیرفعال"}
پاکسازی: ${rules?.sanitize ? "فعال" : "غیرفعال"}
پیشوند نام: ${safeHtml(rules?.naming_prefix || "-")}
کلیدواژه‌های مسدود: ${safeHtml(rules?.blocked_keywords || "-")}
خروجی: ${safeHtml(rules?.output_format || "base64")}

برای تغییر سریع از دکمه‌ها یا دستور زیر استفاده کنید:
<code>/set_rules merge=append dedupe=1 sanitize=1 prefix=VIP_ keywords=ads,spam format=base64</code>
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [
          { text: GLASS_BTN("ادغام + حذف تکراری"), callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "append", dedupe: 1 } })) },
          { text: GLASS_BTN("فقط اپ‌استریم"), callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "upstream_only" } })) },
        ],
        [
          { text: GLASS_BTN("فقط افزودنی‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "extras_only" } })) },
          { text: GLASS_BTN("پاکسازی خاموش"), callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { sanitize: 0 } })) },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildLogsPanel(db, operator) {
    const logs = await D1.listAuditLogs(db, operator.id, 5);
    const items = (logs?.results || [])
      .map((log) => `• ${safeHtml(log.event_type)} ${safeHtml(log.created_at)}`)
      .join("\n");
    const text = `
${GLASS} <b>لاگ‌های اخیر</b>

${items || "فعلاً لاگی ثبت نشده."}
    `.trim();
    return { text, keyboard: null };
  },
  async sendMessage(env, chatId, text, keyboard) {
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
    };
    if (keyboard) body.reply_markup = keyboard;
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  },
};

// =============================
// HTTP Router
// =============================
const Router = {
  async handle(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/webhook") {
      return Telegram.handleWebhook(request, env);
    }
    if (request.method === "POST" && url.pathname === "/auth/telegram") {
      return this.handleTelegramLogin(request, env);
    }
    if (request.method === "GET" && url.pathname.startsWith("/sub/")) {
      const token = url.pathname.split("/").pop();
      return this.handleSubscription(request, env, token);
    }
    if (request.method === "GET" && url.pathname === "/redirect") {
      return this.handleRedirect(url);
    }
    if (request.method === "GET" && url.pathname.startsWith("/verify-domain/")) {
      return this.handleVerifyDomain(request, env, url);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return this.handleHealth(env);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/health/full") {
      return this.handleHealthFull(env);
    }
    if (url.pathname.startsWith("/api/v1/")) {
      return this.handleApi(request, env);
    }
    if (request.method === "GET" && url.pathname === "/") {
      return this.handleLanding(request, env);
    }
    return new Response("not found", { status: 404 });
  },
  async handleTelegramLogin(request, env) {
    if (!env.TELEGRAM_TOKEN || !env.SESSION_SECRET) {
      return jsonResponse({ ok: false, error: "missing_env" }, 500);
    }
    const body = await parseJsonBody(request);
    if (!body) return jsonResponse({ ok: false, error: "invalid_body" }, 400);
    const ok = await validateTelegramLogin(body, env.TELEGRAM_TOKEN);
    if (!ok) return jsonResponse({ ok: false, error: "invalid_auth" }, 403);
    const telegramId = body.id;
    const displayName = body.first_name || body.username || "Operator";
    let operator = await D1.getOperatorByTelegramId(env.DB, telegramId);
    if (!operator) {
      let status = "pending";
      if (isAdmin(telegramId, env)) status = "active";
      if (body.invite_code) {
        const invite = await D1.getInviteCode(env.DB, body.invite_code);
        if (!invite || invite.used_at) return jsonResponse({ ok: false, error: "invalid_invite" }, 403);
        operator = await D1.createOperator(env.DB, telegramId, displayName, "operator", status);
        await D1.useInviteCode(env.DB, body.invite_code, operator.id);
      } else {
        operator = await D1.createOperator(env.DB, telegramId, displayName, "operator", status);
      }
    }
    const payload = {
      sub: operator.id,
      role: operator.role,
      telegram_user_id: operator.telegram_user_id,
      exp: Math.floor(Date.now() / 1000) + APP.sessionTtlSec,
    };
    const token = await signSession(payload, env.SESSION_SECRET);
    return jsonResponse({ ok: true, token, status: operator.status });
  },
  async handleApi(request, env) {
    const ctx = await AuthService.getAuthContext(request, env, env.DB);
    if (!ctx) return jsonResponse({ ok: false, error: "unauthorized" }, 401);
    const { operator } = ctx;
    const url = new URL(request.url);
    const path = url.pathname.replace("/api/v1", "");
    if (request.method === "GET" && path === "/operators/me/upstreams") {
      const data = await D1.listUpstreamsAll(env.DB, operator.id);
      return jsonResponse({ ok: true, data: data?.results || [] });
    }
    if (request.method === "POST" && path === "/operators/me/upstreams") {
      const body = await parseJsonBody(request);
      if (!body?.url) return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      await D1.createUpstream(env.DB, operator.id, body);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_upstream_create" });
      return jsonResponse({ ok: true });
    }
    if (request.method === "POST" && path === "/operators/me/extras") {
      const body = await parseJsonBody(request);
      if (!body?.content) return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      await D1.createExtraConfig(env.DB, operator.id, body.title, body.content);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_extra_create" });
      return jsonResponse({ ok: true });
    }
    if (request.method === "POST" && path === "/operators/me/customer-links") {
      const body = await parseJsonBody(request);
      const link = await D1.createCustomerLink(env.DB, operator.id, body?.label, body?.overrides);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_customer_link_create" });
      return jsonResponse({ ok: true, data: link });
    }
    if (request.method === "GET" && path === "/operators/me/customer-links") {
      const links = await D1.listCustomerLinks(env.DB, operator.id);
      return jsonResponse({ ok: true, data: links?.results || [] });
    }
    if (request.method === "POST" && path.startsWith("/operators/me/customer-links/") && path.endsWith("/rotate")) {
      const id = path.split("/")[4];
      if (!id) return jsonResponse({ ok: false, error: "missing_id" }, 400);
      const link = await D1.rotateCustomerLink(env.DB, operator.id, id);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_customer_link_rotate" });
      return jsonResponse({ ok: true, data: link });
    }
    if (request.method === "PATCH" && path === "/operators/me/rules") {
      const body = await parseJsonBody(request);
      if (!body) return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      await D1.updateRules(env.DB, operator.id, body);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_rules_update" });
      return jsonResponse({ ok: true });
    }
    if (request.method === "GET" && path === "/operators/me/domains") {
      const domains = await D1.listDomains(env.DB, operator.id);
      return jsonResponse({ ok: true, data: domains?.results || [] });
    }
    if (request.method === "POST" && path === "/operators/me/api-keys") {
      const body = await parseJsonBody(request);
      const rawKey = body?.key || crypto.randomUUID();
      const keyHash = await hashApiKey(rawKey);
      await D1.createApiKey(env.DB, operator.id, keyHash, body?.scopes ? JSON.stringify(body.scopes) : null);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_key_create" });
      return jsonResponse({ ok: true, key: rawKey });
    }
    if (request.method === "POST" && path === "/admin/invite-codes") {
      if (!isAdmin(operator.telegram_user_id, env)) return jsonResponse({ ok: false, error: "forbidden" }, 403);
      const code = crypto.randomUUID().split("-")[0];
      await D1.createInviteCode(env.DB, code, operator.id);
      return jsonResponse({ ok: true, code });
    }
    if (request.method === "POST" && path.startsWith("/admin/operators/") && path.endsWith("/approve")) {
      if (!isAdmin(operator.telegram_user_id, env)) return jsonResponse({ ok: false, error: "forbidden" }, 403);
      const id = path.split("/")[3];
      await D1.updateOperatorStatus(env.DB, id, "active");
      return jsonResponse({ ok: true });
    }
    return jsonResponse({ ok: false, error: "not_found" }, 404);
  },
  async handleSubscription(request, env, token) {
    const requestId = crypto.randomUUID();
    const cacheKey = `sub:${token}`;
    const db = env.DB;
    const link = await D1.getCustomerLinkByToken(db, token);
    if (!link) return new Response("not found", { status: 404 });

    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const settings = await D1.getSettings(db, link.operator_id);
    const quotas = safeParseJson(settings?.quotas_json, {});
    const perIp = quotas?.per_ip ?? APP.rateLimitMax;
    const perToken = quotas?.per_token ?? APP.rateLimitMax;
    const perOperator = quotas?.per_operator ?? APP.rateLimitMax * 10;

    if (!rateLimit(`sub-ip:${ip}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-ip:${ip}`, APP.rateLimitWindowMs, perIp);
      if (!ok) return new Response("rate limit", { status: 429 });
    }
    if (!rateLimit(`sub-token:${token}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-token:${token}`, APP.rateLimitWindowMs, perToken);
      if (!ok) return new Response("rate limit", { status: 429 });
    }
    if (!rateLimit(`sub-op:${link.operator_id}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-op:${link.operator_id}`, APP.rateLimitWindowMs, perOperator);
      if (!ok) return new Response("rate limit", { status: 429 });
    }

    const cached = getCachedSub(cacheKey);
    if (cached) {
      await D1.logAudit(db, {
        operator_id: link.operator_id,
        event_type: "subscription_fetch",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 200,
        meta_json: JSON.stringify({ cache: "memory", request_id: requestId }),
      });
      return new Response(cached.body, { headers: { ...cached.headers, "x-request-id": requestId } });
    }

    const cacheUrl = new URL(`https://cache.internal/sub/${token}`);
    const cache = caches.default;
    const cachedResponse = await cache.match(cacheUrl);
    if (cachedResponse) {
      const body = await cachedResponse.text();
      const cachedHeaders = Object.fromEntries(cachedResponse.headers.entries());
      cachedHeaders["cache-control"] = "no-store";
      cachedHeaders["content-disposition"] = cachedHeaders["content-disposition"] || `inline; filename=sub_${token}.txt`;
      setCachedSub(cacheKey, body, cachedHeaders);
      await D1.logAudit(db, {
        operator_id: link.operator_id,
        event_type: "subscription_fetch",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 200,
        meta_json: JSON.stringify({ cache: "edge", request_id: requestId }),
      });
      return new Response(body, { headers: { ...cachedHeaders, "x-request-id": requestId } });
    }

    const { body, headers, valid } = await SubscriptionAssembler.assemble(env, db, link.operator_id, token, request, requestId, link);
    const responseHeadersBase = { ...headers, "content-disposition": `inline; filename=sub_${token}.txt` };
    const clientHeaders = { ...responseHeadersBase, "x-request-id": requestId, "cache-control": "no-store" };
    const cacheHeaders = { ...responseHeadersBase, "cache-control": "max-age=60" };
    if (valid) {
      setCachedSub(cacheKey, body, clientHeaders);
      setLastGoodMem(cacheKey, body, clientHeaders);
      await cache.put(cacheUrl, new Response(body, { headers: cacheHeaders, status: 200 }));
      await D1.upsertLastKnownGood(db, link.operator_id, token, body, JSON.stringify(cacheHeaders));
      await D1.logAudit(db, {
        operator_id: link.operator_id,
        event_type: "subscription_fetch",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 200,
        meta_json: JSON.stringify({ cache: "origin", request_id: requestId }),
      });
      if (settings?.notify_fetches !== 0) {
        const last = settings?.last_fetch_notify_at ? Date.parse(settings.last_fetch_notify_at) : 0;
        if (Date.now() - last > APP.notifyFetchIntervalMs) {
          await AuditService.notifyOperator(env, settings, `🧊 اشتراک دریافت شد: <b>${safeHtml(token)}</b>`);
          await D1.updateSettings(db, link.operator_id, { last_fetch_notify_at: nowIso() });
        }
      }
      return new Response(body, { headers: clientHeaders });
    }

    const lastGoodMem = getLastGoodMem(cacheKey);
    if (lastGoodMem) return new Response(lastGoodMem.body, { headers: { ...lastGoodMem.headers, "x-request-id": requestId } });

    const lastGood = await D1.getLastKnownGood(db, link.operator_id, token);
    if (lastGood?.body_b64) {
      let headersParsed = DEFAULT_HEADERS;
      try {
        headersParsed = lastGood.headers_json ? JSON.parse(lastGood.headers_json) : DEFAULT_HEADERS;
      } catch {
        headersParsed = DEFAULT_HEADERS;
      }
      return new Response(lastGood.body_b64, { headers: { ...headersParsed, "x-request-id": requestId } });
    }
    return new Response(utf8SafeEncode("# upstream_invalid"), {
      headers: { ...DEFAULT_HEADERS, "x-request-id": requestId },
      status: 200,
    });
  },
  handleRedirect(url) {
    const target = url.searchParams.get("target") || "";
    if (!target) return new Response("bad request", { status: 400 });
    if (target.length > APP.maxRedirectTargetBytes || hasCRLF(target)) return new Response("blocked", { status: 400 });
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return new Response("invalid", { status: 400 });
    }
    if (!SAFE_REDIRECT_SCHEMES.includes(parsed.protocol.replace(":", ""))) return new Response("blocked", { status: 403 });
    if (parsed.protocol === "https:" && isBlockedHost(parsed.hostname)) return new Response("blocked", { status: 403 });
    return Response.redirect(parsed.toString(), 302);
  },
  async handleVerifyDomain(request, env, url) {
    const domainId = url.pathname.split("/").pop();
    const token = url.searchParams.get("token");
    if (!domainId || !token) return jsonResponse({ ok: false, error: "missing" }, 400);
    const domain = await D1.getDomainById(env.DB, domainId);
    if (!domain || domain.token !== token) return jsonResponse({ ok: false, error: "unauthorized" }, 403);
    const doh = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain.domain)}&type=TXT`;
    const res = await fetch(doh, { headers: { accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).map((ans) => ans.data.replace(/"/g, ""));
    const match = answers.some((value) => value.includes(token));
    if (match) {
      await D1.updateDomainVerified(env.DB, domainId, true);
    }
    return jsonResponse({ ok: match, domain: domain.domain });
  },
  async handleHealth(env) {
    let dbOk = true;
    let operators = [];
    try {
      await env.DB.prepare("SELECT 1").first();
      const rows = await env.DB
        .prepare("SELECT operator_id, last_upstream_status, last_upstream_at FROM operator_settings ORDER BY last_upstream_at DESC LIMIT 5")
        .all();
      operators = rows?.results || [];
    } catch {
      dbOk = false;
    }
    const payload = {
      status: "ok",
      version: APP.version,
      db: dbOk ? "ok" : "error",
      cache: { memory: SUB_CACHE.size, last_good: LAST_GOOD_MEM.size },
      last_upstream: operators,
    };
    return jsonResponse(payload);
  },
  async handleHealthFull(env) {
    let dbOk = true;
    let operators = [];
    let errors = [];
    try {
      await env.DB.prepare("SELECT 1").first();
      const rows = await env.DB
        .prepare("SELECT operator_id, last_upstream_status, last_upstream_at FROM operator_settings ORDER BY last_upstream_at DESC LIMIT 5")
        .all();
      operators = rows?.results || [];
      const errRows = await env.DB.prepare("SELECT event_type, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 5").all();
      errors = errRows?.results || [];
    } catch {
      dbOk = false;
    }
    const payload = {
      status: "ok",
      version: APP.version,
      db: dbOk ? "ok" : "error",
      cache: { memory: SUB_CACHE.size, last_good: LAST_GOOD_MEM.size },
      last_upstream: operators,
      last_errors: errors,
    };
    return jsonResponse(payload);
  },
  handleLanding(request, env) {
    const base = getBaseUrl(request, env);
    const botUsername = env.TELEGRAM_BOT_USERNAME || "";
    const html = `<!doctype html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>مدیریت اشتراک اپراتورها</title>
  <style>
    body { margin:0; font-family: "Vazirmatn", system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }
    .wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
    .card { max-width:720px; width:100%; background: rgba(255,255,255,0.08); border-radius: 24px; padding: 32px; backdrop-filter: blur(12px); box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
    h1 { margin-top:0; font-size: 28px; }
    .glass-btn { display:inline-flex; align-items:center; gap:8px; padding:12px 20px; border-radius: 999px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); color:#fff; text-decoration:none; }
    .grid { display:flex; flex-wrap:wrap; gap:12px; margin-top: 20px; }
    .muted { color: rgba(226,232,240,0.7); }
    .panel { margin-top: 18px; padding: 16px; background: rgba(15,23,42,0.6); border-radius: 16px; }
    input { width:100%; padding:10px 12px; border-radius: 12px; border:1px solid rgba(255,255,255,0.2); background: rgba(15,23,42,0.6); color: #fff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>پنل اشتراک برند برای اپراتورها</h1>
      <p class="muted">ورود از طریق Telegram Login Widget و کد دعوت مدیر.</p>
      <div class="panel">
        <div id="telegram-login"></div>
        <p class="muted">کد دعوت (اختیاری)</p>
        <input id="invite-code" placeholder="Invite code" />
      </div>
      <div class="grid">
        <a class="glass-btn" href="https://t.me/${botUsername}">🧊 ورود از تلگرام</a>
        <a class="glass-btn" href="${base}/health">🧊 وضعیت سلامت</a>
      </div>
    </div>
  </div>
  <script>
    const inviteInput = document.getElementById('invite-code');
    window.onTelegramAuth = async (user) => {
      const payload = { ...user, invite_code: inviteInput.value || undefined };
      const res = await fetch('${base}/auth/telegram', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.ok) {
        alert('ورود موفق: ' + data.status);
      } else {
        alert('خطا: ' + data.error);
      }
    };
  </script>
  <script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="${botUsername}" data-size="large" data-userpic="false" data-onauth="onTelegramAuth(user)" data-request-access="write"></script>
</body>
</html>`;
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
};

export const TestUtils = {
  stableDedupe,
  sanitizeLines,
  limitOutput,
  assertSafeUpstream,
  SubscriptionAssembler,
};

export default {
  async fetch(request, env) {
    try {
      return await Router.handle(request, env);
    } catch (err) {
      Logger.error("Unhandled error", err);
      return new Response("server error", { status: 500 });
    }
  },
};
