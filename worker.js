/**
 * Cloudflare Worker: Operator Subscription Manager
 * Required env vars:
 * TELEGRAM_TOKEN, TELEGRAM_SECRET(optional), LOG_CHANNEL_ID(optional), ADMIN_IDS,
 * UPSTREAM_BASE(optional), UPSTREAM_HOST(optional), BASE_URL(optional)
 */

const APP = {
  name: "Operator Subscription Manager",
  version: "2.0.0",
  cacheTtlMs: 60_000,
  cacheMaxEntries: 1000,
  rateLimitWindowMs: 10_000,
  rateLimitMax: 20,
};

// =============================
// Types & Constants
// =============================
const GLASS = "🧊";
const GLASS_BTN = (label) => `${GLASS} ${label}`;
const SAFE_REDIRECT_SCHEMES = ["v2rayng", "sn", "streisand", "v2box", "https"];
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

const isValidDomain = (value) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);

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

const sanitizeLines = (lines, blockedKeywords = []) => {
  const blockedSet = blockedKeywords.map((item) => item.toLowerCase());
  return lines.filter((line) => {
    const lower = line.toLowerCase();
    if (!line) return false;
    if (line.startsWith("#")) return false;
    if (blockedSet.some((kw) => kw && lower.includes(kw))) return false;
    return true;
  });
};

// =============================
// Data Access Layer (D1 queries)
// =============================
const D1 = {
  async getOperatorByTelegramId(db, telegramUserId) {
    return db.prepare("SELECT * FROM operators WHERE telegram_user_id = ?").bind(telegramUserId).first();
  },
  async listOperators(db) {
    return db.prepare("SELECT * FROM operators ORDER BY created_at DESC").all();
  },
  async createOperator(db, telegramUserId, displayName) {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO operators (id, telegram_user_id, display_name, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)"
      )
      .bind(id, telegramUserId, displayName || null, nowIso(), nowIso())
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
      .prepare("INSERT INTO share_links (id, operator_id, public_token, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
      .bind(crypto.randomUUID(), id, crypto.randomUUID(), nowIso(), nowIso())
      .run();
    return this.getOperatorByTelegramId(db, telegramUserId);
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
  async listDomains(db, operatorId) {
    return db
      .prepare("SELECT * FROM operator_domains WHERE operator_id = ? AND deleted_at IS NULL ORDER BY created_at DESC")
      .bind(operatorId)
      .all();
  },
  async createDomain(db, operatorId, domain) {
    await db
      .prepare(
        "INSERT INTO operator_domains (id, operator_id, domain, verified, verification_token, is_active, created_at, updated_at) VALUES (?, ?, ?, 0, ?, 1, ?, ?)"
      )
      .bind(crypto.randomUUID(), operatorId, domain, crypto.randomUUID(), nowIso(), nowIso())
      .run();
  },
  async setDomainActive(db, operatorId, domainId) {
    await db
      .prepare("UPDATE operator_settings SET active_domain_id = ?, updated_at = ? WHERE operator_id = ?")
      .bind(domainId, nowIso(), operatorId)
      .run();
    await db
      .prepare("UPDATE operator_domains SET is_active = 0 WHERE operator_id = ?")
      .bind(operatorId)
      .run();
    await db
      .prepare("UPDATE operator_domains SET is_active = 1 WHERE id = ? AND operator_id = ?")
      .bind(domainId, operatorId)
      .run();
  },
  async getDomainById(db, domainId) {
    return db.prepare("SELECT * FROM operator_domains WHERE id = ? AND deleted_at IS NULL").bind(domainId).first();
  },
  async listExtraConfigs(db, operatorId) {
    return db
      .prepare("SELECT * FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL ORDER BY sort_order, created_at")
      .bind(operatorId)
      .all();
  },
  async createExtraConfig(db, operatorId, title, content) {
    await db
      .prepare(
        "INSERT INTO extra_configs (id, operator_id, title, content, is_enabled, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, ?, ?)"
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
      .prepare("UPDATE extra_configs SET is_enabled = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
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
  async getShareLinkByToken(db, token) {
    return db
      .prepare("SELECT * FROM share_links WHERE public_token = ? AND is_active = 1 AND revoked_at IS NULL")
      .bind(token)
      .first();
  },
  async getShareLinkByOperator(db, operatorId) {
    return db
      .prepare("SELECT * FROM share_links WHERE operator_id = ? AND is_active = 1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
      .bind(operatorId)
      .first();
  },
  async rotateShareLink(db, operatorId) {
    const now = nowIso();
    await db
      .prepare("UPDATE share_links SET is_active = 0, revoked_at = ?, updated_at = ? WHERE operator_id = ? AND is_active = 1")
      .bind(now, now, operatorId)
      .run();
    await db
      .prepare("INSERT INTO share_links (id, operator_id, public_token, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
      .bind(crypto.randomUUID(), operatorId, crypto.randomUUID(), now, now)
      .run();
    return this.getShareLinkByOperator(db, operatorId);
  },
  async upsertLastKnownGood(db, operatorId, token, bodyB64, headersJson) {
    await db
      .prepare(
        "INSERT INTO last_known_good (operator_id, public_token, body_b64, headers_json, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(operator_id, public_token) DO UPDATE SET body_b64 = excluded.body_b64, headers_json = excluded.headers_json, updated_at = excluded.updated_at"
      )
      .bind(operatorId, token, bodyB64, headersJson, nowIso())
      .run();
  },
  async getLastKnownGood(db, operatorId, token) {
    return db
      .prepare("SELECT * FROM last_known_good WHERE operator_id = ? AND public_token = ?")
      .bind(operatorId, token)
      .first();
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
    return db
      .prepare("SELECT * FROM audit_logs WHERE operator_id = ? ORDER BY created_at DESC LIMIT ?")
      .bind(operatorId, limit)
      .all();
  },
};

// =============================
// Domain Services
// =============================
const OperatorService = {
  async ensureOperator(db, telegramUser, env) {
    let operator = await D1.getOperatorByTelegramId(db, telegramUser.id);
    if (!operator && isAdmin(telegramUser.id, env)) {
      operator = await D1.createOperator(db, telegramUser.id, telegramUser.first_name || telegramUser.username);
    }
    if (!operator || operator.status !== "active") return null;
    await D1.touchOperator(db, operator.id);
    return operator;
  },
  async getShareLink(db, operator, baseUrl) {
    const settings = await D1.getSettings(db, operator.id);
    const share = await D1.getShareLinkByOperator(db, operator.id);
    let hostBase = baseUrl;
    if (settings?.active_domain_id) {
      const domain = await D1.getDomainById(db, settings.active_domain_id);
      if (domain?.domain) hostBase = `https://${domain.domain}`;
    }
    return `${hostBase.replace(/\/$/, "")}/sub/${share?.public_token || ""}`;
  },
};

const SubscriptionAssembler = {
  async assemble(env, db, operatorId, token, request) {
    const settings = await D1.getSettings(db, operatorId);
    const rules = await D1.getRules(db, operatorId);
    const extras = await D1.listExtraConfigs(db, operatorId);

    const upstreamUrl = this.resolveUpstream(settings?.upstream_url, env);
    const upstreamResponse = await this.fetchUpstream(upstreamUrl);
    const upstreamText = this.decodeSubscription(upstreamResponse.body, upstreamResponse.isBase64);

    if (!upstreamResponse.ok || !isValidSubscriptionText(upstreamText)) {
      await D1.logAudit(db, {
        operator_id: operatorId,
        event_type: "upstream_invalid",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: upstreamResponse.status,
        meta_json: JSON.stringify({ reason: "upstream_invalid" }),
      });
      await AuditService.notifyOperator(env, settings, `⚠️ آپ‌استریم نامعتبر بود برای <b>${safeHtml(settings?.branding || "اپراتور")}</b>`);
      return {
        body: "",
        headers: { ...DEFAULT_HEADERS, "x-sub-status": "upstream_invalid" },
        valid: false,
      };
    }

    const extrasContent = (extras?.results || [])
      .filter((item) => item.is_enabled)
      .map((item) => item.content)
      .join("\n");

    const merged = this.mergeContent(upstreamText, extrasContent, rules);
    const processed = this.applyRules(merged, rules);
    const encoded = utf8SafeEncode(processed);

    return {
      body: encoded,
      headers: {
        ...DEFAULT_HEADERS,
        ...(upstreamResponse.subscriptionUserinfo ? { "subscription-userinfo": upstreamResponse.subscriptionUserinfo } : {}),
      },
      valid: true,
    };
  },
  resolveUpstream(input, env) {
    if (!input) return "";
    if (/^https?:\/\//i.test(input)) return input;
    if (env.UPSTREAM_BASE) return `${env.UPSTREAM_BASE.replace(/\/$/, "")}/${input}`;
    if (env.UPSTREAM_HOST) return `https://${env.UPSTREAM_HOST.replace(/\/$/, "")}/${input}`;
    return input;
  },
  async fetchUpstream(upstreamUrl) {
    if (!upstreamUrl) return { ok: false, status: 400, body: "", subscriptionUserinfo: null, isBase64: false };
    try {
      const res = await fetch(upstreamUrl, { cf: { cacheTtl: 0 } });
      const text = await res.text();
      return {
        ok: res.ok,
        status: res.status,
        body: text,
        subscriptionUserinfo: res.headers.get("subscription-userinfo"),
        isBase64: looksLikeBase64(text),
      };
    } catch (err) {
      Logger.warn("Upstream fetch failed", { error: err?.message });
      return { ok: false, status: 502, body: "", subscriptionUserinfo: null, isBase64: false };
    }
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
    if (rules?.dedupe !== 0) processed = Array.from(new Set(processed));
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

// =============================
// Telegram Adapter
// =============================
const Telegram = {
  async handleWebhook(request, env) {
    if (env.TELEGRAM_SECRET) {
      const secret = request.headers.get("x-telegram-bot-api-secret-token");
      if (secret !== env.TELEGRAM_SECRET) return new Response("unauthorized", { status: 401 });
    }
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (!rateLimit(`tg:${ip}`)) return new Response("rate limit", { status: 429 });

    const update = await request.json();
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

    if (text.startsWith("/start") || text.startsWith("/panel")) {
      const payload = await this.buildPanel(db, operator, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/set_upstream")) {
      const value = text.replace("/set_upstream", "").trim();
      if (!value) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /set_upstream لینک_پنل یا توکن");
        return new Response("ok");
      }
      await D1.updateSettings(db, operator.id, { upstream_url: value });
      await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update", meta_json: JSON.stringify({ field: "upstream_url" }) });
      const updatedSettings = await D1.getSettings(db, operator.id);
      await AuditService.notifyOperator(env, updatedSettings, `🧊 آپ‌استریم بروزرسانی شد برای <b>${safeHtml(operator.display_name || "اپراتور")}</b>`);
      await this.sendMessage(env, message.chat.id, "✅ لینک آپ‌استریم ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/set_domain")) {
      const domain = text.replace("/set_domain", "").trim();
      if (!domain) {
        await this.sendMessage(env, message.chat.id, "❗️دامنه را وارد کنید.");
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
      await D1.logAudit(db, { operator_id: operator.id, event_type: "domain_update", meta_json: JSON.stringify({ domain }) });
      const updatedSettings = await D1.getSettings(db, operator.id);
      await AuditService.notifyOperator(env, updatedSettings, `🧊 دامنه ثبت شد: <b>${safeHtml(domain)}</b>`);
      const token = latest?.verification_token ? `\nتوکن تایید: <code>${safeHtml(latest.verification_token)}</code>` : "";
      const guide = "\nراهنما: یک رکورد TXT روی دامنه با مقدار بالا ثبت کنید.";
      await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد و به عنوان فعال تنظیم گردید.${token}${guide}`);
      return new Response("ok");
    }
    if (text.startsWith("/set_channel")) {
      const channelId = text.replace("/set_channel", "").trim();
      if (!channelId) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /set_channel -1001234567890");
        return new Response("ok");
      }
      await D1.updateSettings(db, operator.id, { channel_id: channelId });
      await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update", meta_json: JSON.stringify({ field: "channel_id" }) });
      await AuditService.notifyOperator(env, { channel_id: channelId }, `🧊 کانال اطلاع‌رسانی تنظیم شد.`);
      await this.sendMessage(env, message.chat.id, "✅ کانال اطلاع‌رسانی ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/extras")) {
      const payload = await this.buildExtrasPanel(db, operator);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/add_extra")) {
      const content = text.replace("/add_extra", "").trim();
      if (!content) {
        await this.sendMessage(env, message.chat.id, "❗️بعد از دستور متن کانفیگ را بفرستید.");
        return new Response("ok");
      }
      await D1.createExtraConfig(db, operator.id, "افزودنی", content);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update", meta_json: JSON.stringify({ action: "add" }) });
      await AuditService.notifyOperator(env, settings, `🧊 افزودنی جدید ثبت شد برای <b>${safeHtml(operator.display_name || "اپراتور")}</b>`);
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
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update", meta_json: JSON.stringify({ action: "edit" }) });
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
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /set_rules merge=append dedupe=1 sanitize=1 prefix=VIP_ keywords=ads,spam");
        return new Response("ok");
      }
      await D1.updateRules(db, operator.id, patch);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "rules_update", meta_json: JSON.stringify(patch) });
      await AuditService.notifyOperator(env, settings, "🧊 قوانین اشتراک بروزرسانی شد.");
      await this.sendMessage(env, message.chat.id, "✅ قوانین ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/link")) {
      const payload = await this.buildLinkPanel(db, operator, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/rotate")) {
      const share = await D1.rotateShareLink(db, operator.id);
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
        .map((item) => `• ${safeHtml(item.display_name || item.telegram_user_id)} (${safeHtml(item.telegram_user_id)}) - ${safeHtml(item.status)}`) 
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
        await D1.createOperator(db, targetId, "Operator");
      }
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_add_operator", meta_json: JSON.stringify({ targetId }) });
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
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_remove_operator", meta_json: JSON.stringify({ targetId }) });
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
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update", meta_json: JSON.stringify({ action: "toggle" }) });
      await this.sendMessage(env, chatId, "✅ وضعیت افزودنی تغییر کرد.");
      return new Response("ok");
    }
    if (action === "delete_extra" && data.id) {
      await D1.deleteExtraConfig(db, operator.id, data.id);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update", meta_json: JSON.stringify({ action: "delete" }) });
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
      const payload = await this.buildExtrasPanel(db, operator);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_rules") {
      const payload = await this.buildRulesPanel(db, operator);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_channel") {
      await this.sendMessage(env, chatId, "برای تنظیم کانال اطلاع‌رسانی:\n<code>/set_channel -100xxxxxxxxxx</code>");
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
    const activeDomain = (domains?.results || []).find((item) => item.is_active);
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
    `.trim();

    const keyboard = {
      inline_keyboard: [
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
    const text = `
${GLASS} <b>لینک اشتراک برند شما</b>

<code>${safeHtml(link)}</code>

با دکمه‌های زیر، لینک را مستقیم داخل اپلیکیشن‌های محبوب باز کنید.
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [
          { text: GLASS_BTN("کپی لینک"), url: `https://t.me/share/url?url=${encodeURIComponent(link)}` },
          { text: GLASS_BTN("پیش‌نمایش"), url: link },
        ],
        [
          {
            text: GLASS_BTN("v2rayNG"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2rayng://install-config?url=${link}#${operator.display_name || "Sub"}`)}`,
          },
          {
            text: GLASS_BTN("NekoBox"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`sn://subscription?url=${link}&name=${operator.display_name || "Sub"}`)}`,
          },
        ],
        [
          {
            text: GLASS_BTN("Streisand"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`streisand://import/${link}`)}`,
          },
          {
            text: GLASS_BTN("v2Box"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2box://install-sub?url=${link}&name=${operator.display_name || "Sub"}`)}`,
          },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildExtrasPanel(db, operator) {
    const extras = await D1.listExtraConfigs(db, operator.id);
    const list = (extras?.results || [])
      .map((item) => `• ${safeHtml(item.title || "افزودنی")} (${safeHtml(item.id)}) ${item.is_enabled ? "✅" : "⛔️"}`)
      .join("\n");
    const text = `
${GLASS} <b>افزودنی‌ها</b>

${list || "فعلاً موردی ثبت نشده."}

برای افزودن:
<code>/add_extra متن_کانفیگ</code>
برای ویرایش:
<code>/edit_extra شناسه متن_جدید</code>
    `.trim();
    const keyboard = {
      inline_keyboard: (extras?.results || []).flatMap((item) => [
        [
          {
            text: GLASS_BTN(item.is_enabled ? "غیرفعال" : "فعال"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "toggle_extra", id: item.id, enabled: !item.is_enabled })),
          },
          {
            text: GLASS_BTN("حذف"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "delete_extra", id: item.id })),
          },
        ],
      ]),
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

برای تغییر سریع از دکمه‌ها یا دستور زیر استفاده کنید:
<code>/set_rules merge=append dedupe=1 sanitize=1 prefix=VIP_ keywords=ads,spam</code>
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [
          {
            text: GLASS_BTN("ادغام + حذف تکراری"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "append_dedupe", dedupe: 1 } })),
          },
          {
            text: GLASS_BTN("فقط اپ‌استریم"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "upstream_only" } })),
          },
        ],
        [
          {
            text: GLASS_BTN("فقط افزودنی‌ها"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { merge_policy: "extras_only" } })),
          },
          {
            text: GLASS_BTN("پاکسازی خاموش"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", patch: { sanitize: 0 } })),
          },
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
    if (request.method === "GET" && url.pathname.startsWith("/sub/")) {
      const token = url.pathname.split("/").pop();
      return this.handleSubscription(request, env, token);
    }
    if (request.method === "GET" && url.pathname === "/redirect") {
      return this.handleRedirect(url);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok", version: APP.version }), { headers: JSON_HEADERS });
    }
    if (request.method === "GET" && url.pathname === "/") {
      return this.handleLanding(request, env);
    }
    return new Response("not found", { status: 404 });
  },
  async handleSubscription(request, env, token) {
    const cacheKey = `sub:${token}`;
    const cached = getCachedSub(cacheKey);
    if (cached) return new Response(cached.body, { headers: cached.headers });

    const db = env.DB;
    const link = await D1.getShareLinkByToken(db, token);
    if (!link) return new Response("not found", { status: 404 });

    const cacheUrl = new URL(request.url);
    const cache = caches.default;
    const cachedResponse = await cache.match(cacheUrl);
    if (cachedResponse) {
      const body = await cachedResponse.text();
      const headers = Object.fromEntries(cachedResponse.headers.entries());
      setCachedSub(cacheKey, body, headers);
      return new Response(body, { headers });
    }

    const { body, headers, valid } = await SubscriptionAssembler.assemble(env, db, link.operator_id, token, request);
    const responseHeaders = { ...headers, "content-disposition": `inline; filename=sub_${token}.txt` };
    if (valid) {
      setCachedSub(cacheKey, body, responseHeaders);
      setLastGoodMem(cacheKey, body, responseHeaders);
      await cache.put(cacheUrl, new Response(body, { headers: responseHeaders, status: 200 }));
      await D1.upsertLastKnownGood(db, link.operator_id, token, utf8SafeEncode(body), JSON.stringify(responseHeaders));
      await D1.logAudit(db, {
        operator_id: link.operator_id,
        event_type: "subscription_fetch",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 200,
      });
      const settings = await D1.getSettings(db, link.operator_id);
      await AuditService.notifyOperator(env, settings, `🧊 اشتراک دریافت شد: <b>${safeHtml(token)}</b>`);
      return new Response(body, { headers: responseHeaders });
    }

    const lastGoodMem = getLastGoodMem(cacheKey);
    if (lastGoodMem) return new Response(lastGoodMem.body, { headers: lastGoodMem.headers });

    const lastGood = await D1.getLastKnownGood(db, link.operator_id, token);
    if (lastGood?.body_b64) {
      let headersParsed = DEFAULT_HEADERS;
      try {
        headersParsed = lastGood.headers_json ? JSON.parse(lastGood.headers_json) : DEFAULT_HEADERS;
      } catch {
        headersParsed = DEFAULT_HEADERS;
      }
      return new Response(utf8SafeDecode(lastGood.body_b64), { headers: headersParsed });
    }
    return new Response(utf8SafeEncode("# upstream_invalid"), {
      headers: { ...DEFAULT_HEADERS, "x-sub-status": "empty" },
      status: 200,
    });
  },
  handleRedirect(url) {
    const target = url.searchParams.get("target");
    if (!target) return new Response("bad request", { status: 400 });
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return new Response("invalid", { status: 400 });
    }
    if (!SAFE_REDIRECT_SCHEMES.includes(parsed.protocol.replace(":", ""))) {
      return new Response("blocked", { status: 403 });
    }
    return Response.redirect(parsed.toString(), 302);
  },
  handleLanding(request, env) {
    const base = getBaseUrl(request, env);
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
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>پنل اشتراک برند برای اپراتورها</h1>
      <p class="muted">این سرویس فقط برای اپراتورهاست و کاربران نهایی با ربات تعامل ندارند.</p>
      <div class="grid">
        <a class="glass-btn" href="https://t.me/">🧊 ورود اپراتور</a>
        <a class="glass-btn" href="${base}/health">🧊 وضعیت سلامت</a>
      </div>
    </div>
  </div>
</body>
</html>`;
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
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
