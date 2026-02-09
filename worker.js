/**
 * Cloudflare Worker: Personal Subscription Manager
 * Required env vars:
 * TELEGRAM_TOKEN, TELEGRAM_SECRET(optional), LOG_CHANNEL_ID, ADMIN_IDS,
 * UPSTREAM_BASE(optional), UPSTREAM_HOST(optional), BASE_URL(optional)
 */

const APP = {
  name: "Haydenet Personal Sub Manager",
  version: "1.0.0",
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
const LAST_GOOD = new Map();
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

const isValidDomain = (value) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);

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

const isAllowedUser = (userId, env) => {
  const allowList = parseCommaList(env.USER_ALLOWLIST || env.ALLOWLIST_IDS);
  if (!allowList.length) return true;
  return allowList.includes(String(userId));
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

const setLastGood = (key, body, headers) => {
  if (LAST_GOOD.size > APP.cacheMaxEntries) LAST_GOOD.clear();
  LAST_GOOD.set(key, { body, headers, timestamp: Date.now() });
};

const getLastGood = (key) => LAST_GOOD.get(key);

const parseMessageText = (message) => message?.text?.trim() || "";

const decodeCallbackData = (data) => {
  try {
    return JSON.parse(utf8SafeDecode(data));
  } catch {
    return { action: data };
  }
};

// =============================
// Data Access Layer (D1 queries)
// =============================
const D1 = {
  async getUserByTelegramId(db, telegramUserId) {
    return db.prepare("SELECT * FROM users WHERE telegram_user_id = ?").bind(telegramUserId).first();
  },
  async createUser(db, telegramUserId, username, displayName) {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO users (id, telegram_user_id, telegram_username, display_name, status, created_at, updated_at, last_seen_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)"
      )
      .bind(id, telegramUserId, username || null, displayName || null, nowIso(), nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO user_settings (user_id, created_at, updated_at) VALUES (?, ?, ?)")
      .bind(id, nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO subscription_rules (user_id, created_at, updated_at) VALUES (?, ?, ?)")
      .bind(id, nowIso(), nowIso())
      .run();
    await db
      .prepare("INSERT INTO share_links (id, user_id, public_token, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
      .bind(crypto.randomUUID(), id, crypto.randomUUID(), nowIso(), nowIso())
      .run();
    return this.getUserByTelegramId(db, telegramUserId);
  },
  async touchUser(db, userId) {
    await db.prepare("UPDATE users SET last_seen_at = ?, updated_at = ? WHERE id = ?").bind(nowIso(), nowIso(), userId).run();
  },
  async updateUserStatus(db, telegramUserId, status) {
    await db
      .prepare("UPDATE users SET status = ?, updated_at = ? WHERE telegram_user_id = ?")
      .bind(status, nowIso(), telegramUserId)
      .run();
  },
  async getSettings(db, userId) {
    return db.prepare("SELECT * FROM user_settings WHERE user_id = ?").bind(userId).first();
  },
  async updateSettings(db, userId, patch) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await db
      .prepare(`UPDATE user_settings SET ${setClause}, updated_at = ? WHERE user_id = ?`)
      .bind(...values, nowIso(), userId)
      .run();
  },
  async getRules(db, userId) {
    return db.prepare("SELECT * FROM subscription_rules WHERE user_id = ?").bind(userId).first();
  },
  async updateRules(db, userId, patch) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await db
      .prepare(`UPDATE subscription_rules SET ${setClause}, updated_at = ? WHERE user_id = ?`)
      .bind(...values, nowIso(), userId)
      .run();
  },
  async listExtraConfigs(db, userId) {
    return db
      .prepare("SELECT * FROM extra_configs WHERE user_id = ? AND deleted_at IS NULL ORDER BY sort_order, created_at")
      .bind(userId)
      .all();
  },
  async createExtraConfig(db, userId, title, content) {
    await db
      .prepare(
        "INSERT INTO extra_configs (id, user_id, title, content, is_enabled, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, ?, ?)"
      )
      .bind(crypto.randomUUID(), userId, title || null, content, nowIso(), nowIso())
      .run();
  },
  async updateExtraConfig(db, userId, configId, content) {
    await db
      .prepare("UPDATE extra_configs SET content = ?, updated_at = ? WHERE id = ? AND user_id = ?")
      .bind(content, nowIso(), configId, userId)
      .run();
  },
  async deleteExtraConfig(db, userId, configId) {
    await db
      .prepare("UPDATE extra_configs SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?")
      .bind(nowIso(), nowIso(), configId, userId)
      .run();
  },
  async listDomains(db, userId) {
    return db
      .prepare("SELECT * FROM user_domains WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at")
      .bind(userId)
      .all();
  },
  async getDomainById(db, domainId) {
    return db.prepare("SELECT * FROM user_domains WHERE id = ? AND deleted_at IS NULL").bind(domainId).first();
  },
  async setDomainActive(db, userId, domainId) {
    await db.prepare("UPDATE user_settings SET domain_active_id = ?, updated_at = ? WHERE user_id = ?").bind(domainId, nowIso(), userId).run();
  },
  async createDomain(db, userId, domain) {
    await db
      .prepare(
        "INSERT INTO user_domains (id, user_id, domain, is_verified, verification_method, verification_token, created_at, updated_at) VALUES (?, ?, ?, 0, 'dns', ?, ?, ?)"
      )
      .bind(crypto.randomUUID(), userId, domain, crypto.randomUUID(), nowIso(), nowIso())
      .run();
  },
  async getShareLinkByToken(db, token) {
    return db
      .prepare("SELECT * FROM share_links WHERE public_token = ? AND is_active = 1 AND revoked_at IS NULL")
      .bind(token)
      .first();
  },
  async getShareLinkByUser(db, userId) {
    return db
      .prepare("SELECT * FROM share_links WHERE user_id = ? AND is_active = 1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
      .bind(userId)
      .first();
  },
  async rotateShareLink(db, userId) {
    const now = nowIso();
    await db
      .prepare("UPDATE share_links SET is_active = 0, revoked_at = ?, updated_at = ? WHERE user_id = ? AND is_active = 1")
      .bind(now, now, userId)
      .run();
    await db
      .prepare("INSERT INTO share_links (id, user_id, public_token, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
      .bind(crypto.randomUUID(), userId, crypto.randomUUID(), now, now)
      .run();
    return this.getShareLinkByUser(db, userId);
  },
  async logAudit(db, payload) {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO audit_logs (id, user_id, public_token, event_type, ip, country, user_agent, request_path, response_status, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        id,
        payload.user_id || null,
        payload.public_token || null,
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
  async listAuditLogs(db, userId, limit = 5) {
    return db
      .prepare("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?")
      .bind(userId, limit)
      .all();
  },
  async setBotSetting(db, key, value) {
    await db
      .prepare("INSERT INTO bot_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .bind(key, value, nowIso())
      .run();
  },
  async getBotSetting(db, key) {
    return db.prepare("SELECT * FROM bot_settings WHERE key = ?").bind(key).first();
  },
};

// =============================
// Domain Services
// =============================
const OnboardingService = {
  async ensureUser(db, telegramUser) {
    let user = await D1.getUserByTelegramId(db, telegramUser.id);
    if (!user) {
      user = await D1.createUser(db, telegramUser.id, telegramUser.username, telegramUser.first_name);
    }
    await D1.touchUser(db, user.id);
    return user;
  },
  async getProgress(db, userId) {
    const settings = await D1.getSettings(db, userId);
    const share = await D1.getShareLinkByUser(db, userId);
    const extras = await D1.listExtraConfigs(db, userId);
    const rules = await D1.getRules(db, userId);
    const domainReady = Boolean(settings?.domain_active_id);
    return {
      settings,
      share,
      extrasCount: extras?.results?.length || 0,
      rules,
      steps: {
        A: Boolean(settings?.mainstream_name && settings?.upstream_url),
        B: true,
        C: domainReady,
        D: (extras?.results?.length || 0) > 0,
        E: Boolean(rules),
      },
    };
  },
};

const SubscriptionAssembler = {
  async assemble(env, db, userId, token, request) {
    const settings = await D1.getSettings(db, userId);
    const rules = await D1.getRules(db, userId);
    const extras = await D1.listExtraConfigs(db, userId);

    const upstreamUrl = settings?.upstream_url;
    const upstreamContent = await this.fetchUpstream(upstreamUrl, env, token);
    const extrasContent = (extras?.results || [])
      .filter((item) => item.is_enabled)
      .map((item) => item.content)
      .join("\n");

    let merged = this.mergeContent(upstreamContent, extrasContent, rules);
    merged = this.applyRules(merged, rules);

    await D1.logAudit(db, {
      user_id: userId,
      public_token: token,
      event_type: "subscription_fetch",
      ip: request.headers.get("cf-connecting-ip"),
      country: request.headers.get("cf-ipcountry"),
      user_agent: request.headers.get("user-agent"),
      request_path: new URL(request.url).pathname,
      response_status: 200,
      meta_json: JSON.stringify({ extras: extras?.results?.length || 0, rules: rules?.merge_policy || null }),
    });

    return merged;
  },
  async fetchUpstream(upstreamUrl, env, token) {
    if (!upstreamUrl) return "";
    try {
      const res = await fetch(upstreamUrl, { cf: { cacheTtl: 0 } });
      if (!res.ok) return "";
      return await res.text();
    } catch (err) {
      Logger.warn("Upstream fetch failed", { token, error: err?.message });
      return "";
    }
  },
  mergeContent(upstream, extras, rules) {
    const policy = rules?.merge_policy || "append";
    if (policy === "upstream_only") return upstream || "";
    if (policy === "extras_only") return extras || "";
    if (policy === "replace") return extras || "";
    const combined = [upstream, extras].filter(Boolean).join("\n");
    return combined;
  },
  applyRules(content, rules) {
    const lines = content
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const dedupe = rules?.dedupe !== 0;
    const sanitize = rules?.sanitize !== 0;
    let processed = lines;
    if (sanitize) processed = processed.filter((line) => !line.startsWith("#"));
    if (dedupe) processed = Array.from(new Set(processed));
    if (rules?.naming_mode === "prefix" && rules?.naming_prefix) {
      processed = processed.map((line) => `${rules.naming_prefix}${line}`);
    }
    return processed.join("\n");
  },
};

const AuditService = {
  async notifyTelegram(env, messageHtml) {
    if (!env.LOG_CHANNEL_ID || !env.TELEGRAM_TOKEN) return;
    try {
      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: env.LOG_CHANNEL_ID,
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
    if (!isAllowedUser(user.id, env)) {
      await this.sendMessage(env, user.id, "⚠️ دسترسی شما در حال حاضر فعال نیست.");
      return new Response("ok");
    }

    const db = env.DB;
    const userRecord = await OnboardingService.ensureUser(db, user);
    if (userRecord.status === "banned") {
      await this.sendMessage(env, user.id, "⛔️ دسترسی شما مسدود شده است.");
      return new Response("ok");
    }

    if (update.message) {
      return this.handleMessage(env, db, userRecord, update.message);
    }
    if (update.callback_query) {
      return this.handleCallback(env, db, userRecord, update.callback_query);
    }
    return new Response("ok");
  },
  async handleMessage(env, db, userRecord, message) {
    const text = parseMessageText(message);
    if (text.startsWith("/start")) {
      const progress = await OnboardingService.getProgress(db, userRecord.id);
      const payload = this.buildOnboardingMessage(progress, userRecord, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      await AuditService.notifyTelegram(env, `🧊 کاربر جدید: <b>${safeHtml(userRecord.display_name || "بدون نام")}</b>`);
      return new Response("ok");
    }
    if (text.startsWith("/panel")) {
      const payload = await this.buildPanel(db, userRecord, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/domain")) {
      const payload = await this.buildDomainPanel(db, userRecord, env);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/extras")) {
      const payload = await this.buildExtrasPanel(db, userRecord);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/rules")) {
      const payload = await this.buildRulesPanel(db, userRecord);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/logs")) {
      const payload = await this.buildLogsPanel(db, userRecord);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/ping")) {
      await this.sendMessage(env, message.chat.id, "🟢 همه‌چیز سالم است.");
      return new Response("ok");
    }

    if (text.startsWith("/admin")) {
      if (!isAdmin(userRecord.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const payload = this.buildAdminPanel();
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (text.startsWith("/botsettings")) {
      if (!isAdmin(userRecord.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const parts = text.split(" ").slice(1);
      const [key, ...valueParts] = parts;
      const value = valueParts.join(" ").trim();
      if (!key || !value) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /botsettings کلید مقدار");
        return new Response("ok");
      }
      await D1.setBotSetting(db, key, value);
      await this.sendMessage(env, message.chat.id, "✅ تنظیمات ربات ذخیره شد.");
      return new Response("ok");
    }
    if (text.startsWith("/broadcast")) {
      if (!isAdmin(userRecord.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const messageBody = text.replace("/broadcast", "").trim();
      if (!messageBody) {
        await this.sendMessage(env, message.chat.id, "❗️متن پیام را بنویسید.");
        return new Response("ok");
      }
      await AuditService.notifyTelegram(env, `📣 اطلاعیه مدیر:\n${safeHtml(messageBody)}`);
      await this.sendMessage(env, message.chat.id, "✅ ارسال شد.");
      return new Response("ok");
    }
    if (text.startsWith("/ban")) {
      if (!isAdmin(userRecord.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const targetId = text.replace("/ban", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه کاربر را بنویسید.");
        return new Response("ok");
      }
      await D1.updateUserStatus(db, targetId, "banned");
      await this.sendMessage(env, message.chat.id, "✅ کاربر مسدود شد.");
      return new Response("ok");
    }
    if (text.startsWith("/approve")) {
      if (!isAdmin(userRecord.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.");
        return new Response("ok");
      }
      const targetId = text.replace("/approve", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه کاربر را بنویسید.");
        return new Response("ok");
      }
      await D1.updateUserStatus(db, targetId, "active");
      await this.sendMessage(env, message.chat.id, "✅ کاربر تایید شد.");
      return new Response("ok");
    }

    if (text.startsWith("/setmain")) {
      const parts = text.split(" ").slice(1);
      const [name, ...urlParts] = parts;
      const url = urlParts.join(" ");
      if (!name || !url) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /setmain نام لینک_اصلی");
        return new Response("ok");
      }
      await D1.updateSettings(db, userRecord.id, { mainstream_name: name, upstream_url: url });
      await AuditService.notifyTelegram(env, `🧊 تنظیمات آپدیت شد: <b>${safeHtml(name)}</b>`);
      await this.sendMessage(env, message.chat.id, "✅ اطلاعات مین‌استریم ذخیره شد.");
      return new Response("ok");
    }

    if (text.startsWith("/addextra")) {
      const content = text.replace("/addextra", "").trim();
      if (!content) {
        await this.sendMessage(env, message.chat.id, "❗️بعد از دستور متن کانفیگ را بفرستید.");
        return new Response("ok");
      }
      await D1.createExtraConfig(db, userRecord.id, "افزودنی", content);
      await AuditService.notifyTelegram(env, `🧊 افزودنی جدید ثبت شد برای <b>${safeHtml(userRecord.display_name || "کاربر")}</b>`);
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ اضافی ثبت شد.");
      return new Response("ok");
    }
    if (text.startsWith("/editextra")) {
      const parts = text.split(" ").slice(1);
      const [configId, ...contentParts] = parts;
      const content = contentParts.join(" ").trim();
      if (!configId || !content) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /editextra شناسه متن_جدید");
        return new Response("ok");
      }
      await D1.updateExtraConfig(db, userRecord.id, configId, content);
      await AuditService.notifyTelegram(env, `🧊 افزودنی ویرایش شد برای <b>${safeHtml(userRecord.display_name || "کاربر")}</b>`);
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ بروزرسانی شد.");
      return new Response("ok");
    }

    if (text.startsWith("/setdomain")) {
      const domain = text.replace("/setdomain", "").trim();
      if (!domain) {
        await this.sendMessage(env, message.chat.id, "❗️دامنه را وارد کنید.");
        return new Response("ok");
      }
      if (!isValidDomain(domain)) {
        await this.sendMessage(env, message.chat.id, "❗️دامنه معتبر نیست.");
        return new Response("ok");
      }
      await D1.createDomain(db, userRecord.id, domain);
      const domains = await D1.listDomains(db, userRecord.id);
      const latest = domains?.results?.slice(-1)[0];
      if (latest) await D1.setDomainActive(db, userRecord.id, latest.id);
      await AuditService.notifyTelegram(env, `🧊 دامنه ثبت شد: <b>${safeHtml(domain)}</b>`);
      await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد: ${safeHtml(domain)}`);
      return new Response("ok");
    }

    await this.sendMessage(env, message.chat.id, "❓ دستور ناشناخته. /panel را بزنید.");
    return new Response("ok");
  },
  async handleCallback(env, db, userRecord, callback) {
    const data = decodeCallbackData(callback.data || "");
    const action = data.action || "";
    const chatId = callback.message?.chat?.id;
    if (!chatId) return new Response("ok");

    if (action === "rotate_token") {
      const share = await D1.rotateShareLink(db, userRecord.id);
      const baseUrl = env.BASE_URL || "";
      const link = await this.buildShareLink(db, baseUrl, userRecord, share);
      await this.sendMessage(env, chatId, `✅ لینک جدید: <code>${safeHtml(link)}</code>`);
      return new Response("ok");
    }

    if (action === "set_rules") {
      await D1.updateRules(db, userRecord.id, { merge_policy: data.policy || "append", dedupe: data.dedupe ? 1 : 0 });
      await this.sendMessage(env, chatId, "✅ قوانین اشتراک ذخیره شد.");
      return new Response("ok");
    }

    if (action === "delete_extra" && data.id) {
      await D1.deleteExtraConfig(db, userRecord.id, data.id);
      await AuditService.notifyTelegram(env, `🧊 افزودنی حذف شد برای <b>${safeHtml(userRecord.display_name || "کاربر")}</b>`);
      await this.sendMessage(env, chatId, "🗑️ کانفیگ حذف شد.");
      return new Response("ok");
    }

    if (action === "panel_refresh") {
      const payload = await this.buildPanel(db, userRecord, env);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_extras") {
      const payload = await this.buildExtrasPanel(db, userRecord);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "panel_rules") {
      const payload = await this.buildRulesPanel(db, userRecord);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard);
      return new Response("ok");
    }
    if (action === "step_a") {
      await this.sendMessage(env, chatId, "گام A: با دستور زیر نام پروفایل و لینک آپ‌استریم را ثبت کنید:\n<code>/setmain نام لینک_اصلی</code>");
      return new Response("ok");
    }
    if (action === "step_c") {
      await this.sendMessage(env, chatId, "گام C: دامنه اختصاصی خود را ثبت کنید:\n<code>/setdomain example.com</code>");
      return new Response("ok");
    }
    if (action === "step_d") {
      await this.sendMessage(env, chatId, "گام D: کانفیگ‌های اضافی را اضافه کنید:\n<code>/addextra متن_کانفیگ</code>");
      return new Response("ok");
    }
    if (action === "step_e") {
      await this.sendMessage(env, chatId, "گام E: قوانین ادغام را از پنل قوانین تنظیم کنید. /rules");
      return new Response("ok");
    }

    await this.sendMessage(env, chatId, "✅ انجام شد.");
    return new Response("ok");
  },
  async buildShareLink(db, baseUrl, userRecord, share) {
    const token = share?.public_token || "";
    let hostBase = baseUrl || "";
    const settings = await D1.getSettings(db, userRecord.id);
    if (settings?.domain_active_id) {
      const domain = await D1.getDomainById(db, settings.domain_active_id);
      if (domain?.domain) hostBase = `https://${domain.domain}`;
    }
    return `${hostBase.replace(/\/$/, "")}/sub/${token}`;
  },

  buildOnboardingMessage(progress, userRecord, env) {
    const steps = progress.steps;
    const statusIcon = (ok) => (ok ? "✅" : "⚪️");
    const text = `
${GLASS} <b>خوش آمدید ${safeHtml(userRecord.display_name || "دوست عزیز")}</b>

هدف: راه‌اندازی سریع اشتراک شخصی شما در ۵ قدم

${statusIcon(steps.A)} گام A: ثبت پروفایل اصلی (نام + لینک)
${statusIcon(steps.B)} گام B: تنظیمات ربات (اختیاری)
${statusIcon(steps.C)} گام C: دامنه و لینک اشتراک
${statusIcon(steps.D)} گام D: افزودنی‌ها (Extra Configs)
${statusIcon(steps.E)} گام E: قوانین ادغام و نام‌گذاری

🔹 شروع سریع: دستور زیر را بفرستید
<code>/setmain نام لینک_اصلی</code>

برای پنل کامل: /panel
    `.trim();

    const keyboard = {
      inline_keyboard: [
        [{ text: GLASS_BTN("پنل مدیریت"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_refresh" })) }],
        [
          { text: GLASS_BTN("گام A"), callback_data: utf8SafeEncode(JSON.stringify({ action: "step_a" })) },
          { text: GLASS_BTN("گام C"), callback_data: utf8SafeEncode(JSON.stringify({ action: "step_c" })) },
        ],
        [
          { text: GLASS_BTN("گام D"), callback_data: utf8SafeEncode(JSON.stringify({ action: "step_d" })) },
          { text: GLASS_BTN("گام E"), callback_data: utf8SafeEncode(JSON.stringify({ action: "step_e" })) },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildPanel(db, userRecord, env) {
    const progress = await OnboardingService.getProgress(db, userRecord.id);
    let baseUrl = env.BASE_URL || "";
    const shareLink = await this.buildShareLink(db, baseUrl, userRecord, progress.share);
    if (!baseUrl && shareLink.startsWith("http")) {
      baseUrl = new URL(shareLink).origin;
    }
    const text = `
${GLASS} <b>پنل اشتراک شخصی</b>

👤 کاربر: <code>${safeHtml(userRecord.telegram_username || userRecord.display_name || "بدون نام")}</code>
📌 لینک اشتراک: <code>${safeHtml(shareLink)}</code>

وضعیت:
• پروفایل اصلی: ${progress.steps.A ? "✅" : "⚪️"}
• دامنه فعال: ${progress.steps.C ? "✅" : "⚪️"}
• افزودنی‌ها: ${progress.extrasCount}

دستورات سریع:
/setmain نام لینک_اصلی
/addextra متن_کانفیگ
/setdomain دامنه

    `.trim();

    const keyboard = {
      inline_keyboard: [
        [
          { text: GLASS_BTN("کپی لینک"), url: `https://t.me/share/url?url=${encodeURIComponent(shareLink)}` },
          { text: GLASS_BTN("پیش‌نمایش لینک"), url: shareLink },
          { text: GLASS_BTN("چرخش توکن"), callback_data: utf8SafeEncode(JSON.stringify({ action: "rotate_token" })) },
        ],
        [
          {
            text: GLASS_BTN("v2rayNG"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2rayng://install-config?url=${shareLink}#${userRecord.telegram_username || "Sub"}`)}`,
          },
          {
            text: GLASS_BTN("NekoBox"),
            url: `${baseUrl}/redirect?target=${encodeURIComponent(`sn://subscription?url=${shareLink}&name=${userRecord.telegram_username || "Sub"}`)}`,
          },
        ],
        [
          { text: GLASS_BTN("افزودنی‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_extras" })) },
          { text: GLASS_BTN("قوانین"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_rules" })) },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildDomainPanel(db, userRecord) {
    const domains = await D1.listDomains(db, userRecord.id);
    const latest = domains?.results?.slice(-1)[0];
    const text = `
${GLASS} <b>مدیریت دامنه</b>

دامنه فعلی: ${latest ? safeHtml(latest.domain) : "ثبت نشده"}

برای ثبت دامنه جدید:
<code>/setdomain example.com</code>

راهنمای DNS:
TXT record روی دامنه با مقدار توکن اختصاصی ثبت می‌شود (نمایش فقط).
    `.trim();
    const keyboard = { inline_keyboard: [[{ text: GLASS_BTN("بازگشت"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_refresh" })) }]] };
    return { text, keyboard };
  },
  async buildExtrasPanel(db, userRecord) {
    const extras = await D1.listExtraConfigs(db, userRecord.id);
    const list = (extras?.results || [])
      .map((item) => `• ${safeHtml(item.title || "افزودنی")} (${safeHtml(item.id)}) ${item.is_enabled ? "✅" : "⛔️"}`)
      .join("\n");
    const text = `
${GLASS} <b>افزودنی‌ها</b>

${list || "فعلاً موردی ثبت نشده."}

برای افزودن:
<code>/addextra متن_کانفیگ</code>
برای ویرایش:
<code>/editextra شناسه متن_جدید</code>
    `.trim();
    const keyboard = {
      inline_keyboard: (extras?.results || []).map((item) => [
        { text: GLASS_BTN(`حذف ${item.title || item.id}`), callback_data: utf8SafeEncode(JSON.stringify({ action: "delete_extra", id: item.id })) },
      ]),
    };
    return { text, keyboard };
  },
  async buildRulesPanel(db, userRecord) {
    const rules = await D1.getRules(db, userRecord.id);
    const text = `
${GLASS} <b>قوانین اشتراک</b>

سیاست ادغام: ${safeHtml(rules?.merge_policy || "append")}
حذف تکراری: ${rules?.dedupe ? "فعال" : "غیرفعال"}
پاکسازی: ${rules?.sanitize ? "فعال" : "غیرفعال"}

برای تغییر سریع از دکمه‌ها استفاده کنید.
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [
          {
            text: GLASS_BTN("ادغام + حذف تکراری"),
            callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", policy: "append_dedupe", dedupe: true })),
          },
          { text: GLASS_BTN("فقط اپ‌استریم"), callback_data: utf8SafeEncode(JSON.stringify({ action: "set_rules", policy: "upstream_only" })) },
        ],
        [{ text: GLASS_BTN("بازگشت"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_refresh" })) }],
      ],
    };
    return { text, keyboard };
  },
  async buildLogsPanel(db, userRecord) {
    const logs = await D1.listAuditLogs(db, userRecord.id, 5);
    const items = (logs?.results || [])
      .map((log) => `• ${safeHtml(log.event_type)} ${safeHtml(log.created_at)}`)
      .join("\n");
    const text = `
${GLASS} <b>لاگ‌های اخیر</b>

${items || "فعلاً لاگی ثبت نشده."}
    `.trim();
    const keyboard = { inline_keyboard: [[{ text: GLASS_BTN("بازگشت"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_refresh" })) }]] };
    return { text, keyboard };
  },
  buildAdminPanel() {
    const text = `
${GLASS} <b>پنل مدیر</b>

گزینه‌ها:
• تایید/مسدودسازی کاربران: /approve یا /ban
• ارسال پیام سراسری: /broadcast پیام
• تنظیمات ربات: /botsettings کلید مقدار
• وضعیت سلامت سیستم: /health
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
    if (cached) {
      return new Response(cached.body, { headers: cached.headers });
    }

    const db = env.DB;
    const link = await D1.getShareLinkByToken(db, token);
    if (!link) return new Response("not found", { status: 404 });

    const cacheUrl = new URL(request.url);
    const cache = caches.default;
    const cachedResponse = await cache.match(cacheUrl);
    if (cachedResponse) {
      const body = await cachedResponse.text();
      setCachedSub(cacheKey, body, DEFAULT_HEADERS);
      return new Response(body, { headers: DEFAULT_HEADERS });
    }

    const content = await SubscriptionAssembler.assemble(env, db, link.user_id, token, request);
    const headers = {
      ...DEFAULT_HEADERS,
      "content-disposition": `inline; filename=subscription_${token}.txt`,
    };
    if (content) {
      setCachedSub(cacheKey, content, headers);
      setLastGood(cacheKey, content, headers);
      await cache.put(cacheUrl, new Response(content, { headers, status: 200 }));
      await AuditService.notifyTelegram(env, `🧊 اشتراک دریافت شد: <b>${safeHtml(token)}</b>`);
      return new Response(content, { headers });
    }

    const lastGood = getLastGood(cacheKey);
    if (lastGood) {
      return new Response(lastGood.body, { headers: lastGood.headers });
    }
    return new Response("", { headers });
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
  <title>مدیریت اشتراک شخصی</title>
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
      <h1>مدیریت اشتراک شخصی، شفاف و امن</h1>
      <p class="muted">برای شروع، به ربات تلگرام وارد شوید و مراحل راه‌اندازی را انجام دهید.</p>
      <div class="grid">
        <a class="glass-btn" href="https://t.me/">🧊 ورود به ربات</a>
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
