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
  notifyFetchDefault: 0,
  upstreamTimeoutMs: 8000,
  maxRedirects: 2,
  sessionTtlSec: 60 * 60 * 24,
  snapshotTtlSec: 300,
  auditSampleRate: 0.01,
  upstreamMaxConcurrency: 3,
  upstreamFailureThreshold: 3,
  upstreamCooldownMs: 5 * 60 * 1000,
  purgeRetentionDays: 30,
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
const HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "content-security-policy":
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://telegram.org; frame-src https://telegram.org; connect-src 'self'; base-uri 'none'; form-action 'self';",
};

const SUB_CACHE = new Map();
const LAST_GOOD_MEM = new Map();
const RATE_LIMIT = new Map();
const TELEGRAM_CACHE = {
  invalidTokenUntil: 0,
  invalidTokenLoggedAt: 0,
  getMe: { at: 0, result: null },
};
const TELEGRAM_TOKEN_REGEX = /^\d+:[A-Za-z0-9_-]+$/;
const TELEGRAM_CACHE_TTL_MS = 5 * 60 * 1000;

const ERROR_CODES = {
  E_AUTH_UNAUTHORIZED: {
    reason: "auth_unauthorized",
    hints: ["Validate auth headers", "Ensure session token is valid and unexpired"],
  },
  E_AUTH_FORBIDDEN: {
    reason: "auth_forbidden",
    hints: ["Check operator permissions", "Verify admin role"],
  },
  E_INPUT_INVALID: {
    reason: "input_invalid",
    hints: ["Validate request payload", "Check required fields"],
  },
  E_JSON_PARSE: {
    reason: "json_parse_failed",
    hints: ["Validate JSON format", "Ensure content-type is application/json"],
  },
  E_DB_QUERY: {
    reason: "db_query_failed",
    hints: ["Check D1 binding", "Validate SQL syntax", "Inspect database availability"],
  },
  E_UPSTREAM_FETCH: {
    reason: "upstream_fetch_failed",
    hints: ["Validate upstream URL", "Check network connectivity", "Inspect upstream response"],
  },
  E_UPSTREAM_INVALID: {
    reason: "upstream_invalid",
    hints: ["Check upstream response content", "Verify subscription format"],
  },
  E_SSRF_BLOCKED: {
    reason: "ssrf_blocked",
    hints: ["Verify allowlist/denylist", "Check upstream host safety"],
  },
  E_RATE_LIMIT: {
    reason: "rate_limited",
    hints: ["Reduce request rate", "Check per-token quotas"],
  },
  E_TELEGRAM_API: {
    reason: "telegram_api_error",
    hints: ["Check Telegram token", "Inspect Telegram API response"],
  },
  E_INTERNAL: {
    reason: "internal_error",
    hints: ["Check logs for stack trace", "Inspect recent deployments"],
  },
};

const LOG_LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };
const ERROR_CLASSIFICATION = {
  E_AUTH_UNAUTHORIZED: "auth",
  E_AUTH_FORBIDDEN: "auth",
  E_INPUT_INVALID: "input",
  E_JSON_PARSE: "input",
  E_DB_QUERY: "db",
  E_UPSTREAM_FETCH: "upstream",
  E_UPSTREAM_INVALID: "upstream",
  E_SSRF_BLOCKED: "security",
  E_RATE_LIMIT: "throttle",
  E_TELEGRAM_API: "external",
  E_INTERNAL: "internal",
};

const truncateStack = (stack, maxLines = 12) => {
  if (!stack) return null;
  return String(stack).split("\n").slice(0, maxLines).join("\n");
};

const normalizeError = (err) => {
  if (!err) {
    return { name: "Error", message: "Unknown error", stack: null, cause_chain: [] };
  }
  const base = {
    name: err.name || "Error",
    message: err.message || String(err),
    stack: truncateStack(err.stack),
    cause_chain: [],
  };
  let current = err;
  for (let i = 0; i < 5; i += 1) {
    if (!current?.cause) break;
    current = current.cause;
    base.cause_chain.push({
      name: current?.name || "Error",
      message: current?.message || String(current),
      stack: truncateStack(current?.stack),
    });
  }
  return base;
};

const createLogger = (env, baseContext = {}) => {
  const levelName = String(env?.LOG_LEVEL || "INFO").toUpperCase();
  const threshold = LOG_LEVELS[levelName] ?? LOG_LEVELS.INFO;
  const write = (level, msg, data = {}) => {
    if (LOG_LEVELS[level] < threshold) return;
    const payload = { level, msg, ts: new Date().toISOString(), ...baseContext, ...data };
    const line = JSON.stringify(payload);
    if (level === "ERROR") {
      console.error(line);
    } else if (level === "WARN") {
      console.warn(line);
    } else {
      console.log(line);
    }
  };
  const logger = {
    debug: (msg, data = {}) => write("DEBUG", msg, data),
    info: (msg, data = {}) => write("INFO", msg, data),
    warn: (msg, data = {}) => write("WARN", msg, data),
    error: (msg, err, ctx = {}) => {
      const { reason, error_code, hints, http_status, classification, ...rest } = ctx;
      const code = error_code || "E_INTERNAL";
      write("ERROR", msg, {
        ...rest,
        reason: reason || (ERROR_CODES[code] || ERROR_CODES.E_INTERNAL).reason,
        error_code: code,
        classification: classification || ERROR_CLASSIFICATION[code] || "internal",
        hints: hints || (ERROR_CODES[code] || ERROR_CODES.E_INTERNAL).hints,
        ...(http_status ? { http_status } : {}),
        error: normalizeError(err),
      });
    },
    child: (ctx = {}) => createLogger(env, { ...baseContext, ...ctx }),
    span: (name, ctx = {}) => {
      const start = Date.now();
      const spanLogger = createLogger(env, { ...baseContext, span: name, ...ctx });
      return {
        end: (successCtx = {}) =>
          spanLogger.info("span_end", { duration_ms: Date.now() - start, ...successCtx }),
        fail: (err, failCtx = {}) =>
          spanLogger.error("span_fail", err, {
            duration_ms: Date.now() - start,
            error_code: failCtx.error_code || "E_INTERNAL",
            reason: failCtx.reason || ERROR_CODES.E_INTERNAL.reason,
            hints: failCtx.hints || ERROR_CODES.E_INTERNAL.hints,
            ...failCtx,
          }),
      };
    },
  };
  return logger;
};

const Logger = createLogger();

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

const normalizeBase64Input = (value) => {
  const stripped = String(value || "").replace(/[\n\r\s]/g, "");
  const normalized = stripped.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return `${normalized}${pad}`;
};

const utf8SafeDecode = (b64) => {
  try {
    const clean = normalizeBase64Input(b64);
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

const setCachedSub = (key, body, headers, meta = {}) => {
  if (SUB_CACHE.size > APP.cacheMaxEntries) SUB_CACHE.clear();
  SUB_CACHE.set(key, { body, headers, timestamp: Date.now(), ...meta });
};

const setLastGoodMem = (key, body, headers, meta = {}) => {
  if (LAST_GOOD_MEM.size > APP.cacheMaxEntries) LAST_GOOD_MEM.clear();
  LAST_GOOD_MEM.set(key, { body, headers, timestamp: Date.now(), ...meta });
};

const getLastGoodMem = (key) => LAST_GOOD_MEM.get(key);

const parseMessageText = (message) => message?.text?.trim() || "";

const normalizeBaseUrl = (value) => String(value || "").trim().replace(/\/$/, "");

const parsePanelSubscriptionInput = (text) => {
  const trimmed = String(text || "").trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    try {
      const parsed = new URL(trimmed);
      const match = parsed.pathname.match(/^(.*)\/sub\/([^/]+)/);
      if (!match) return null;
      const token = match[2];
      if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;
      const basePath = match[1] || "";
      const base = `${parsed.protocol}//${parsed.host}${basePath}`;
      const template = `${parsed.protocol}//${parsed.host}${basePath}/sub/{{TOKEN}}`;
      return { token, origin: `${parsed.protocol}//${parsed.host}`, base, template };
    } catch {
      return null;
    }
  }
  if (trimmed.startsWith("/")) {
    const match = trimmed.match(/\/sub\/([^/]+)/);
    if (!match) return null;
    const token = match[1];
    if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;
    return { token, origin: null };
  }
  if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
    return { token: trimmed, origin: null };
  }
  return null;
};

const decodePanelTokenUsername = (token) => {
  if (!token) return "Premium User";
  try {
    const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
    const pad = normalized.length % 4 === 0 ? normalized : normalized + "=".repeat(4 - (normalized.length % 4));
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(pad), (c) => c.charCodeAt(0)));
    if (decoded.includes(",") || decoded.includes(":")) {
      const value = decoded.split(/[,:]/)[0].trim();
      return value || "Premium User";
    }
    return decoded.trim() || "Premium User";
  } catch {
    return "Premium User";
  }
};

const resolveUpstreamUrl = (upstreamUrl, formatHint, panelToken) => {
  if (!panelToken) return upstreamUrl;
  if (formatHint === "template") return upstreamUrl.replace(/\{\{TOKEN\}\}/g, panelToken);
  if (formatHint === "base") {
    const normalized = upstreamUrl.replace(/\/$/, "");
    return `${normalized}/sub/${panelToken}`;
  }
  return upstreamUrl;
};

const analyzeUpstreamBody = (body) => {
  const trimmed = String(body || "").trim();
  if (!trimmed) return { isBase64: false, reason: "decode_failed" };
  if (trimmed.includes("://")) return { isBase64: false, reason: "plain" };
  const normalized = normalizeBase64Input(trimmed);
  try {
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0)));
    if (decoded.includes("://")) {
      const urlsafe = /[-_]/.test(trimmed) || trimmed.length % 4 !== 0;
      return { isBase64: true, reason: urlsafe ? "urlsafe_base64" : "base64" };
    }
  } catch {
    return { isBase64: false, reason: "decode_failed" };
  }
  return { isBase64: false, reason: "decode_failed" };
};

const buildOperatorPrefixes = (options) => {
  const { baseUrl, nationalBaseUrl, shareToken, domain } = options;
  const workerBase = normalizeBaseUrl(baseUrl);
  const nationalBase = normalizeBaseUrl(nationalBaseUrl);
  const mainPrefix = domain ? `https://${domain}/sub/` : shareToken && workerBase ? `${workerBase}/sub/${shareToken}/` : "";
  const meliPrefix = nationalBase ? (domain ? `${nationalBase}/sub/` : shareToken ? `${nationalBase}/sub/${shareToken}/` : "") : "";
  return { mainPrefix, meliPrefix };
};

const buildPremiumSubscriptionMessage = (payload) => {
  const { operatorName, username, mainLink, meliLink, warningLine } = payload;
  let redirectBase = "";
  try {
    redirectBase = new URL(mainLink).origin;
  } catch {
    redirectBase = "";
  }
  const label = operatorName || "Premium";
  const targetName = label || "Premium";
  const quickGuide = `
${GLASS} <b>HideNet Premium</b>

👤 کاربر: <b>${safeHtml(username || "Premium User")}</b>
${warningLine ? `⚠️ ${safeHtml(warningLine)}\n` : ""}🔗 لینک اشتراک اصلی:
<code>${safeHtml(mainLink)}</code>
${meliLink ? `🇮🇷 لینک ملی:\n<code>${safeHtml(meliLink)}</code>\n` : ""}
🧊 <b>اتصال فوری با یک کلیک</b>
دکمه‌های پایین را بزنید تا مستقیم اضافه شود.

🧭 <b>راهنمای اتصال دستی</b>
1) اپ مورد نظر را باز کنید.
2) گزینه Import / اضافه کردن لینک را بزنید.
3) لینک بالا را کپی و وارد کنید.
4) ذخیره کنید و متصل شوید.
  `.trim();
  const keyboard = {
    inline_keyboard: [
      [
        {
          text: GLASS_BTN("v2rayNG"),
          url: redirectBase
            ? `${redirectBase}/redirect?target=${encodeURIComponent(`v2rayng://install-config?url=${mainLink}#${targetName}`)}`
            : mainLink,
        },
        {
          text: GLASS_BTN("NekoBox"),
          url: redirectBase
            ? `${redirectBase}/redirect?target=${encodeURIComponent(`sn://subscription?url=${mainLink}&name=${targetName}`)}`
            : mainLink,
        },
      ],
      [
        {
          text: GLASS_BTN("Streisand"),
          url: redirectBase
            ? `${redirectBase}/redirect?target=${encodeURIComponent(`streisand://import/${mainLink}`)}`
            : mainLink,
        },
        {
          text: GLASS_BTN("v2Box"),
          url: redirectBase
            ? `${redirectBase}/redirect?target=${encodeURIComponent(`v2box://install-sub?url=${mainLink}&name=${targetName}`)}`
            : mainLink,
        },
      ],
      [{ text: GLASS_BTN("Share"), url: `https://t.me/share/url?url=${encodeURIComponent(mainLink)}` }],
    ],
  };
  return { text: quickGuide, keyboard };
};

const isSnapshotFresh = (snapshot) => {
  if (!snapshot?.updated_at || !snapshot?.ttl_sec) return false;
  const updated = Date.parse(snapshot.updated_at);
  if (!Number.isFinite(updated)) return false;
  return Date.now() - updated < snapshot.ttl_sec * 1000;
};

const mapWithConcurrency = async (items, limit, mapper) => {
  const results = [];
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }).map(async () => {
    while (index < items.length) {
      const current = index;
      index += 1;
      results[current] = await mapper(items[current], current);
    }
  });
  await Promise.all(workers);
  return results;
};

const decodeCallbackData = (data, logger) => {
  const decoded = utf8SafeDecode(data);
  return safeJsonParse(decoded, { action: data }, logger, { error_code: "E_JSON_PARSE" });
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

const summarizeUpstreamFailures = (payloads) => {
  if (!payloads?.length) return "no_upstreams";
  if (payloads.some((item) => item.ok && item.decodeReason === "decode_failed")) return "decode_failed";
  const errors = payloads.map((item) => item.error).filter(Boolean);
  if (errors.some((err) => err === "timeout")) return "timeout";
  if (errors.some((err) => err === "fetch_failed")) return "fetch_failed";
  if (errors.some((err) => ["blocked_host", "denylisted", "not_allowlisted", "https_only", "invalid_url"].includes(err))) {
    return "blocked_host";
  }
  return errors[0] || "upstream_invalid";
};

const withStatusHeaders = (headers, subStatus, upstreamStatus) => ({
  ...headers,
  "x-sub-status": subStatus,
  "x-upstream-status": upstreamStatus,
});

const isValidSubscriptionText = (text) => {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (/error|not\s+found|invalid/i.test(trimmed)) return false;
  return /:\/\//.test(trimmed);
};

const redactPathSegments = (pathname) =>
  pathname
    .split("/")
    .map((segment) => {
      if (!segment) return segment;
      if (segment.startsWith("bot") && segment.length > 6) return "bot***";
      if (/^[0-9a-f-]{16,}$/i.test(segment)) return "***";
      if (/^[A-Za-z0-9_-]{24,}$/.test(segment)) return "***";
      return segment;
    })
    .join("/");

const redactUrlForLog = (url) => {
  try {
    const parsed = new URL(url);
    const sensitive = ["token", "key", "pass", "auth", "jwt", "session", "code"];
    for (const key of sensitive) {
      if (parsed.searchParams.has(key)) parsed.searchParams.set(key, "***");
    }
    parsed.username = "";
    parsed.password = "";
    parsed.pathname = redactPathSegments(parsed.pathname);
    return parsed.toString();
  } catch {
    return "***";
  }
};

const redactUrlForDisplay = (url) => {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.hostname}/***`;
  } catch {
    return "***";
  }
};

const scrubPathForLog = (pathname) => {
  if (pathname.startsWith("/sub/")) return "/sub/:token";
  if (pathname.startsWith("/verify-domain/")) return "/verify-domain/:id";
  if (pathname.startsWith("/api/v1/operators/me/customer-links/") && pathname.endsWith("/rotate")) {
    return "/api/v1/operators/me/customer-links/:id/rotate";
  }
  if (pathname.startsWith("/admin/operators/") && pathname.endsWith("/approve")) {
    return "/admin/operators/:id/approve";
  }
  return redactPathSegments(pathname);
};

const buildRequestContext = (request, requestId) => {
  const url = new URL(request.url);
  return {
    request_id: requestId,
    route: scrubPathForLog(url.pathname),
    method: request.method,
    cf_ray: request.headers.get("cf-ray") || null,
    ip: request.headers.get("cf-connecting-ip") || null,
    country: request.headers.get("cf-ipcountry") || null,
  };
};

const getHeaderNames = (headers) => {
  const names = [];
  const redacted = [];
  const sensitive = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"]);
  if (!headers) return { header_names: names, redacted };
  for (const [key] of headers.entries()) {
    const lower = key.toLowerCase();
    names.push(lower);
    if (sensitive.has(lower) || lower.includes("token") || lower.includes("secret")) {
      redacted.push(lower);
    }
  }
  return { header_names: names, redacted };
};

const withRequestLogger = async (request, env, fn) => {
  const requestId = crypto.randomUUID();
  const baseLogger = createLogger(env);
  const context = buildRequestContext(request, requestId);
  const logger = baseLogger.child(context);
  const url = new URL(request.url);
  const start = Date.now();
  logger.info("request_start", {
    query_keys: Array.from(url.searchParams.keys()),
    user_agent: request.headers.get("user-agent") || null,
  });
  try {
    const response = await fn(logger, requestId);
    logger.info("request_end", { status: response?.status || 200, duration_ms: Date.now() - start });
    return response;
  } catch (err) {
    logger.error("request_failed", err, {
      error_code: "E_INTERNAL",
      reason: ERROR_CODES.E_INTERNAL.reason,
      hints: ERROR_CODES.E_INTERNAL.hints,
    });
    logger.info("request_end", { status: 500, duration_ms: Date.now() - start });
    return new Response("server error", { status: 500, headers: { "x-request-id": requestId } });
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

const htmlResponse = (html, status = 200) => new Response(html, { status, headers: HTML_HEADERS });

const safeJsonParse = (value, fallback = {}, logger, meta = {}) => {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch (err) {
    const inputLength = typeof value === "string" ? value.length : 0;
    const log = logger || Logger;
    log.error("json_parse_failed", err, {
      ...meta,
      error_code: "E_JSON_PARSE",
      reason: ERROR_CODES.E_JSON_PARSE.reason,
      hints: ERROR_CODES.E_JSON_PARSE.hints,
      input_length: inputLength,
    });
    return fallback;
  }
};

const safeParseJson = safeJsonParse;

const parseJsonBody = async (request, logger) => {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  const bodyText = await request.text();
  if (!bodyText) return null;
  return safeJsonParse(bodyText, null, logger, { error_code: "E_JSON_PARSE" });
};

const dbFirst = async (db, label, executor, logger, meta = {}) => {
  const start = Date.now();
  try {
    const result = await executor();
    (logger || Logger).debug("db_first", { label, duration_ms: Date.now() - start, ...meta });
    return result;
  } catch (err) {
    (logger || Logger).error("db_query_failed", err, {
      label,
      duration_ms: Date.now() - start,
      error_code: "E_DB_QUERY",
      reason: ERROR_CODES.E_DB_QUERY.reason,
      hints: ERROR_CODES.E_DB_QUERY.hints,
      ...meta,
    });
    throw err;
  }
};

const dbAll = async (db, label, executor, logger, meta = {}) => {
  const start = Date.now();
  try {
    const result = await executor();
    (logger || Logger).debug("db_all", { label, duration_ms: Date.now() - start, ...meta });
    return result;
  } catch (err) {
    (logger || Logger).error("db_query_failed", err, {
      label,
      duration_ms: Date.now() - start,
      error_code: "E_DB_QUERY",
      reason: ERROR_CODES.E_DB_QUERY.reason,
      hints: ERROR_CODES.E_DB_QUERY.hints,
      ...meta,
    });
    throw err;
  }
};

const dbRun = async (db, label, executor, logger, meta = {}) => {
  const start = Date.now();
  try {
    const result = await executor();
    (logger || Logger).debug("db_run", { label, duration_ms: Date.now() - start, ...meta });
    return result;
  } catch (err) {
    (logger || Logger).error("db_query_failed", err, {
      label,
      duration_ms: Date.now() - start,
      error_code: "E_DB_QUERY",
      reason: ERROR_CODES.E_DB_QUERY.reason,
      hints: ERROR_CODES.E_DB_QUERY.hints,
      ...meta,
    });
    throw err;
  }
};

const fetchWithLogs = async (url, options = {}, meta = {}, logger) => {
  const start = Date.now();
  const log = logger || Logger;
  const redactedUrl = redactUrlForLog(url);
  log.info("fetch_start", {
    url: redactedUrl,
    method: options.method || "GET",
    ...meta,
    ...getHeaderNames(new Headers(options.headers || {})),
  });
  try {
    const res = await fetch(url, options);
    const endPayload = {
      url: redactedUrl,
      status: res.status,
      duration_ms: Date.now() - start,
      ...meta,
    };
    if (res.status >= 400) {
      log.warn("fetch_end", endPayload);
    } else {
      log.info("fetch_end", endPayload);
    }
    return res;
  } catch (err) {
    log.error("fetch_failed", err, {
      url: redactedUrl,
      duration_ms: Date.now() - start,
      error_code: meta.error_code || "E_UPSTREAM_FETCH",
      reason: meta.reason || ERROR_CODES.E_UPSTREAM_FETCH.reason,
      hints: meta.hints || ERROR_CODES.E_UPSTREAM_FETCH.hints,
      ...meta,
    });
    throw err;
  }
};

const getTelegramToken = (env, logger) => {
  const raw = String(env?.TELEGRAM_TOKEN || "").trim();
  const now = Date.now();
  if (!raw || !TELEGRAM_TOKEN_REGEX.test(raw)) {
    if (now > TELEGRAM_CACHE.invalidTokenUntil) {
      TELEGRAM_CACHE.invalidTokenUntil = now + TELEGRAM_CACHE_TTL_MS;
      if (now - TELEGRAM_CACHE.invalidTokenLoggedAt > TELEGRAM_CACHE_TTL_MS) {
        TELEGRAM_CACHE.invalidTokenLoggedAt = now;
        (logger || Logger).error("telegram_token_invalid", new Error("Invalid TELEGRAM_TOKEN format"), {
          error_code: "E_TELEGRAM_API",
          reason: "Invalid TELEGRAM_TOKEN format",
          hints: [
            "Check TELEGRAM_TOKEN",
            "Call getMe",
            "Verify bot token has no 'bot' prefix",
            "Trim whitespace",
          ],
          severity: "CRITICAL",
        });
      }
    }
    return null;
  }
  return raw;
};

const telegramHintsForStatus = (status) => {
  const hints = [
    "Check TELEGRAM_TOKEN",
    "Call getMe",
    "Verify bot token has no 'bot' prefix",
    "Trim whitespace",
  ];
  if (status === 404) {
    hints.push("Likely invalid TELEGRAM_TOKEN or wrong endpoint/method");
  }
  return hints;
};

const telegramFetch = async (methodName, payload, ctx = {}) => {
  const start = Date.now();
  const log = ctx.logger || Logger;
  const token = getTelegramToken(ctx.env, log);
  const route = `/bot***/${methodName}`;
  const label = ctx.label || `telegram_${methodName}`;
  if (!token) {
    return {
      ok: false,
      status: 0,
      skipped: true,
      reason: "invalid_telegram_token",
    };
  }
  const url = `https://api.telegram.org/bot${token}/${methodName}`;
  const options = payload
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }
    : { method: "GET" };
  try {
    const res = await fetch(url, options);
    const durationMs = Date.now() - start;
    const contentType = res.headers.get("content-type") || "";
    let bodyText = "";
    try {
      bodyText = await res.text();
    } catch {
      bodyText = "";
    }
    let telegram = null;
    if (contentType.includes("application/json") || bodyText.trim().startsWith("{")) {
      try {
        const parsed = JSON.parse(bodyText);
        telegram = {
          ok: parsed.ok,
          error_code: parsed.error_code,
          description: parsed.description,
        };
      } catch {
        telegram = null;
      }
    }
    const logPayload = {
      label,
      duration_ms: durationMs,
      status: res.status,
      route,
      request_id: ctx.request_id,
      operator_id: ctx.operator_id,
      telegram_user_id: ctx.telegram_user_id,
      telegram,
    };
    if (res.ok) {
      log.info("telegram_api_response", logPayload);
    } else {
      log.error("telegram_api_response", new Error("Telegram API responded with non-2xx"), {
        ...logPayload,
        error_code: "E_TELEGRAM_API",
        reason: "Telegram API responded with non-2xx",
        hints: telegramHintsForStatus(res.status),
        http_status: res.status,
      });
    }
    return { ok: res.ok, status: res.status, telegram };
  } catch (err) {
    log.error("telegram_api_fetch_failed", err, {
      label,
      duration_ms: Date.now() - start,
      status: 0,
      route,
      request_id: ctx.request_id,
      operator_id: ctx.operator_id,
      telegram_user_id: ctx.telegram_user_id,
      error_code: "E_TELEGRAM_API",
      reason: "Telegram API fetch failed",
      hints: telegramHintsForStatus(0),
    });
    return { ok: false, status: 0, telegram: null };
  }
};

const constantTimeEqual = (a, b) => {
  const aBytes = new TextEncoder().encode(String(a || ""));
  const bBytes = new TextEncoder().encode(String(b || ""));
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i += 1) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
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

const base64Encode = (data) => btoa(String.fromCharCode(...new Uint8Array(data)));
const base64Decode = (data) => Uint8Array.from(atob(data), (c) => c.charCodeAt(0));

const getEncryptionSecret = (env) => env.ENCRYPTION_KEY || env.SESSION_SECRET || "";

const deriveAesKey = async (secret) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
};

const encryptString = async (env, plainText) => {
  const secret = getEncryptionSecret(env);
  if (!secret) return plainText;
  const key = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plainText));
  return `enc:v1:${base64UrlEncode(iv)}:${base64UrlEncode(cipher)}`;
};

const decryptString = async (env, value) => {
  if (!value || !value.startsWith("enc:v1:")) return value || "";
  const secret = getEncryptionSecret(env);
  if (!secret) return "";
  const [, , ivB64, dataB64] = value.split(":");
  if (!ivB64 || !dataB64) return "";
  const key = await deriveAesKey(secret);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64UrlDecode(ivB64) }, key, base64UrlDecode(dataB64));
    return new TextDecoder().decode(plain);
  } catch {
    return "";
  }
};

const encryptUpstreamUrl = async (env, url) => {
  if (!url) return "";
  return encryptString(env, url);
};

const decryptUpstreamUrl = async (env, url) => {
  if (!url) return "";
  return decryptString(env, url);
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
  const authDate = Number(data.auth_date || 0) * 1000;
  if (!authDate || Date.now() - authDate > 10 * 60 * 1000) return false;
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
  return constantTimeEqual(hash, data.hash);
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

const fetchWithRedirects = async (url, options, maxRedirects, validateUrl, logger) => {
  let currentUrl = url;
  for (let i = 0; i <= maxRedirects; i += 1) {
    const res = await fetchWithLogs(
      currentUrl,
      { ...options, redirect: "manual" },
      { label: "fetch_redirect", error_code: "E_UPSTREAM_FETCH" },
      logger
    );
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const nextUrl = new URL(res.headers.get("location"), currentUrl).toString();
      if (validateUrl) {
        const check = validateUrl(nextUrl);
        if (!check.ok) {
          (logger || Logger).warn("redirect_blocked", {
            error_code: "E_SSRF_BLOCKED",
            reason: ERROR_CODES.E_SSRF_BLOCKED.reason,
            hints: ERROR_CODES.E_SSRF_BLOCKED.hints,
            from_url: redactUrlForLog(currentUrl),
            to_url: redactUrlForLog(nextUrl),
            blocked_reason: check.error,
          });
          return new Response("blocked", { status: 403 });
        }
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
  async getOperatorByTelegramId(db, telegramUserId, logger) {
    return dbFirst(
      db,
      "operators.get_by_telegram_id",
      () => db.prepare("SELECT * FROM operators WHERE telegram_user_id = ?").bind(telegramUserId).first(),
      logger
    );
  },
  async getOperatorById(db, operatorId, logger) {
    return dbFirst(db, "operators.get_by_id", () => db.prepare("SELECT * FROM operators WHERE id = ?").bind(operatorId).first(), logger);
  },
  async listOperators(db, logger) {
    return dbAll(db, "operators.list", () => db.prepare("SELECT * FROM operators ORDER BY created_at DESC").all(), logger);
  },
  async createOperator(db, telegramUserId, displayName, role = "operator", status = "pending", logger) {
    const id = crypto.randomUUID();
    await dbRun(
      db,
      "operators.create",
      () =>
        db
          .prepare(
            "INSERT INTO operators (id, telegram_user_id, display_name, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
          )
          .bind(id, telegramUserId, displayName || null, role, status, nowIso(), nowIso())
          .run(),
      logger
    );
    await dbRun(
      db,
      "operator_settings.create",
      () => db.prepare("INSERT INTO operator_settings (operator_id, created_at, updated_at) VALUES (?, ?, ?)").bind(id, nowIso(), nowIso()).run(),
      logger
    );
    await dbRun(
      db,
      "subscription_rules.create",
      () => db.prepare("INSERT INTO subscription_rules (operator_id, created_at, updated_at) VALUES (?, ?, ?)").bind(id, nowIso(), nowIso()).run(),
      logger
    );
    await dbRun(
      db,
      "customer_links.create",
      () =>
        db
          .prepare("INSERT INTO customer_links (id, operator_id, public_token, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)")
          .bind(crypto.randomUUID(), id, crypto.randomUUID(), nowIso(), nowIso())
          .run(),
      logger
    );
    return this.getOperatorByTelegramId(db, telegramUserId, logger);
  },
  async updateOperatorStatus(db, operatorId, status, logger) {
    await dbRun(
      db,
      "operators.update_status",
      () => db.prepare("UPDATE operators SET status = ?, updated_at = ? WHERE id = ?").bind(status, nowIso(), operatorId).run(),
      logger
    );
  },
  async removeOperator(db, telegramUserId, logger) {
    await dbRun(
      db,
      "operators.remove",
      () =>
        db
          .prepare("UPDATE operators SET status = 'removed', updated_at = ? WHERE telegram_user_id = ?")
          .bind(nowIso(), telegramUserId)
          .run(),
      logger
    );
  },
  async touchOperator(db, operatorId, logger) {
    await dbRun(db, "operators.touch", () => db.prepare("UPDATE operators SET updated_at = ? WHERE id = ?").bind(nowIso(), operatorId).run(), logger);
  },
  async getSettings(db, operatorId, logger) {
    return dbFirst(
      db,
      "operator_settings.get",
      () => db.prepare("SELECT * FROM operator_settings WHERE operator_id = ?").bind(operatorId).first(),
      logger
    );
  },
  async updateSettings(db, operatorId, patch, logger) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await dbRun(
      db,
      "operator_settings.update",
      () => db.prepare(`UPDATE operator_settings SET ${setClause}, updated_at = ? WHERE operator_id = ?`).bind(...values, nowIso(), operatorId).run(),
      logger
    );
  },
  async setPendingAction(db, operatorId, action, meta = null, logger) {
    await dbRun(
      db,
      "operator_settings.set_pending_action",
      () =>
        db
          .prepare("UPDATE operator_settings SET pending_action = ?, pending_meta = ?, updated_at = ? WHERE operator_id = ?")
          .bind(action, meta ? JSON.stringify(meta) : null, nowIso(), operatorId)
          .run(),
      logger
    );
  },
  async listDomains(db, operatorId, logger) {
    return dbAll(
      db,
      "domains.list",
      () => db.prepare("SELECT * FROM domains WHERE operator_id = ? AND deleted_at IS NULL ORDER BY created_at DESC").bind(operatorId).all(),
      logger
    );
  },
  async createDomain(db, operatorId, domain, logger) {
    await dbRun(
      db,
      "domains.create",
      () =>
        db
          .prepare(
            "INSERT INTO domains (id, operator_id, domain, verified, token, active, created_at, updated_at) VALUES (?, ?, ?, 0, ?, 1, ?, ?)"
          )
          .bind(crypto.randomUUID(), operatorId, domain, crypto.randomUUID(), nowIso(), nowIso())
          .run(),
      logger
    );
  },
  async setDomainActive(db, operatorId, domainId, logger) {
    await dbRun(
      db,
      "domains.set_active",
      () => db.prepare("UPDATE operator_settings SET active_domain_id = ?, updated_at = ? WHERE operator_id = ?").bind(domainId, nowIso(), operatorId).run(),
      logger
    );
    await dbRun(db, "domains.set_inactive", () => db.prepare("UPDATE domains SET active = 0 WHERE operator_id = ?").bind(operatorId).run(), logger);
    await dbRun(
      db,
      "domains.set_active_row",
      () => db.prepare("UPDATE domains SET active = 1 WHERE id = ? AND operator_id = ?").bind(domainId, operatorId).run(),
      logger
    );
  },
  async updateDomainVerified(db, domainId, verified, logger) {
    await dbRun(
      db,
      "domains.update_verified",
      () => db.prepare("UPDATE domains SET verified = ?, updated_at = ? WHERE id = ?").bind(verified ? 1 : 0, nowIso(), domainId).run(),
      logger
    );
  },
  async getDomainById(db, domainId, logger) {
    return dbFirst(db, "domains.get_by_id", () => db.prepare("SELECT * FROM domains WHERE id = ? AND deleted_at IS NULL").bind(domainId).first(), logger);
  },
  async getDomainByHostname(db, hostname, logger) {
    return dbFirst(
      db,
      "domains.get_by_hostname",
      () =>
        db
          .prepare("SELECT * FROM domains WHERE domain = ? AND deleted_at IS NULL ORDER BY verified DESC, active DESC, created_at DESC LIMIT 1")
          .bind(hostname.toLowerCase())
          .first(),
      logger
    );
  },
  async listExtraConfigs(db, operatorId, limit = 5, offset = 0, logger) {
    return dbAll(
      db,
      "extra_configs.list",
      () =>
        db
          .prepare("SELECT * FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL ORDER BY sort_order, created_at LIMIT ? OFFSET ?")
          .bind(operatorId, limit, offset)
          .all(),
      logger
    );
  },
  async listEnabledExtras(db, operatorId, logger) {
    return dbAll(
      db,
      "extra_configs.list_enabled",
      () =>
        db
          .prepare("SELECT * FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL AND enabled = 1 ORDER BY sort_order, created_at")
          .bind(operatorId)
          .all(),
      logger
    );
  },
  async countExtraConfigs(db, operatorId, logger) {
    return dbFirst(
      db,
      "extra_configs.count",
      () => db.prepare("SELECT COUNT(*) as count FROM extra_configs WHERE operator_id = ? AND deleted_at IS NULL").bind(operatorId).first(),
      logger
    );
  },
  async createExtraConfig(db, operatorId, title, content, logger) {
    await dbRun(
      db,
      "extra_configs.create",
      () =>
        db
          .prepare(
            "INSERT INTO extra_configs (id, operator_id, title, content, enabled, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, ?, ?)"
          )
          .bind(crypto.randomUUID(), operatorId, title || null, content, nowIso(), nowIso())
          .run(),
      logger
    );
  },
  async updateExtraConfig(db, operatorId, configId, content, logger) {
    await dbRun(
      db,
      "extra_configs.update",
      () => db.prepare("UPDATE extra_configs SET content = ?, updated_at = ? WHERE id = ? AND operator_id = ?").bind(content, nowIso(), configId, operatorId).run(),
      logger
    );
  },
  async setExtraEnabled(db, operatorId, configId, enabled, logger) {
    await dbRun(
      db,
      "extra_configs.set_enabled",
      () => db.prepare("UPDATE extra_configs SET enabled = ?, updated_at = ? WHERE id = ? AND operator_id = ?").bind(enabled ? 1 : 0, nowIso(), configId, operatorId).run(),
      logger
    );
  },
  async deleteExtraConfig(db, operatorId, configId, logger) {
    await dbRun(
      db,
      "extra_configs.delete",
      () => db.prepare("UPDATE extra_configs SET deleted_at = ?, updated_at = ? WHERE id = ? AND operator_id = ?").bind(nowIso(), nowIso(), configId, operatorId).run(),
      logger
    );
  },
  async getRules(db, operatorId, logger) {
    return dbFirst(db, "subscription_rules.get", () => db.prepare("SELECT * FROM subscription_rules WHERE operator_id = ?").bind(operatorId).first(), logger);
  },
  async updateRules(db, operatorId, patch, logger) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await dbRun(
      db,
      "subscription_rules.update",
      () => db.prepare(`UPDATE subscription_rules SET ${setClause}, updated_at = ? WHERE operator_id = ?`).bind(...values, nowIso(), operatorId).run(),
      logger
    );
  },
  async listUpstreams(db, operatorId, logger) {
    return dbAll(
      db,
      "operator_upstreams.list_enabled",
      () =>
        db
          .prepare("SELECT * FROM operator_upstreams WHERE operator_id = ? AND enabled = 1 ORDER BY priority DESC, created_at DESC")
          .bind(operatorId)
          .all(),
      logger
    );
  },
  async listUpstreamsAll(db, operatorId, logger) {
    return dbAll(
      db,
      "operator_upstreams.list_all",
      () => db.prepare("SELECT * FROM operator_upstreams WHERE operator_id = ? ORDER BY priority DESC, created_at DESC").bind(operatorId).all(),
      logger
    );
  },
  async createUpstream(db, env, operatorId, payload, logger) {
    const encryptedUrl = await encryptUpstreamUrl(env, payload.url);
    await dbRun(
      db,
      "operator_upstreams.create",
      () =>
        db
          .prepare(
            "INSERT INTO operator_upstreams (id, operator_id, url, enabled, weight, priority, headers_json, format_hint, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
          .bind(
            crypto.randomUUID(),
            operatorId,
            encryptedUrl,
            payload.enabled ? 1 : 0,
            payload.weight ?? 1,
            payload.priority ?? 0,
            payload.headers_json || null,
            payload.format_hint || null,
            nowIso(),
            nowIso()
          )
          .run(),
      logger
    );
  },
  async updateUpstream(db, env, operatorId, upstreamId, patch, logger) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const mutatedPatch = { ...patch };
    if (mutatedPatch.url) mutatedPatch.url = await encryptUpstreamUrl(env, mutatedPatch.url);
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => mutatedPatch[field]);
    await dbRun(
      db,
      "operator_upstreams.update",
      () => db.prepare(`UPDATE operator_upstreams SET ${setClause}, updated_at = ? WHERE id = ? AND operator_id = ?`).bind(...values, nowIso(), upstreamId, operatorId).run(),
      logger
    );
  },
  async listCustomerLinks(db, operatorId, logger) {
    return dbAll(db, "customer_links.list", () => db.prepare("SELECT * FROM customer_links WHERE operator_id = ? ORDER BY created_at DESC").bind(operatorId).all(), logger);
  },
  async getCustomerLinkByToken(db, token, logger) {
    return dbFirst(
      db,
      "customer_links.get_by_token",
      () => db.prepare("SELECT * FROM customer_links WHERE public_token = ? AND enabled = 1 AND revoked_at IS NULL").bind(token).first(),
      logger
    );
  },
  async getCustomerLinkById(db, operatorId, id, logger) {
    return dbFirst(
      db,
      "customer_links.get_by_id",
      () => db.prepare("SELECT * FROM customer_links WHERE id = ? AND operator_id = ?").bind(id, operatorId).first(),
      logger
    );
  },
  async getPrimaryCustomerLink(db, operatorId, logger) {
    return dbFirst(
      db,
      "customer_links.get_primary",
      () =>
        db
          .prepare("SELECT * FROM customer_links WHERE operator_id = ? AND enabled = 1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
          .bind(operatorId)
          .first(),
      logger
    );
  },
  async createCustomerLink(db, operatorId, label, overrides, logger) {
    const id = crypto.randomUUID();
    const token = crypto.randomUUID();
    await dbRun(
      db,
      "customer_links.create",
      () =>
        db
          .prepare(
            "INSERT INTO customer_links (id, operator_id, public_token, label, enabled, overrides_json, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)"
          )
          .bind(id, operatorId, token, label || null, overrides ? JSON.stringify(overrides) : null, nowIso(), nowIso())
          .run(),
      logger
    );
    return this.getCustomerLinkById(db, operatorId, id, logger);
  },
  async rotateCustomerLink(db, operatorId, id, logger) {
    const now = nowIso();
    await dbRun(
      db,
      "customer_links.rotate",
      () =>
        db
          .prepare("UPDATE customer_links SET enabled = 0, revoked_at = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
          .bind(now, now, id, operatorId)
          .run(),
      logger
    );
    return this.createCustomerLink(db, operatorId, null, null, logger);
  },
  async updateCustomerLinkOverrides(db, operatorId, id, overrides, logger) {
    await dbRun(
      db,
      "customer_links.update_overrides",
      () =>
        db
          .prepare("UPDATE customer_links SET overrides_json = ?, updated_at = ? WHERE id = ? AND operator_id = ?")
          .bind(overrides ? JSON.stringify(overrides) : null, nowIso(), id, operatorId)
          .run(),
      logger
    );
  },
  async upsertLastKnownGood(db, operatorId, token, bodyValue, bodyFormat, headersJson, logger) {
    await dbRun(
      db,
      "last_known_good.upsert",
      () =>
        db
          .prepare(
            "INSERT INTO last_known_good (operator_id, public_token, body_value, body_format, headers_json, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(operator_id, public_token) DO UPDATE SET body_value = excluded.body_value, body_format = excluded.body_format, headers_json = excluded.headers_json, updated_at = excluded.updated_at"
          )
          .bind(operatorId, token, bodyValue, bodyFormat, headersJson, nowIso())
          .run(),
      logger
    );
  },
  async getLastKnownGood(db, operatorId, token, logger) {
    return dbFirst(
      db,
      "last_known_good.get",
      () => db.prepare("SELECT * FROM last_known_good WHERE operator_id = ? AND public_token = ?").bind(operatorId, token).first(),
      logger
    );
  },
  async upsertSnapshot(db, snapshot, logger) {
    await dbRun(
      db,
      "snapshots.upsert",
      () =>
        db
          .prepare(
            "INSERT INTO snapshots (token, operator_id, body_value, body_format, headers_json, updated_at, ttl_sec, quotas_json, notify_fetches, last_fetch_notify_at, channel_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET body_value = excluded.body_value, body_format = excluded.body_format, headers_json = excluded.headers_json, updated_at = excluded.updated_at, ttl_sec = excluded.ttl_sec, operator_id = excluded.operator_id, quotas_json = excluded.quotas_json, notify_fetches = excluded.notify_fetches, last_fetch_notify_at = excluded.last_fetch_notify_at, channel_id = excluded.channel_id"
          )
          .bind(
            snapshot.token,
            snapshot.operator_id,
            snapshot.body_value,
            snapshot.body_format,
            snapshot.headers_json,
            snapshot.updated_at,
            snapshot.ttl_sec,
            snapshot.quotas_json || null,
            snapshot.notify_fetches ?? APP.notifyFetchDefault,
            snapshot.last_fetch_notify_at || null,
            snapshot.channel_id || null
          )
          .run(),
      logger
    );
  },
  async getSnapshot(db, token, logger) {
    return dbFirst(db, "snapshots.get", () => db.prepare("SELECT * FROM snapshots WHERE token = ?").bind(token).first(), logger);
  },
  async getLatestSnapshotInfo(db, operatorId, logger) {
    return dbFirst(
      db,
      "snapshots.get_latest_info",
      () =>
        db
          .prepare("SELECT token, updated_at, ttl_sec FROM snapshots WHERE operator_id = ? ORDER BY updated_at DESC LIMIT 1")
          .bind(operatorId)
          .first(),
      logger
    );
  },
  async bumpUpstreamFailure(db, upstreamId, failureCount, cooldownUntil, logger) {
    await dbRun(
      db,
      "operator_upstreams.bump_failure",
      () =>
        db
          .prepare("UPDATE operator_upstreams SET failure_count = ?, cooldown_until = ?, last_failure_at = ? WHERE id = ?")
          .bind(failureCount, cooldownUntil, nowIso(), upstreamId)
          .run(),
      logger
    );
  },
  async clearUpstreamFailure(db, upstreamId, logger) {
    await dbRun(
      db,
      "operator_upstreams.clear_failure",
      () =>
        db
          .prepare("UPDATE operator_upstreams SET failure_count = 0, cooldown_until = NULL, last_success_at = ? WHERE id = ?")
          .bind(nowIso(), upstreamId)
          .run(),
      logger
    );
  },
  async createNotifyJob(db, payload, logger) {
    await dbRun(
      db,
      "notify_jobs.create",
      () =>
        db
          .prepare(
            "INSERT INTO notify_jobs (id, operator_id, payload_json, status, attempts, available_at, created_at, updated_at) VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)"
          )
          .bind(crypto.randomUUID(), payload.operator_id || null, JSON.stringify(payload), Date.now(), nowIso(), nowIso())
          .run(),
      logger
    );
  },
  async listNotifyJobs(db, limit = 10, logger) {
    return dbAll(
      db,
      "notify_jobs.list_pending",
      () =>
        db
          .prepare("SELECT * FROM notify_jobs WHERE status = 'pending' AND available_at <= ? ORDER BY created_at ASC LIMIT ?")
          .bind(Date.now(), limit)
          .all(),
      logger
    );
  },
  async updateNotifyJob(db, id, patch, logger) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    const setClause = fields.map((field) => `${field} = ?`).join(", ");
    const values = fields.map((field) => patch[field]);
    await dbRun(
      db,
      "notify_jobs.update",
      () => db.prepare(`UPDATE notify_jobs SET ${setClause}, updated_at = ? WHERE id = ?`).bind(...values, nowIso(), id).run(),
      logger
    );
  },
  async purgeOldRecords(db, retentionMs, logger) {
    await dbRun(
      db,
      "audit_logs.purge",
      () => db.prepare("DELETE FROM audit_logs WHERE created_at < ?").bind(new Date(Date.now() - retentionMs).toISOString()).run(),
      logger
    );
    await dbRun(
      db,
      "rate_limits.purge",
      () => db.prepare("DELETE FROM rate_limits WHERE updated_at < ?").bind(new Date(Date.now() - retentionMs).toISOString()).run(),
      logger
    );
    await dbRun(
      db,
      "notify_jobs.purge",
      () => db.prepare("DELETE FROM notify_jobs WHERE created_at < ? AND status = 'done'").bind(new Date(Date.now() - retentionMs).toISOString()).run(),
      logger
    );
  },
  async createApiKey(db, operatorId, keyHash, scopesJson, logger) {
    await dbRun(
      db,
      "api_keys.create",
      () =>
        db
          .prepare("INSERT INTO api_keys (id, operator_id, key_hash, scopes_json, created_at) VALUES (?, ?, ?, ?, ?)")
          .bind(crypto.randomUUID(), operatorId, keyHash, scopesJson || null, nowIso())
          .run(),
      logger
    );
  },
  async getApiKeyByHash(db, keyHash, logger) {
    return dbFirst(db, "api_keys.get_by_hash", () => db.prepare("SELECT * FROM api_keys WHERE key_hash = ?").bind(keyHash).first(), logger);
  },
  async touchApiKey(db, keyHash, logger) {
    await dbRun(db, "api_keys.touch", () => db.prepare("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?").bind(nowIso(), keyHash).run(), logger);
  },
  async createInviteCode(db, code, operatorId, logger) {
    await dbRun(
      db,
      "invite_codes.create",
      () => db.prepare("INSERT INTO invite_codes (code, created_by, created_at) VALUES (?, ?, ?)").bind(code, operatorId, nowIso()).run(),
      logger
    );
  },
  async getInviteCode(db, code, logger) {
    return dbFirst(db, "invite_codes.get", () => db.prepare("SELECT * FROM invite_codes WHERE code = ?").bind(code).first(), logger);
  },
  async useInviteCode(db, code, operatorId, logger) {
    await dbRun(
      db,
      "invite_codes.use",
      () => db.prepare("UPDATE invite_codes SET used_by = ?, used_at = ? WHERE code = ? AND used_at IS NULL").bind(operatorId, nowIso(), code).run(),
      logger
    );
  },
  async logAudit(db, payload, logger) {
    const id = crypto.randomUUID();
    await dbRun(
      db,
      "audit_logs.create",
      () =>
        db
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
          .run(),
      logger
    );
  },
  async listAuditLogs(db, operatorId, limit = 5, logger) {
    return dbAll(
      db,
      "audit_logs.list",
      () => db.prepare("SELECT * FROM audit_logs WHERE operator_id = ? ORDER BY created_at DESC LIMIT ?").bind(operatorId, limit).all(),
      logger
    );
  },
  async bumpRateLimit(db, key, windowMs, max, logger) {
    const now = Date.now();
    const existing = await dbFirst(db, "rate_limits.get", () => db.prepare("SELECT * FROM rate_limits WHERE key = ?").bind(key).first(), logger);
    if (!existing || now - existing.window_start > windowMs) {
      await dbRun(
        db,
        "rate_limits.upsert",
        () =>
          db
            .prepare(
              "INSERT INTO rate_limits (key, count, window_start, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count, window_start = excluded.window_start, updated_at = excluded.updated_at"
            )
            .bind(key, 1, now, nowIso())
            .run(),
        logger
      );
      return true;
    }
    const nextCount = existing.count + 1;
    await dbRun(
      db,
      "rate_limits.update",
      () => db.prepare("UPDATE rate_limits SET count = ?, updated_at = ? WHERE key = ?").bind(nextCount, nowIso(), key).run(),
      logger
    );
    return nextCount <= max;
  },
};

// =============================
// Domain Services
// =============================
const OperatorService = {
  async ensureOperator(db, telegramUser, env, logger) {
    let operator = await D1.getOperatorByTelegramId(db, telegramUser.id, logger);
    if (!operator && isAdmin(telegramUser.id, env)) {
      operator = await D1.createOperator(
        db,
        telegramUser.id,
        telegramUser.first_name || telegramUser.username,
        "admin",
        "active",
        logger
      );
    }
    if (!operator) return null;
    if (operator.status !== "active") return operator;
    await D1.touchOperator(db, operator.id, logger);
    return operator;
  },
  async getShareToken(db, operatorId, logger) {
    const share = await D1.getPrimaryCustomerLink(db, operatorId, logger);
    return share?.public_token || "";
  },
  async getBrandingInfo(db, operator, env, logger) {
    const settings = await D1.getSettings(db, operator.id, logger);
    const shareToken = await this.getShareToken(db, operator.id, logger);
    const baseUrl = normalizeBaseUrl(env.BASE_URL || "");
    const nationalBaseUrl = normalizeBaseUrl(settings?.national_base_url || env.NATIONAL_BASE_URL || "");
    let domain = null;
    if (settings?.active_domain_id) {
      const active = await D1.getDomainById(db, settings.active_domain_id, logger);
      if (active?.verified) domain = active.domain;
    }
    return { settings, shareToken, baseUrl, nationalBaseUrl, domain };
  },
};

const SubscriptionAssembler = {
  async assemble(env, db, operatorId, panelToken, request, requestId, customerLink, preloaded = {}, logger) {
    const span = (logger || Logger).span("subscription_assemble", { operator_id: operatorId });
    try {
      const settings = preloaded.settings || (await D1.getSettings(db, operatorId, logger));
      const baseRules = preloaded.rules || (await D1.getRules(db, operatorId, logger));
      const overrides = safeJsonParse(customerLink?.overrides_json, {}, logger, {
        error_code: "E_JSON_PARSE",
        operator_id: operatorId,
        context: "customer_link_overrides",
      });
      const rules = { ...baseRules, ...overrides };
      const extras = preloaded.extras || (await D1.listEnabledExtras(db, operatorId, logger));
      const selectedExtras = overrides?.extras?.length
        ? (extras?.results || []).filter((item) => overrides.extras.includes(item.id))
        : (extras?.results || []);

      const upstreams = preloaded.upstreams || (await D1.listUpstreams(db, operatorId, logger));
      const allowlist = parseCommaList(settings?.upstream_allowlist);
      const denylist = parseCommaList(settings?.upstream_denylist);

      if (!(upstreams?.results || []).length) {
        await D1.updateSettings(db, operatorId, { last_upstream_status: "unset", last_upstream_at: nowIso() }, logger);
        await D1.logAudit(
          db,
          {
            operator_id: operatorId,
            event_type: "upstream_unset",
            ip: request.headers.get("cf-connecting-ip"),
            country: request.headers.get("cf-ipcountry"),
            user_agent: request.headers.get("user-agent"),
            request_path: new URL(request.url).pathname,
            response_status: 502,
            meta_json: JSON.stringify({ reason: "no_upstreams", request_id: requestId }),
          },
          logger
        );
        return { body: "", headers: { ...DEFAULT_HEADERS }, valid: false, reason: "no_upstreams", upstreamStatus: "unset" };
      }

      const upstreamPayloads = await this.fetchUpstreams(env, db, upstreams?.results || [], allowlist, denylist, panelToken, logger);
      const selected = this.selectUpstreamsByPolicy(upstreamPayloads, rules?.merge_policy || "append", logger);
      const extrasContent = selectedExtras.map((item) => item.content).join("\n");

      if (!selected.ok) {
        const hasOk = upstreamPayloads.some((item) => item.ok);
        const reason = summarizeUpstreamFailures(upstreamPayloads);
        await D1.updateSettings(db, operatorId, { last_upstream_status: hasOk ? "invalid" : "error", last_upstream_at: nowIso() }, logger);
        await D1.logAudit(
          db,
          {
            operator_id: operatorId,
            event_type: "upstream_invalid",
            ip: request.headers.get("cf-connecting-ip"),
            country: request.headers.get("cf-ipcountry"),
            user_agent: request.headers.get("user-agent"),
            request_path: new URL(request.url).pathname,
            response_status: 502,
            meta_json: JSON.stringify({ reason, request_id: requestId }),
          },
          logger
        );
        await AuditService.notifyOperator(env, settings, `⚠️ آپ‌استریم نامعتبر بود برای <b>${safeHtml(settings?.branding || "اپراتور")}</b>`, logger);
        (logger || Logger).warn("upstream_invalid", {
          error_code: "E_UPSTREAM_INVALID",
          reason: ERROR_CODES.E_UPSTREAM_INVALID.reason,
          hints: ERROR_CODES.E_UPSTREAM_INVALID.hints,
          operator_id: operatorId,
        });
        return {
          body: "",
          headers: { ...DEFAULT_HEADERS },
          valid: false,
          reason,
          upstreamStatus: hasOk ? "invalid" : "error",
        };
      }

      await D1.updateSettings(db, operatorId, { last_upstream_status: "ok", last_upstream_at: nowIso() }, logger);

      const merged = this.mergeContent(selected.text, extrasContent, rules);
      const processed = this.applyRules(merged, rules, logger);
      const limited = limitOutput(processed.split("\n"), rules?.limit_lines || APP.maxOutputLines, rules?.limit_bytes || APP.maxOutputBytes);
      const outputBody = limited.join("\n");
      const formatted = rules?.output_format === "plain" ? outputBody : utf8SafeEncode(outputBody);

      span.end({ operator_id: operatorId, output_bytes: outputBody.length });
      return {
        body: formatted,
        headers: {
          ...DEFAULT_HEADERS,
          ...(selected.subscriptionUserinfo ? { "subscription-userinfo": selected.subscriptionUserinfo } : {}),
        },
        valid: true,
        decodeReason: selected.decodeReason,
        upstreamStatus: "ok",
      };
    } catch (err) {
      span.fail(err, { operator_id: operatorId, error_code: "E_INTERNAL", reason: ERROR_CODES.E_INTERNAL.reason });
      throw err;
    }
  },
  async fetchUpstreams(env, db, upstreams, allowlist, denylist, panelToken, logger) {
    const span = (logger || Logger).span("upstreams_fetch", { upstream_count: upstreams.length });
    const now = Date.now();
    const results = await mapWithConcurrency(upstreams, APP.upstreamMaxConcurrency, async (upstream) => {
      const cooldownUntil = upstream.cooldown_until ? Date.parse(upstream.cooldown_until) : 0;
      if (cooldownUntil && cooldownUntil > now) {
        return { ok: false, status: 429, body: "", subscriptionUserinfo: null, isBase64: false, error: "cooldown", upstream };
      }
      const decryptedUrl = await decryptUpstreamUrl(env, upstream.url);
      const requestUrl = resolveUpstreamUrl(decryptedUrl, upstream.format_hint, panelToken);
      const validation = assertSafeUpstream(requestUrl, allowlist, denylist);
      if (!validation.ok) {
        (logger || Logger).warn("upstream_blocked", {
          error_code: "E_SSRF_BLOCKED",
          reason: ERROR_CODES.E_SSRF_BLOCKED.reason,
          hints: ERROR_CODES.E_SSRF_BLOCKED.hints,
          upstream: redactUrlForLog(requestUrl),
          blocked_reason: validation.error,
        });
        return { ok: false, status: 400, body: "", subscriptionUserinfo: null, isBase64: false, error: validation.error, upstream };
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), APP.upstreamTimeoutMs);
      try {
        const headers = upstream.headers_json
          ? safeJsonParse(upstream.headers_json, { "user-agent": "v2rayNG" }, logger, {
              error_code: "E_JSON_PARSE",
              context: "upstream_headers",
            })
          : { "user-agent": "v2rayNG" };
        const res = await fetchWithRedirects(
          requestUrl,
          { cf: { cacheTtl: 0 }, signal: controller.signal, headers },
          APP.maxRedirects,
          (nextUrl) => assertSafeUpstream(nextUrl, allowlist, denylist),
          logger
        );
        const text = await res.text();
        const decodeInfo = res.ok ? analyzeUpstreamBody(text) : { isBase64: false, reason: null };
        if (new TextEncoder().encode(text).length > APP.maxOutputBytes) {
          return { ok: false, status: 413, body: "", subscriptionUserinfo: null, isBase64: false, error: "too_large", upstream };
        }
        clearTimeout(timeout);
        if (res.ok) {
          await D1.clearUpstreamFailure(db, upstream.id, logger);
        } else {
          const nextFailure = Math.min(APP.upstreamFailureThreshold, (upstream.failure_count || 0) + 1);
          const cooldown = nextFailure >= APP.upstreamFailureThreshold ? new Date(Date.now() + APP.upstreamCooldownMs).toISOString() : null;
          await D1.bumpUpstreamFailure(db, upstream.id, nextFailure, cooldown, logger);
        }
        return {
          ok: res.ok,
          status: res.status,
          body: text,
          subscriptionUserinfo: res.headers.get("subscription-userinfo"),
          isBase64: decodeInfo.isBase64,
          decodeReason: decodeInfo.reason,
          upstream,
        };
      } catch (err) {
        clearTimeout(timeout);
        const isTimeout = err?.name === "AbortError";
        (logger || Logger).error("upstream_fetch_failed", err, {
          error_code: "E_UPSTREAM_FETCH",
          reason: ERROR_CODES.E_UPSTREAM_FETCH.reason,
          hints: ERROR_CODES.E_UPSTREAM_FETCH.hints,
          upstream: redactUrlForLog(decryptedUrl),
        });
        const nextFailure = Math.min(APP.upstreamFailureThreshold, (upstream.failure_count || 0) + 1);
        const cooldown = nextFailure >= APP.upstreamFailureThreshold ? new Date(Date.now() + APP.upstreamCooldownMs).toISOString() : null;
        await D1.bumpUpstreamFailure(db, upstream.id, nextFailure, cooldown, logger);
        return {
          ok: false,
          status: 502,
          body: "",
          subscriptionUserinfo: null,
          isBase64: false,
          error: isTimeout ? "timeout" : "fetch_failed",
          upstream,
        };
      }
    });
    span.end({ upstream_ok: results.filter((item) => item.ok).length });
    return results;
  },
  selectUpstreamsByPolicy(results, policy, logger) {
    (logger || Logger).info("upstream_select_policy", { policy, candidates: results.length });
    const valid = results.filter((item) => item.ok && isValidSubscriptionText(this.decodeSubscription(item.body, item.isBase64)));
    if (!valid.length) {
      (logger || Logger).warn("upstream_selection_empty", {
        error_code: "E_UPSTREAM_INVALID",
        reason: ERROR_CODES.E_UPSTREAM_INVALID.reason,
        hints: ERROR_CODES.E_UPSTREAM_INVALID.hints,
      });
      return { ok: false, text: "", subscriptionUserinfo: null };
    }
    const decodeReason = valid.some((item) => item.decodeReason === "urlsafe_base64")
      ? "urlsafe_base64"
      : valid[0]?.decodeReason || null;
    if (policy === "upstream_only") {
      const first = valid[0];
      return {
        ok: true,
        text: this.decodeSubscription(first.body, first.isBase64),
        subscriptionUserinfo: first.subscriptionUserinfo,
        decodeReason,
      };
    }
    if (policy === "failover") {
      const first = valid[0];
      return {
        ok: true,
        text: this.decodeSubscription(first.body, first.isBase64),
        subscriptionUserinfo: first.subscriptionUserinfo,
        decodeReason,
      };
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
      return { ok: true, text: merged.join("\n"), subscriptionUserinfo: valid[0].subscriptionUserinfo, decodeReason };
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
      return { ok: true, text: merged.join("\n"), subscriptionUserinfo: valid[0].subscriptionUserinfo, decodeReason };
    }
    const combined = valid.map((item) => this.decodeSubscription(item.body, item.isBase64)).join("\n");
    return { ok: true, text: combined, subscriptionUserinfo: valid[0].subscriptionUserinfo, decodeReason };
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
  applyRules(content, rules, logger) {
    (logger || Logger).debug("apply_rules_start", {
      sanitize: rules?.sanitize,
      dedupe: rules?.dedupe,
      naming_mode: rules?.naming_mode,
    });
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
    (logger || Logger).debug("apply_rules_end", { output_lines: processed.length });
    return processed.join("\n");
  },
};

const testUpstreamConnection = async (env, db, operatorId, panelToken, logger) => {
  const scopedLogger = (logger || Logger).child({ operator_id: operatorId, token_prefix: panelToken.slice(0, 6) });
  try {
    const settings = await D1.getSettings(db, operatorId, scopedLogger);
    const upstreams = await D1.listUpstreams(db, operatorId, scopedLogger);
    const list = upstreams?.results || [];
    if (!list.length) {
      await D1.updateSettings(db, operatorId, { last_upstream_status: "unset", last_upstream_at: nowIso() }, scopedLogger);
      return;
    }
    const targetUpstream = list[0];
    const decryptedUrl = await decryptUpstreamUrl(env, targetUpstream.url);
    const requestUrl = resolveUpstreamUrl(decryptedUrl, targetUpstream.format_hint, panelToken);
    const allowlist = parseCommaList(settings?.upstream_allowlist);
    const denylist = parseCommaList(settings?.upstream_denylist);
    const validation = assertSafeUpstream(requestUrl, allowlist, denylist);
    if (!validation.ok) {
      await D1.updateSettings(db, operatorId, { last_upstream_status: "invalid", last_upstream_at: nowIso() }, scopedLogger);
      return;
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), APP.upstreamTimeoutMs);
    let response;
    try {
      response = await fetchWithRedirects(
        requestUrl,
        { signal: controller.signal, headers: { "user-agent": "EdgeSubscriptionBot/1.0" } },
        APP.maxRedirects,
        (url) => assertSafeUpstream(url, allowlist, denylist),
        scopedLogger
      );
    } finally {
      clearTimeout(timeout);
    }
    if (!response || response.status >= 400) {
      await D1.updateSettings(db, operatorId, { last_upstream_status: "error", last_upstream_at: nowIso() }, scopedLogger);
      return;
    }
    const body = await response.text();
    const decodeInfo = analyzeUpstreamBody(body);
    const decoded = decodeInfo.isBase64 ? utf8SafeDecode(body) : body;
    if (!isValidSubscriptionText(decoded)) {
      await D1.updateSettings(db, operatorId, { last_upstream_status: "invalid", last_upstream_at: nowIso() }, scopedLogger);
      return;
    }
    await D1.updateSettings(db, operatorId, { last_upstream_status: "ok", last_upstream_at: nowIso() }, scopedLogger);
  } catch (err) {
    (logger || Logger).warn("upstream_test_failed", { error: normalizeError(err), operator_id: operatorId });
    await D1.updateSettings(db, operatorId, { last_upstream_status: "error", last_upstream_at: nowIso() }, scopedLogger);
  }
};

const NotificationService = {
  async enqueue(env, payload, logger) {
    if (!payload?.messageHtml) return;
    if (env.NOTIFY_QUEUE) {
      await env.NOTIFY_QUEUE.send(payload);
      return;
    }
    await D1.createNotifyJob(env.DB, payload, logger);
  },
  async sendWithBackoff(env, payload, attempt = 0, logger) {
    const channelId = payload?.channel_id || env.LOG_CHANNEL_ID;
    if (!channelId || !env.TELEGRAM_TOKEN) return false;
    const maxAttempts = 4;
    for (let i = attempt; i < maxAttempts; i += 1) {
      const result = await telegramFetch(
        "sendMessage",
        {
          chat_id: channelId,
          text: payload.messageHtml,
          parse_mode: "HTML",
          disable_web_page_preview: true,
        },
        { env, logger, label: "telegram_notify_message" }
      );
      if (result.ok) return true;
      (logger || Logger).error("telegram_notify_failed", new Error("Telegram API responded with non-2xx"), {
        error_code: "E_TELEGRAM_API",
        reason: "Telegram API responded with non-2xx",
        hints: telegramHintsForStatus(result.status),
        status: result.status,
        telegram: result.telegram,
      });
      const delayMs = Math.min(30_000, 1000 * 2 ** i);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    return false;
  },
  async processQueueMessage(env, message, logger) {
    const ok = await this.sendWithBackoff(env, message?.body || message, 0, logger);
    if (!ok) throw new Error("notify_failed");
  },
  async processPendingJobs(env, logger) {
    const jobs = await D1.listNotifyJobs(env.DB, 20, logger);
    for (const job of jobs?.results || []) {
      const payload = safeJsonParse(job.payload_json, null, logger, { error_code: "E_JSON_PARSE", context: "notify_job_payload" });
      const ok = await this.sendWithBackoff(env, payload, job.attempts || 0, logger);
      if (ok) {
        await D1.updateNotifyJob(env.DB, job.id, { status: "done" }, logger);
      } else {
        const nextAttempts = (job.attempts || 0) + 1;
        const delayMs = Math.min(60_000, 1000 * 2 ** nextAttempts);
        await D1.updateNotifyJob(
          env.DB,
          job.id,
          {
            attempts: nextAttempts,
            available_at: Date.now() + delayMs,
            status: "pending",
          },
          logger
        );
      }
    }
  },
};

const AuditService = {
  async notifyOperator(env, settings, messageHtml, logger) {
    await NotificationService.enqueue(
      env,
      {
        operator_id: settings?.operator_id,
        channel_id: settings?.channel_id,
        messageHtml,
      },
      logger
    );
  },
};

const AuthService = {
  async getAuthContext(request, env, db, logger) {
    const authHeader = request.headers.get("authorization") || "";
    if (authHeader.startsWith("Bearer ")) {
      const token = authHeader.replace("Bearer ", "").trim();
      if (!token || !env.SESSION_SECRET) {
        (logger || Logger).warn("auth_missing_token", {
          error_code: "E_AUTH_UNAUTHORIZED",
          reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
          hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
        });
        return null;
      }
      const payload = await verifySession(token, env.SESSION_SECRET);
      if (!payload || payload.exp < Math.floor(Date.now() / 1000)) {
        (logger || Logger).warn("auth_session_invalid", {
          error_code: "E_AUTH_UNAUTHORIZED",
          reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
          hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
        });
        return null;
      }
      const operator = await D1.getOperatorById(db, payload.sub, logger);
      if (!operator || operator.status !== "active") {
        (logger || Logger).warn("auth_operator_inactive", {
          error_code: "E_AUTH_FORBIDDEN",
          reason: ERROR_CODES.E_AUTH_FORBIDDEN.reason,
          hints: ERROR_CODES.E_AUTH_FORBIDDEN.hints,
          operator_id: payload.sub,
        });
        return null;
      }
      const tokenHash = await hashApiKey(token);
      (logger || Logger).info("auth_session_ok", {
        operator_id: operator.id,
        token_prefix: token.slice(0, 6),
        token_hash: tokenHash.slice(0, 16),
      });
      return { operator, tokenType: "session" };
    }
    const apiKey = request.headers.get("x-api-key");
    if (apiKey) {
      const hash = await hashApiKey(apiKey);
      const key = await D1.getApiKeyByHash(db, hash, logger);
      if (!key) {
        (logger || Logger).warn("auth_api_key_invalid", {
          error_code: "E_AUTH_UNAUTHORIZED",
          reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
          hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
        });
        return null;
      }
      const operator = await D1.getOperatorById(db, key.operator_id, logger);
      if (!operator || operator.status !== "active") {
        (logger || Logger).warn("auth_api_key_forbidden", {
          error_code: "E_AUTH_FORBIDDEN",
          reason: ERROR_CODES.E_AUTH_FORBIDDEN.reason,
          hints: ERROR_CODES.E_AUTH_FORBIDDEN.hints,
          operator_id: key.operator_id,
        });
        return null;
      }
      await D1.touchApiKey(db, hash, logger);
      (logger || Logger).info("auth_api_key_ok", {
        operator_id: operator.id,
        token_hash: hash.slice(0, 16),
      });
      return { operator, tokenType: "api_key" };
    }
    (logger || Logger).warn("auth_missing", {
      error_code: "E_AUTH_UNAUTHORIZED",
      reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
      hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
    });
    return null;
  },
};

const SnapshotService = {
  async getSnapshot(env, token, logger) {
    if (env.SNAP_KV) {
      const entry = await env.SNAP_KV.get(token, "json");
      return entry;
    }
    return D1.getSnapshot(env.DB, token, logger);
  },
  async setSnapshot(env, snapshot, logger) {
    const payload = {
      token: snapshot.token,
      operator_id: snapshot.operator_id,
      body_value: snapshot.body_value,
      body_format: snapshot.body_format,
      headers_json: snapshot.headers_json,
      updated_at: snapshot.updated_at,
      ttl_sec: snapshot.ttl_sec,
      quotas_json: snapshot.quotas_json || null,
      notify_fetches: snapshot.notify_fetches ?? APP.notifyFetchDefault,
      last_fetch_notify_at: snapshot.last_fetch_notify_at || null,
      channel_id: snapshot.channel_id || null,
    };
    if (env.SNAP_KV) {
      await env.SNAP_KV.put(snapshot.token, JSON.stringify(payload), { expirationTtl: snapshot.ttl_sec });
    }
    await D1.upsertSnapshot(env.DB, snapshot, logger);
  },
  async getLastKnownGood(env, operatorId, token, logger) {
    return D1.getLastKnownGood(env.DB, operatorId, token, logger);
  },
};

const buildSnapshotHeaders = (snapshot, requestId, logger) => {
  const headers = snapshot.headers_json
    ? safeJsonParse(snapshot.headers_json, DEFAULT_HEADERS, logger, {
        error_code: "E_JSON_PARSE",
        context: "snapshot_headers",
      })
    : DEFAULT_HEADERS;
  return {
    ...headers,
    "content-disposition": headers["content-disposition"] || `inline; filename=sub_${snapshot.token}.txt`,
    "x-request-id": requestId,
    "cache-control": "no-store",
  };
};

const buildSnapshotResponse = (snapshot, requestId, logger) => {
  const headers = buildSnapshotHeaders(snapshot, requestId, logger);
  return new Response(snapshot.body_value || "", { headers });
};

const persistSnapshot = async (env, db, payload, logger) => {
  const { operatorId, subscriptionToken, assembled, settings, rules, request, requestId } = payload;
  const responseHeadersBase = { ...assembled.headers, "content-disposition": `inline; filename=sub_${subscriptionToken}.txt` };
  const bodyFormat = rules?.output_format === "plain" ? "plain" : "base64";
  const snapshot = {
    token: subscriptionToken,
    operator_id: operatorId,
    body_value: assembled.body,
    body_format: bodyFormat,
    headers_json: JSON.stringify(responseHeadersBase),
    updated_at: nowIso(),
    ttl_sec: APP.snapshotTtlSec,
    quotas_json: settings?.quotas_json || null,
    notify_fetches: settings?.notify_fetches ?? APP.notifyFetchDefault,
    last_fetch_notify_at: settings?.last_fetch_notify_at || null,
    channel_id: settings?.channel_id || null,
  };
  setCachedSub(`sub:${subscriptionToken}`, assembled.body, responseHeadersBase, { snapshot });
  setLastGoodMem(`sub:${subscriptionToken}`, assembled.body, responseHeadersBase, { body_format: bodyFormat });
  await SnapshotService.setSnapshot(env, snapshot, logger);
  await D1.upsertLastKnownGood(db, operatorId, subscriptionToken, assembled.body, bodyFormat, JSON.stringify(responseHeadersBase), logger);
  const cacheUrl = new URL(`https://cache.internal/snap/${subscriptionToken}`);
  const cacheHeaders = {
    ...responseHeadersBase,
    "cache-control": `max-age=${APP.snapshotTtlSec}`,
    "x-snapshot-updated": snapshot.updated_at,
    "x-snapshot-ttl": String(snapshot.ttl_sec),
    "x-snapshot-format": snapshot.body_format,
    "x-operator-id": snapshot.operator_id,
    "x-snapshot-quotas": snapshot.quotas_json || "",
    "x-snapshot-notify": String(snapshot.notify_fetches ?? APP.notifyFetchDefault),
    "x-snapshot-last-notify": snapshot.last_fetch_notify_at || "",
    "x-snapshot-channel": snapshot.channel_id || "",
  };
  await caches.default.put(cacheUrl, new Response(assembled.body, { headers: cacheHeaders, status: 200 }));
  await D1.logAudit(
    db,
    {
      operator_id: operatorId,
      event_type: "snapshot_refresh_ok",
      ip: request.headers.get("cf-connecting-ip"),
      country: request.headers.get("cf-ipcountry"),
      user_agent: request.headers.get("user-agent"),
      request_path: new URL(request.url).pathname,
      response_status: 200,
      meta_json: JSON.stringify({
        request_id: requestId,
        ...(assembled.decodeReason === "urlsafe_base64" ? { reason: "urlsafe_base64" } : {}),
      }),
    },
    logger
  );
  return { snapshot, responseHeadersBase, bodyFormat };
};

const assembleWithTimeout = async (promise, timeoutMs) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const err = new Error("timeout");
          err.name = "TimeoutError";
          reject(err);
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const refreshSnapshot = async (env, operatorId, subscriptionToken, panelToken, request, requestId, customerLink, logger) => {
  if (!operatorId || !subscriptionToken) return;
  const db = env.DB;
  const scopedLogger = (logger || Logger).child({ operator_id: operatorId });
  const [settings, rules, extras, upstreams] = await Promise.all([
    D1.getSettings(db, operatorId, scopedLogger),
    D1.getRules(db, operatorId, scopedLogger),
    D1.listEnabledExtras(db, operatorId, scopedLogger),
    D1.listUpstreams(db, operatorId, scopedLogger),
  ]);
  const assembled = await SubscriptionAssembler.assemble(
    env,
    db,
    operatorId,
    panelToken,
    request,
    requestId,
    customerLink,
    {
      settings,
      rules,
      extras,
      upstreams,
    },
    scopedLogger
  );
  if (assembled.valid) {
    await persistSnapshot(
      env,
      db,
      { operatorId, subscriptionToken, assembled, settings, rules, request, requestId },
      scopedLogger
    );
  } else {
    await D1.logAudit(
      db,
      {
        operator_id: operatorId,
        event_type: "snapshot_refresh_failed",
        ip: request.headers.get("cf-connecting-ip"),
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 502,
        meta_json: JSON.stringify({ request_id: requestId, reason: assembled.reason || "upstream_invalid" }),
      },
      scopedLogger
    );
    await AuditService.notifyOperator(
      env,
      settings,
      `⚠️ بروزرسانی اسنپ‌شات ناموفق بود برای <b>${safeHtml(settings?.branding || "اپراتور")}</b>.`,
      scopedLogger
    );
  }
};

// =============================
// Telegram Adapter
// =============================
const Telegram = {
  async handleWebhook(request, env, ctx, logger) {
    const span = (logger || Logger).span("telegram_webhook");
    if (env.TELEGRAM_SECRET) {
      const secret = request.headers.get("x-telegram-bot-api-secret-token");
      if (secret !== env.TELEGRAM_SECRET) {
        (logger || Logger).warn("telegram_webhook_secret_mismatch", {
          error_code: "E_AUTH_UNAUTHORIZED",
          reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
          hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
        });
        span.end({ status: 401 });
        return new Response("unauthorized", { status: 401 });
      }
    }
    if (!request.headers.get("content-type")?.includes("application/json")) {
      (logger || Logger).warn("telegram_webhook_unsupported", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
      });
      span.end({ status: 415 });
      return new Response("unsupported", { status: 415 });
    }
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength && contentLength > APP.maxWebhookBytes) {
      (logger || Logger).warn("telegram_webhook_too_large", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
        content_length: contentLength,
      });
      span.end({ status: 413 });
      return new Response("payload too large", { status: 413 });
    }

    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (!rateLimit(`tg:${ip}`)) {
      const ok = await D1.bumpRateLimit(env.DB, `tg:${ip}`, APP.rateLimitWindowMs, APP.rateLimitMax * 2, logger);
      if (!ok) {
        (logger || Logger).warn("telegram_rate_limited_ip", {
          error_code: "E_RATE_LIMIT",
          reason: ERROR_CODES.E_RATE_LIMIT.reason,
          hints: ERROR_CODES.E_RATE_LIMIT.hints,
          ip,
        });
        span.end({ status: 429 });
        return new Response("rate limit", { status: 429 });
      }
    }

    const bodyBuf = await request.arrayBuffer();
    if (bodyBuf.byteLength > APP.maxWebhookBytes) {
      (logger || Logger).warn("telegram_webhook_too_large", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
        content_length: bodyBuf.byteLength,
      });
      span.end({ status: 413 });
      return new Response("payload too large", { status: 413 });
    }
    const update = safeJsonParse(new TextDecoder().decode(bodyBuf), null, logger, {
      error_code: "E_JSON_PARSE",
      context: "telegram_webhook_payload",
    });
    if (!update) {
      (logger || Logger).warn("telegram_webhook_invalid_json", {
        error_code: "E_JSON_PARSE",
        reason: ERROR_CODES.E_JSON_PARSE.reason,
        hints: ERROR_CODES.E_JSON_PARSE.hints,
      });
      span.end({ status: 400 });
      return new Response("invalid", { status: 400 });
    }
    const message = update.message || update.callback_query?.message;
    const user = update.message?.from || update.callback_query?.from;
    if (!user) {
      span.end({ status: 200 });
      return new Response("ok");
    }
    if (!rateLimit(`tg-user:${user.id}`)) {
      (logger || Logger).warn("telegram_rate_limited_user", {
        error_code: "E_RATE_LIMIT",
        reason: ERROR_CODES.E_RATE_LIMIT.reason,
        hints: ERROR_CODES.E_RATE_LIMIT.hints,
        telegram_user_id: user.id,
      });
      span.end({ status: 429 });
      return new Response("rate limit", { status: 429 });
    }

    const db = env.DB;
    const text = update.message ? parseMessageText(update.message) : "";
    const operator = await OperatorService.ensureOperator(db, user, env, logger);
    if (!operator) {
      if (update.message && text.startsWith("/invite")) {
        const response = await this.handleInvite(env, db, user, text, logger);
        span.end({ status: response?.status || 200, action: "invite" });
        return response;
      }
      if (update.message && text.startsWith("/start")) {
        const payload = this.buildOnboardingMessage(env);
        await this.sendMessage(env, user.id, payload.text, payload.keyboard, logger, {
          telegram_user_id: user.id,
        });
        span.end({ status: 200, action: "onboarding" });
        return new Response("ok");
      }
      await this.sendMessage(env, user.id, "⚠️ این ربات فقط برای اپراتورها فعال است.", null, logger, {
        telegram_user_id: user.id,
      });
      span.end({ status: 200 });
      return new Response("ok");
    }

    const operatorLogger = (logger || Logger).child({ operator_id: operator.id, telegram_user_id: operator.telegram_user_id });
    if (operator.status === "pending") {
      await this.sendMessage(env, user.id, "⏳ حساب شما در انتظار تایید مدیر است.", null, operatorLogger);
      span.end({ status: 200 });
      return new Response("ok");
    }

    if (update.message) {
      const response = await this.handleMessage(env, db, operator, update.message, operatorLogger, ctx);
      span.end({ status: response?.status || 200 });
      return response;
    }
    if (update.callback_query) {
      const response = await this.handleCallback(env, db, operator, update.callback_query, operatorLogger);
      span.end({ status: response?.status || 200 });
      return response;
    }
    span.end({ status: 200 });
    return new Response("ok");
  },
  async handleMessage(env, db, operator, message, logger, ctx) {
    const scopedLogger = (logger || Logger).child({ operator_id: operator.id, telegram_user_id: operator.telegram_user_id });
    const span = scopedLogger.span("telegram_message", { operator_id: operator.id, telegram_user_id: operator.telegram_user_id });
    logger = scopedLogger;
    const text = parseMessageText(message);
    const settings = await D1.getSettings(db, operator.id, logger);

    if (text.startsWith("/invite")) {
      const response = await this.handleInvite(env, db, message.from, text, logger, operator);
      span.end({ action: "invite" });
      return response;
    }

    if (text === "/cancel") {
      await D1.setPendingAction(db, operator.id, null, null, logger);
      await this.sendMessage(env, message.chat.id, "✅ عملیات لغو شد.", null, logger);
      span.end({ action: "cancel" });
      return new Response("ok");
    }

    if (!text.startsWith("/") && settings?.pending_action) {
      const action = settings.pending_action;
      if (action === "set_upstream") {
        await D1.createUpstream(db, env, operator.id, { url: text, enabled: true, weight: 1, priority: 1 }, logger);
        await D1.setPendingAction(db, operator.id, null, null, logger);
        await D1.logAudit(
          db,
          {
            operator_id: operator.id,
            event_type: "settings_update:upstream_url",
            meta_json: JSON.stringify({ upstream: redactUrlForLog(text) }),
          },
          logger
        );
        await AuditService.notifyOperator(env, settings, "🧊 آپ‌استریم بروزرسانی شد.", logger);
        await this.sendMessage(env, message.chat.id, "✅ لینک آپ‌استریم ذخیره شد.", null, logger);
        span.end({ action: "set_upstream" });
        return new Response("ok");
      }
      if (action === "set_domain") {
        if (!isValidDomain(text)) {
          (logger || Logger).warn("domain_invalid", {
            error_code: "E_INPUT_INVALID",
            reason: ERROR_CODES.E_INPUT_INVALID.reason,
            hints: ERROR_CODES.E_INPUT_INVALID.hints,
            domain: text,
          });
          await this.sendMessage(env, message.chat.id, "❗️دامنه معتبر نیست.", null, logger);
          span.end({ action: "set_domain_invalid" });
          return new Response("ok");
        }
        await D1.createDomain(db, operator.id, text, logger);
        const domains = await D1.listDomains(db, operator.id, logger);
        const latest = domains?.results?.[0];
        if (latest) await D1.setDomainActive(db, operator.id, latest.id, logger);
        await D1.setPendingAction(db, operator.id, null, null, logger);
        await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:domain" }, logger);
        await AuditService.notifyOperator(env, settings, "🧊 دامنه بروزرسانی شد.", logger);
        const token = latest?.token ? `\nتوکن تایید: <code>${safeHtml(latest.token)}</code>` : "";
        await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد.${token}`, null, logger);
        span.end({ action: "set_domain" });
        return new Response("ok");
      }
      if (action === "set_channel") {
        await D1.updateSettings(db, operator.id, { channel_id: text }, logger);
        await D1.setPendingAction(db, operator.id, null, null, logger);
        await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:channel" }, logger);
        await AuditService.notifyOperator(env, { channel_id: text }, "✅ اتصال کانال تایید شد.", logger);
        await this.sendMessage(env, message.chat.id, "✅ کانال اطلاع‌رسانی ذخیره شد.", null, logger);
        span.end({ action: "set_channel" });
        return new Response("ok");
      }
    }

    if (!text.startsWith("/") && !settings?.pending_action) {
      const parsed = parsePanelSubscriptionInput(text);
      if (parsed?.token) {
        const panelToken = parsed.token;
        const username = decodePanelTokenUsername(panelToken);
        const upstreams = await D1.listUpstreams(db, operator.id, logger);
        const upstreamList = upstreams?.results || [];
        const templateUrl = parsed.template;
        let origin = parsed.base || parsed.origin;
        let upstreamUnset = !upstreamList.length;
        let templateCreated = false;
        if (!origin && upstreamList.length) {
          try {
            const existing = await decryptUpstreamUrl(env, upstreamList[0].url);
            origin = new URL(existing).origin;
          } catch {
            origin = null;
          }
        }
        if (!upstreamList.length && templateUrl) {
          await D1.createUpstream(
            db,
            env,
            operator.id,
            { url: templateUrl, enabled: true, weight: 1, priority: 1, format_hint: "template" },
            logger
          );
          templateCreated = true;
          await D1.updateSettings(db, operator.id, { last_upstream_status: "unset", last_upstream_at: nowIso() }, logger);
          await D1.logAudit(
            db,
            {
              operator_id: operator.id,
              event_type: "settings_update:upstream_auto",
              meta_json: JSON.stringify({ upstream: redactUrlForLog(templateUrl), format_hint: "template" }),
            },
            logger
          );
        } else if (!upstreamList.length) {
          await D1.updateSettings(db, operator.id, { last_upstream_status: "unset", last_upstream_at: nowIso() }, logger);
        }

        const branding = await OperatorService.getBrandingInfo(db, operator, env, logger);
        const prefixes = buildOperatorPrefixes({
          baseUrl: branding.baseUrl,
          nationalBaseUrl: branding.nationalBaseUrl,
          shareToken: branding.shareToken,
          domain: branding.domain,
        });
        if (!prefixes.mainPrefix) {
          await this.sendMessage(env, message.chat.id, "❗️Base URL تنظیم نشده است. لطفاً BASE_URL را تنظیم کنید.", null, logger);
          span.end({ action: "smart_paste_missing_base" });
          return new Response("ok");
        }
        const mainLink = `${prefixes.mainPrefix}${panelToken}`;
        const meliLink = prefixes.meliPrefix ? `${prefixes.meliPrefix}${panelToken}` : "";
        const payload = buildPremiumSubscriptionMessage({
          operatorName: operator.display_name || "Premium",
          username,
          mainLink,
          meliLink: meliLink || null,
          warningLine: templateCreated
            ? "آپ‌استریم تنظیم نشده بود؛ یک قالب از لینک شما ساخته شد."
            : upstreamUnset
              ? "آپ‌استریم تنظیم نشده است."
              : null,
        });
        await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
        if (ctx) {
          const requestId = crypto.randomUUID();
          const syntheticRequest = new Request("https://telegram.local/refresh", {
            headers: { "user-agent": "TelegramBot" },
          });
          ctx.waitUntil(refreshSnapshot(env, operator.id, panelToken, panelToken, syntheticRequest, requestId, null, logger));
          ctx.waitUntil(testUpstreamConnection(env, db, operator.id, panelToken, logger));
        }
        span.end({ action: "smart_paste" });
        return new Response("ok");
      }
    }

    if (text.startsWith("/start") || text.startsWith("/panel")) {
      const payload = await this.buildPanel(db, operator, env, logger);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
      span.end({ action: "panel" });
      return new Response("ok");
    }
    if (text.startsWith("/set_upstream")) {
      const value = text.replace("/set_upstream", "").trim();
      if (!value) {
        await D1.setPendingAction(db, operator.id, "set_upstream", null, logger);
        await this.sendMessage(env, message.chat.id, "📌 لطفاً لینک آپ‌استریم را بفرستید.", null, logger);
        span.end({ action: "set_upstream_prompt" });
        return new Response("ok");
      }
      await D1.createUpstream(db, env, operator.id, { url: value, enabled: true, weight: 1, priority: 1 }, logger);
      await D1.logAudit(
        db,
        {
          operator_id: operator.id,
          event_type: "settings_update:upstream_url",
          meta_json: JSON.stringify({ upstream: redactUrlForLog(value) }),
        },
        logger
      );
      await AuditService.notifyOperator(env, settings, "🧊 آپ‌استریم بروزرسانی شد.", logger);
      await this.sendMessage(env, message.chat.id, "✅ لینک آپ‌استریم ذخیره شد.", null, logger);
      span.end({ action: "set_upstream" });
      return new Response("ok");
    }
    if (text.startsWith("/set_domain")) {
      const domain = text.replace("/set_domain", "").trim();
      if (!domain) {
        await D1.setPendingAction(db, operator.id, "set_domain", null, logger);
        await this.sendMessage(env, message.chat.id, "📌 لطفاً دامنه را بفرستید.", null, logger);
        span.end({ action: "set_domain_prompt" });
        return new Response("ok");
      }
      if (!isValidDomain(domain)) {
        (logger || Logger).warn("domain_invalid", {
          error_code: "E_INPUT_INVALID",
          reason: ERROR_CODES.E_INPUT_INVALID.reason,
          hints: ERROR_CODES.E_INPUT_INVALID.hints,
          domain,
        });
        await this.sendMessage(env, message.chat.id, "❗️دامنه معتبر نیست.", null, logger);
        span.end({ action: "set_domain_invalid" });
        return new Response("ok");
      }
      await D1.createDomain(db, operator.id, domain, logger);
      const domains = await D1.listDomains(db, operator.id, logger);
      const latest = domains?.results?.[0];
      if (latest) await D1.setDomainActive(db, operator.id, latest.id, logger);
      await D1.logAudit(
        db,
        { operator_id: operator.id, event_type: "settings_update:domain", meta_json: JSON.stringify({ domain }) },
        logger
      );
      await AuditService.notifyOperator(env, settings, "🧊 دامنه بروزرسانی شد.", logger);
      const token = latest?.token ? `\nتوکن تایید: <code>${safeHtml(latest.token)}</code>` : "";
      await this.sendMessage(env, message.chat.id, `✅ دامنه ثبت شد.${token}`, null, logger);
      span.end({ action: "set_domain" });
      return new Response("ok");
    }
    if (text.startsWith("/set_channel")) {
      const channelId = text.replace("/set_channel", "").trim();
      if (!channelId) {
        await D1.setPendingAction(db, operator.id, "set_channel", null, logger);
        await this.sendMessage(env, message.chat.id, "📌 لطفاً شناسه کانال را بفرستید.", null, logger);
        span.end({ action: "set_channel_prompt" });
        return new Response("ok");
      }
      await D1.updateSettings(db, operator.id, { channel_id: channelId }, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "settings_update:channel" }, logger);
      await AuditService.notifyOperator(env, { channel_id: channelId }, "✅ اتصال کانال تایید شد.", logger);
      await this.sendMessage(env, message.chat.id, "✅ کانال اطلاع‌رسانی ذخیره شد.", null, logger);
      span.end({ action: "set_channel" });
      return new Response("ok");
    }
    if (text.startsWith("/extras")) {
      const payload = await this.buildExtrasPanel(db, operator, 0, logger);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
      span.end({ action: "extras" });
      return new Response("ok");
    }
    if (text.startsWith("/add_extra")) {
      const { title, content } = parseAddExtra(text);
      if (!content) {
        await this.sendMessage(env, message.chat.id, "❗️بعد از دستور متن کانفیگ را بفرستید. مثال: /add_extra عنوان | متن", null, logger);
        span.end({ action: "add_extra_invalid" });
        return new Response("ok");
      }
      await D1.createExtraConfig(db, operator.id, title, content, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:add" }, logger);
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ اضافی ثبت شد.", null, logger);
      span.end({ action: "add_extra" });
      return new Response("ok");
    }
    if (text.startsWith("/edit_extra")) {
      const parts = text.split(" ").slice(1);
      const [configId, ...contentParts] = parts;
      const content = contentParts.join(" ").trim();
      if (!configId || !content) {
        await this.sendMessage(env, message.chat.id, "❗️فرمت: /edit_extra شناسه متن_جدید", null, logger);
        span.end({ action: "edit_extra_invalid" });
        return new Response("ok");
      }
      await D1.updateExtraConfig(db, operator.id, configId, content, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:edit" }, logger);
      await this.sendMessage(env, message.chat.id, "✅ کانفیگ ویرایش شد.", null, logger);
      span.end({ action: "edit_extra" });
      return new Response("ok");
    }
    if (text.startsWith("/rules")) {
      const payload = await this.buildRulesPanel(db, operator, logger);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
      span.end({ action: "rules" });
      return new Response("ok");
    }
    if (text.startsWith("/set_rules")) {
      const patch = parseRulesArgs(text);
      if (!Object.keys(patch).length) {
        await this.sendMessage(
          env,
          message.chat.id,
          "❗️فرمت: /set_rules merge=append dedupe=1 sanitize=1 prefix=VIP_ keywords=ads,spam format=base64",
          null,
          logger
        );
        span.end({ action: "set_rules_invalid" });
        return new Response("ok");
      }
      await D1.updateRules(db, operator.id, patch, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "rules_update", meta_json: JSON.stringify(patch) }, logger);
      await this.sendMessage(env, message.chat.id, "✅ قوانین ذخیره شد.", null, logger);
      span.end({ action: "set_rules" });
      return new Response("ok");
    }
    if (text.startsWith("/link")) {
      const payload = await this.buildLinkPanel(db, operator, env, logger);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
      span.end({ action: "link" });
      return new Response("ok");
    }
    if (text.startsWith("/rotate")) {
      const primary = await D1.getPrimaryCustomerLink(db, operator.id, logger);
      const share = primary
        ? await D1.rotateCustomerLink(db, operator.id, primary.id, logger)
        : await D1.createCustomerLink(db, operator.id, null, null, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "link_rotate" }, logger);
      const branding = await OperatorService.getBrandingInfo(db, operator, env, logger);
      const prefixes = buildOperatorPrefixes({
        baseUrl: branding.baseUrl,
        nationalBaseUrl: branding.nationalBaseUrl,
        shareToken: share?.public_token || branding.shareToken,
        domain: branding.domain,
      });
      const prefixText = prefixes.mainPrefix ? `<code>${safeHtml(prefixes.mainPrefix)}</code>` : "نامشخص";
      await this.sendMessage(env, message.chat.id, `✅ توکن اشتراک بروزرسانی شد.\nپیشوند جدید:\n${prefixText}`, null, logger);
      span.end({ action: "rotate" });
      return new Response("ok");
    }
    if (text.startsWith("/logs")) {
      const payload = await this.buildLogsPanel(db, operator, logger);
      await this.sendMessage(env, message.chat.id, payload.text, payload.keyboard, logger);
      span.end({ action: "logs" });
      return new Response("ok");
    }

    if (text.startsWith("/admin_list_operators")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.", null, logger);
        span.end({ action: "admin_list_forbidden" });
        return new Response("ok");
      }
      const operators = await D1.listOperators(db, logger);
      const list = (operators?.results || [])
        .map((item) => `• ${safeHtml(item.display_name || item.telegram_user_id)} (${safeHtml(item.telegram_user_id)}) - ${safeHtml(item.status)} - ${safeHtml(item.role)}`)
        .join("\n");
      await this.sendMessage(env, message.chat.id, list || "لیست خالی است.", null, logger);
      span.end({ action: "admin_list_operators" });
      return new Response("ok");
    }
    if (text.startsWith("/admin_add_operator")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.", null, logger);
        span.end({ action: "admin_add_forbidden" });
        return new Response("ok");
      }
      const targetId = text.replace("/admin_add_operator", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه تلگرام را وارد کنید.", null, logger);
        span.end({ action: "admin_add_invalid" });
        return new Response("ok");
      }
      const existing = await D1.getOperatorByTelegramId(db, targetId, logger);
      if (!existing) {
        await D1.createOperator(db, targetId, "Operator", "operator", "active", logger);
      }
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_add_operator" }, logger);
      await this.sendMessage(env, message.chat.id, "✅ اپراتور اضافه شد.", null, logger);
      span.end({ action: "admin_add_operator" });
      return new Response("ok");
    }
    if (text.startsWith("/admin_remove_operator")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.", null, logger);
        span.end({ action: "admin_remove_forbidden" });
        return new Response("ok");
      }
      const targetId = text.replace("/admin_remove_operator", "").trim();
      if (!targetId) {
        await this.sendMessage(env, message.chat.id, "❗️شناسه تلگرام را وارد کنید.", null, logger);
        span.end({ action: "admin_remove_invalid" });
        return new Response("ok");
      }
      await D1.removeOperator(db, targetId, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_remove_operator" }, logger);
      await this.sendMessage(env, message.chat.id, "✅ اپراتور غیرفعال شد.", null, logger);
      span.end({ action: "admin_remove_operator" });
      return new Response("ok");
    }
    if (text.startsWith("/admin_broadcast")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.", null, logger);
        span.end({ action: "admin_broadcast_forbidden" });
        return new Response("ok");
      }
      const messageBody = text.replace("/admin_broadcast", "").trim();
      if (!messageBody) {
        await this.sendMessage(env, message.chat.id, "❗️متن پیام را بنویسید.", null, logger);
        span.end({ action: "admin_broadcast_invalid" });
        return new Response("ok");
      }
      const operators = await D1.listOperators(db, logger);
      for (const item of operators?.results || []) {
        const opSettings = await D1.getSettings(db, item.id, logger);
        await AuditService.notifyOperator(env, opSettings, `📣 پیام مدیر: ${safeHtml(messageBody)}`, logger);
      }
      await D1.logAudit(db, { operator_id: operator.id, event_type: "admin_broadcast" }, logger);
      await this.sendMessage(env, message.chat.id, "✅ پیام ارسال شد.", null, logger);
      span.end({ action: "admin_broadcast" });
      return new Response("ok");
    }
    if (text.startsWith("/admin_health_telegram")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        await this.sendMessage(env, message.chat.id, "⚠️ این بخش فقط برای مدیر است.", null, logger);
        span.end({ action: "admin_health_telegram_forbidden" });
        return new Response("ok");
      }
      const result = await this.getMeCached(env, logger, {
        operator_id: operator.id,
        telegram_user_id: operator.telegram_user_id,
      });
      if (result?.ok && result?.telegram?.ok) {
        await this.sendMessage(env, message.chat.id, "✅ Telegram getMe: ok", null, logger);
      } else {
        const desc = result?.telegram?.description ? ` - ${safeHtml(result.telegram.description)}` : "";
        await this.sendMessage(env, message.chat.id, `❗️Telegram getMe: error${desc}`, null, logger);
      }
      span.end({ action: "admin_health_telegram" });
      return new Response("ok");
    }
    if (text.startsWith("/admin_health")) {
      await this.sendMessage(env, message.chat.id, `🟢 سلامت سیستم: ${APP.name} v${APP.version}`, null, logger);
      span.end({ action: "admin_health" });
      return new Response("ok");
    }

    await this.sendMessage(env, message.chat.id, "❓ دستور ناشناخته. /panel را بزنید.", null, logger);
    span.end({ action: "unknown_command" });
    return new Response("ok");
  },
  async handleCallback(env, db, operator, callback, logger) {
    const scopedLogger = (logger || Logger).child({ operator_id: operator.id, telegram_user_id: operator.telegram_user_id });
    const span = scopedLogger.span("telegram_callback", { operator_id: operator.id, telegram_user_id: operator.telegram_user_id });
    logger = scopedLogger;
    const data = decodeCallbackData(callback.data || "", logger);
    const action = data.action || "";
    const chatId = callback.message?.chat?.id;
    if (!chatId) {
      span.end({ action: "missing_chat" });
      return new Response("ok");
    }

    if (action === "toggle_extra" && data.id) {
      await D1.setExtraEnabled(db, operator.id, data.id, data.enabled, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:toggle" }, logger);
      await this.sendMessage(env, chatId, "✅ وضعیت افزودنی تغییر کرد.", null, logger);
      span.end({ action: "toggle_extra" });
      return new Response("ok");
    }
    if (action === "delete_extra" && data.id) {
      await D1.deleteExtraConfig(db, operator.id, data.id, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "extras_update:delete" }, logger);
      await this.sendMessage(env, chatId, "🗑️ کانفیگ حذف شد.", null, logger);
      span.end({ action: "delete_extra" });
      return new Response("ok");
    }
    if (action === "set_rules") {
      await D1.updateRules(db, operator.id, data.patch || {}, logger);
      await D1.logAudit(db, { operator_id: operator.id, event_type: "rules_update" }, logger);
      await this.sendMessage(env, chatId, "✅ قوانین اشتراک ذخیره شد.", null, logger);
      span.end({ action: "set_rules" });
      return new Response("ok");
    }
    if (action === "panel_extras") {
      const page = Number(data.page || 0);
      const payload = await this.buildExtrasPanel(db, operator, page, logger);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard, logger);
      span.end({ action: "panel_extras" });
      return new Response("ok");
    }
    if (action === "panel_rules") {
      const payload = await this.buildRulesPanel(db, operator, logger);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard, logger);
      span.end({ action: "panel_rules" });
      return new Response("ok");
    }
    if (action === "panel_channel") {
      await D1.setPendingAction(db, operator.id, "set_channel", null, logger);
      await this.sendMessage(env, chatId, "📌 شناسه کانال را ارسال کنید.", null, logger);
      span.end({ action: "panel_channel" });
      return new Response("ok");
    }
    if (action === "panel_upstream") {
      await D1.setPendingAction(db, operator.id, "set_upstream", null, logger);
      await this.sendMessage(env, chatId, "📌 لینک آپ‌استریم را ارسال کنید.", null, logger);
      span.end({ action: "panel_upstream" });
      return new Response("ok");
    }
    if (action === "panel_domain") {
      await D1.setPendingAction(db, operator.id, "set_domain", null, logger);
      await this.sendMessage(env, chatId, "📌 دامنه را ارسال کنید.", null, logger);
      span.end({ action: "panel_domain" });
      return new Response("ok");
    }
    if (action === "show_link") {
      const payload = await this.buildLinkPanel(db, operator, env, logger);
      await this.sendMessage(env, chatId, payload.text, payload.keyboard, logger);
      span.end({ action: "show_link" });
      return new Response("ok");
    }

    await this.sendMessage(env, chatId, "✅ انجام شد.", null, logger);
    span.end({ action });
    return new Response("ok");
  },
  async buildPanel(db, operator, env, logger) {
    const settings = await D1.getSettings(db, operator.id, logger);
    const domains = await D1.listDomains(db, operator.id, logger);
    const activeDomain = (domains?.results || []).find((item) => item.active);
    const upstreams = await D1.listUpstreams(db, operator.id, logger);
    const snapshot = await D1.getLatestSnapshotInfo(db, operator.id, logger);
    const snapshotFresh = snapshot && isSnapshotFresh(snapshot) ? "تازه" : "نیازمند بروزرسانی";
    const shareToken = await OperatorService.getShareToken(db, operator.id, logger);
    const prefixes = buildOperatorPrefixes({
      baseUrl: env.BASE_URL || "",
      shareToken,
      domain: activeDomain?.verified ? activeDomain.domain : null,
    });
    const upstreamStatus = (upstreams?.results || []).length ? settings?.last_upstream_status || "unset" : "unset";
    const upstreamAt = (upstreams?.results || []).length ? settings?.last_upstream_at || "-" : "-";
    const text = `
${GLASS} <b>پنل اپراتور</b>

👤 اپراتور: <code>${safeHtml(operator.display_name || operator.telegram_user_id)}</code>
🌐 دامنه فعال: <code>${safeHtml(activeDomain?.domain || "ثبت نشده")}</code>
✅ تایید دامنه: <code>${activeDomain?.verified ? "تایید شد" : activeDomain ? "در انتظار" : "نامشخص"}</code>
⚡ وضعیت آپ‌استریم: <code>${safeHtml(upstreamStatus)}</code> (${safeHtml(upstreamAt)})
🧾 آخرین اسنپ‌شات: <code>${safeHtml(snapshot?.updated_at || "-")}</code> (${snapshotFresh})
🔗 پیشوند لینک مشتری: <code>${safeHtml(prefixes.mainPrefix || "-")}</code>

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
          { text: GLASS_BTN("مدیریت آپ‌استریم‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_upstream" })) },
          { text: GLASS_BTN("تایید دامنه"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_domain" })) },
        ],
        [
          { text: GLASS_BTN("مدیریت لینک‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "show_link" })) },
          { text: GLASS_BTN("مدیریت افزودنی‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_extras" })) },
        ],
        [
          { text: GLASS_BTN("قوانین"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_rules" })) },
          { text: GLASS_BTN("اعلان‌ها"), callback_data: utf8SafeEncode(JSON.stringify({ action: "panel_channel" })) },
        ],
      ],
    };
    return { text, keyboard };
  },
  async buildLinkPanel(db, operator, env, logger) {
    const settings = await D1.getSettings(db, operator.id, logger);
    const activeDomain = settings?.active_domain_id ? await D1.getDomainById(db, settings.active_domain_id, logger) : null;
    const shareToken = await OperatorService.getShareToken(db, operator.id, logger);
    const prefixes = buildOperatorPrefixes({
      baseUrl: env.BASE_URL || "",
      nationalBaseUrl: settings?.national_base_url || env.NATIONAL_BASE_URL || "",
      shareToken,
      domain: activeDomain?.verified ? activeDomain.domain : null,
    });
    const upstreams = await D1.listUpstreams(db, operator.id, logger);
    const upstreamStatus = (upstreams?.results || []).length ? settings?.last_upstream_status || "unset" : "unset";
    const upstreamAt = (upstreams?.results || []).length ? settings?.last_upstream_at || "-" : "-";
    const extrasCount = await D1.countExtraConfigs(db, operator.id, logger);
    const rules = await D1.getRules(db, operator.id, logger);
    const snapshot = await D1.getLatestSnapshotInfo(db, operator.id, logger);
    const snapshotFresh = snapshot && isSnapshotFresh(snapshot) ? "تازه" : "نیازمند بروزرسانی";
    const prefixText = prefixes.mainPrefix || "-";
    const sharePrefix = prefixes.mainPrefix || "";
    const text = `
${GLASS} <b>پیشوند لینک اشتراک برند شما</b>

<code>${safeHtml(prefixText)}</code>

برای ساخت لینک مشتری فقط لینک پنل مشتری را ارسال کنید.

دامنه فعال: ${safeHtml(activeDomain?.domain || "-")}
تایید دامنه: ${activeDomain?.verified ? "تایید شد" : activeDomain ? "در انتظار" : "-"}
وضعیت آپ‌استریم: ${safeHtml(upstreamStatus)} (${safeHtml(upstreamAt)})
وضعیت اسنپ‌شات: ${safeHtml(snapshot?.updated_at || "-")} (${snapshotFresh})
افزودنی‌ها: ${extrasCount?.count || 0}
Merge policy: ${safeHtml(rules?.merge_policy || "append")}
    `.trim();
    const keyboard = {
      inline_keyboard: [
        [{ text: GLASS_BTN("کپی پیشوند"), url: `https://t.me/share/url?url=${encodeURIComponent(sharePrefix)}` }],
      ],
    };
    return { text, keyboard };
  },
  async buildExtrasPanel(db, operator, page = 0, logger) {
    const limit = 5;
    const offset = page * limit;
    const extras = await D1.listExtraConfigs(db, operator.id, limit, offset, logger);
    const total = await D1.countExtraConfigs(db, operator.id, logger);
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
  async buildRulesPanel(db, operator, logger) {
    const rules = await D1.getRules(db, operator.id, logger);
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
  async buildLogsPanel(db, operator, logger) {
    const logs = await D1.listAuditLogs(db, operator.id, 5, logger);
    const items = (logs?.results || [])
      .map((log) => `• ${safeHtml(log.event_type)} ${safeHtml(log.created_at)}`)
      .join("\n");
    const text = `
${GLASS} <b>لاگ‌های اخیر</b>

${items || "فعلاً لاگی ثبت نشده."}
    `.trim();
    return { text, keyboard: null };
  },
  buildOnboardingMessage(env) {
    const baseUrl = String(env.BASE_URL || "").replace(/\/$/, "");
    const text = "You are not an operator yet. Send /invite CODE or contact admin.";
    const keyboard = baseUrl
      ? {
          inline_keyboard: [[{ text: GLASS_BTN("Open web login"), url: baseUrl }]],
        }
      : null;
    return { text, keyboard };
  },
  async handleInvite(env, db, telegramUser, text, logger, existingOperator = null) {
    const inviteCode = text.replace("/invite", "").trim();
    const log = logger || Logger;
    if (!inviteCode) {
      await this.sendMessage(env, telegramUser.id, "❗️فرمت: /invite CODE", null, log, {
        telegram_user_id: telegramUser.id,
      });
      return new Response("ok");
    }
    const invite = await D1.getInviteCode(db, inviteCode, log);
    if (!invite || invite.used_at) {
      await this.sendMessage(env, telegramUser.id, "❗️کد دعوت معتبر نیست یا قبلاً استفاده شده است.", null, log, {
        telegram_user_id: telegramUser.id,
      });
      return new Response("ok");
    }
    const displayName = telegramUser.first_name || telegramUser.username || "Operator";
    let operator = existingOperator || (await D1.getOperatorByTelegramId(db, telegramUser.id, log));
    if (!operator) {
      operator = await D1.createOperator(db, telegramUser.id, displayName, "operator", "active", log);
    } else if (operator.status !== "active") {
      await D1.updateOperatorStatus(db, operator.id, "active", log);
      operator.status = "active";
    }
    await D1.useInviteCode(db, inviteCode, operator.id, log);
    await D1.logAudit(db, { operator_id: operator.id, event_type: "invite_redeem" }, log);
    const payload = await this.buildPanel(db, operator, env, log);
    await this.sendMessage(env, telegramUser.id, payload.text, payload.keyboard, log, {
      operator_id: operator.id,
      telegram_user_id: operator.telegram_user_id,
    });
    return new Response("ok");
  },
  async getMe(env, logger, ctx = {}) {
    return telegramFetch("getMe", null, { env, logger, label: "telegram_get_me", ...ctx });
  },
  async getMeCached(env, logger, ctx = {}) {
    const now = Date.now();
    if (TELEGRAM_CACHE.getMe.result && now - TELEGRAM_CACHE.getMe.at < TELEGRAM_CACHE_TTL_MS) {
      return TELEGRAM_CACHE.getMe.result;
    }
    const result = await this.getMe(env, logger, ctx);
    TELEGRAM_CACHE.getMe = { at: now, result };
    return result;
  },
  async sendMessage(env, chatId, text, keyboard, logger, extraCtx = {}) {
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
    };
    if (keyboard) body.reply_markup = keyboard;
    const log = logger || Logger;
    try {
      const result = await telegramFetch("sendMessage", body, {
        env,
        logger: log,
        label: "telegram_send_message",
        ...extraCtx,
      });
      if (!result.ok) {
        const reason = result.skipped ? "Invalid TELEGRAM_TOKEN format" : "Telegram API responded with non-2xx";
        const hints = result.skipped ? telegramHintsForStatus(0) : telegramHintsForStatus(result.status);
        log.error("telegram_send_failed", new Error(reason), {
          error_code: "E_TELEGRAM_API",
          reason,
          hints,
          status: result.status,
          telegram: result.telegram,
          request_id: extraCtx.request_id,
          operator_id: extraCtx.operator_id,
          telegram_user_id: extraCtx.telegram_user_id,
        });
      }
      return result.ok;
    } catch (err) {
      log.error("telegram_send_failed", err, {
        error_code: "E_TELEGRAM_API",
        reason: "Telegram API fetch failed",
        hints: telegramHintsForStatus(0),
        request_id: extraCtx.request_id,
        operator_id: extraCtx.operator_id,
        telegram_user_id: extraCtx.telegram_user_id,
      });
      return false;
    }
  },
};

// =============================
// HTTP Router
// =============================
const Router = {
  async handle(request, env, ctx, logger, requestId) {
    const url = new URL(request.url);
    (logger || Logger).info("router_dispatch", { route: scrubPathForLog(url.pathname) });
    if (request.method === "POST" && url.pathname === "/webhook") {
      return Telegram.handleWebhook(request, env, ctx, logger);
    }
    if (request.method === "POST" && url.pathname === "/auth/telegram") {
      return this.handleTelegramLogin(request, env, logger);
    }
    if (request.method === "GET" && url.pathname.startsWith("/sub/")) {
      return this.handleSubscription(request, env, url, ctx, logger, requestId);
    }
    if (request.method === "GET" && url.pathname === "/redirect") {
      return this.handleRedirect(url, logger);
    }
    if (request.method === "GET" && url.pathname.startsWith("/verify-domain/")) {
      return this.handleVerifyDomain(request, env, url, logger);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return this.handleHealth(env, logger);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/health/full") {
      return this.handleHealthFull(env, logger);
    }
    if (request.method === "POST" && url.pathname === "/admin/purge") {
      return this.handlePurge(request, env, logger);
    }
    if (url.pathname.startsWith("/api/v1/")) {
      return this.handleApi(request, env, logger);
    }
    if (request.method === "GET" && url.pathname === "/") {
      return this.handleLanding(request, env, logger);
    }
    return new Response("not found", { status: 404 });
  },
  async handlePurge(request, env, logger) {
    const span = (logger || Logger).span("admin_purge");
    const ctx = await AuthService.getAuthContext(request, env, env.DB, logger);
    if (!ctx || !isAdmin(ctx.operator.telegram_user_id, env)) {
      span.end({ status: 403 });
      return jsonResponse({ ok: false, error: "forbidden" }, 403);
    }
    const url = new URL(request.url);
    const days = Number(url.searchParams.get("days") || APP.purgeRetentionDays);
    const retentionMs = Math.max(1, days) * 24 * 60 * 60 * 1000;
    const scopedLogger = logger.child({ operator_id: ctx.operator.id, telegram_user_id: ctx.operator.telegram_user_id });
    await D1.purgeOldRecords(env.DB, retentionMs, scopedLogger);
    span.end({ status: 200, retention_days: days });
    return jsonResponse({ ok: true, retention_days: days });
  },
  async handleTelegramLogin(request, env, logger) {
    const span = (logger || Logger).span("telegram_login");
    if (!env.TELEGRAM_TOKEN || !env.SESSION_SECRET) {
      span.end({ status: 500 });
      return jsonResponse({ ok: false, error: "missing_env" }, 500);
    }
    const body = await parseJsonBody(request, logger);
    if (!body) {
      (logger || Logger).warn("telegram_login_invalid_body", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
      });
      span.end({ status: 400 });
      return jsonResponse({ ok: false, error: "invalid_body" }, 400);
    }
    const ok = await validateTelegramLogin(body, env.TELEGRAM_TOKEN);
    if (!ok) {
      (logger || Logger).warn("telegram_login_invalid_auth", {
        error_code: "E_AUTH_UNAUTHORIZED",
        reason: ERROR_CODES.E_AUTH_UNAUTHORIZED.reason,
        hints: ERROR_CODES.E_AUTH_UNAUTHORIZED.hints,
      });
      span.end({ status: 403 });
      return jsonResponse({ ok: false, error: "invalid_auth" }, 403);
    }
    const telegramId = body.id;
    const displayName = body.first_name || body.username || "Operator";
    let operator = await D1.getOperatorByTelegramId(env.DB, telegramId, logger);
    if (!operator) {
      let status = "pending";
      if (isAdmin(telegramId, env)) status = "active";
      if (body.invite_code) {
        const invite = await D1.getInviteCode(env.DB, body.invite_code, logger);
        if (!invite || invite.used_at) {
          (logger || Logger).warn("telegram_login_invalid_invite", {
            error_code: "E_AUTH_FORBIDDEN",
            reason: ERROR_CODES.E_AUTH_FORBIDDEN.reason,
            hints: ERROR_CODES.E_AUTH_FORBIDDEN.hints,
          });
          span.end({ status: 403 });
          return jsonResponse({ ok: false, error: "invalid_invite" }, 403);
        }
        operator = await D1.createOperator(env.DB, telegramId, displayName, "operator", status, logger);
        await D1.useInviteCode(env.DB, body.invite_code, operator.id, logger);
      } else {
        operator = await D1.createOperator(env.DB, telegramId, displayName, "operator", status, logger);
      }
    }
    const payload = {
      sub: operator.id,
      role: operator.role,
      telegram_user_id: operator.telegram_user_id,
      exp: Math.floor(Date.now() / 1000) + APP.sessionTtlSec,
    };
    const token = await signSession(payload, env.SESSION_SECRET);
    span.end({ status: 200, operator_id: operator.id });
    return jsonResponse({ ok: true, token, status: operator.status });
  },
  async handleApi(request, env, logger) {
    const span = (logger || Logger).span("api_request");
    const ctx = await AuthService.getAuthContext(request, env, env.DB, logger);
    if (!ctx) {
      span.end({ status: 401 });
      return jsonResponse({ ok: false, error: "unauthorized" }, 401);
    }
    const { operator } = ctx;
    const apiLogger = logger.child({ operator_id: operator.id, telegram_user_id: operator.telegram_user_id, token_type: ctx.tokenType });
    const url = new URL(request.url);
    const path = url.pathname.replace("/api/v1", "");
    if (request.method === "GET" && path === "/operators/me/upstreams") {
      const data = await D1.listUpstreamsAll(env.DB, operator.id, apiLogger);
      const masked = await Promise.all(
        (data?.results || []).map(async (item) => {
          const plainUrl = await decryptUpstreamUrl(env, item.url);
          return { ...item, url: redactUrlForDisplay(plainUrl) };
        })
      );
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, data: masked });
    }
    if (request.method === "POST" && path === "/operators/me/upstreams") {
      const body = await parseJsonBody(request, apiLogger);
      if (!body?.url) {
        apiLogger.warn("api_invalid_body", {
          error_code: "E_INPUT_INVALID",
          reason: ERROR_CODES.E_INPUT_INVALID.reason,
          hints: ERROR_CODES.E_INPUT_INVALID.hints,
          path,
        });
        span.end({ status: 400, path });
        return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      }
      await D1.createUpstream(env.DB, env, operator.id, body, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_upstream_create" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true });
    }
    if (request.method === "POST" && path === "/operators/me/extras") {
      const body = await parseJsonBody(request, apiLogger);
      if (!body?.content) {
        apiLogger.warn("api_invalid_body", {
          error_code: "E_INPUT_INVALID",
          reason: ERROR_CODES.E_INPUT_INVALID.reason,
          hints: ERROR_CODES.E_INPUT_INVALID.hints,
          path,
        });
        span.end({ status: 400, path });
        return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      }
      await D1.createExtraConfig(env.DB, operator.id, body.title, body.content, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_extra_create" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true });
    }
    if (request.method === "POST" && path === "/operators/me/customer-links") {
      const body = await parseJsonBody(request, apiLogger);
      const link = await D1.createCustomerLink(env.DB, operator.id, body?.label, body?.overrides, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_customer_link_create" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, data: link });
    }
    if (request.method === "GET" && path === "/operators/me/customer-links") {
      const links = await D1.listCustomerLinks(env.DB, operator.id, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, data: links?.results || [] });
    }
    if (request.method === "GET" && path === "/operators/me/status") {
      const settings = await D1.getSettings(env.DB, operator.id, apiLogger);
      const upstreams = await D1.listUpstreams(env.DB, operator.id, apiLogger);
      const domains = await D1.listDomains(env.DB, operator.id, apiLogger);
      const activeDomain = (domains?.results || []).find((item) => item.active);
      const snapshot = await D1.getLatestSnapshotInfo(env.DB, operator.id, apiLogger);
      const upstreamStatus = (upstreams?.results || []).length ? settings?.last_upstream_status || null : "unset";
      const upstreamAt = (upstreams?.results || []).length ? settings?.last_upstream_at || null : null;
      span.end({ status: 200, path });
      return jsonResponse({
        ok: true,
        data: {
          last_upstream_status: upstreamStatus,
          last_upstream_at: upstreamAt,
          domain_status: activeDomain?.verified ? "verified" : activeDomain ? "pending" : "unset",
          domain_name: activeDomain?.domain || null,
          snapshot_updated_at: snapshot?.updated_at || null,
          snapshot_ttl_sec: snapshot?.ttl_sec || null,
        },
      });
    }
    if (request.method === "POST" && path.startsWith("/operators/me/customer-links/") && path.endsWith("/rotate")) {
      const id = path.split("/")[4];
      if (!id) {
        apiLogger.warn("api_missing_id", {
          error_code: "E_INPUT_INVALID",
          reason: ERROR_CODES.E_INPUT_INVALID.reason,
          hints: ERROR_CODES.E_INPUT_INVALID.hints,
          path,
        });
        span.end({ status: 400, path });
        return jsonResponse({ ok: false, error: "missing_id" }, 400);
      }
      const link = await D1.rotateCustomerLink(env.DB, operator.id, id, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_customer_link_rotate" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, data: link });
    }
    if (request.method === "PATCH" && path === "/operators/me/rules") {
      const body = await parseJsonBody(request, apiLogger);
      if (!body) {
        apiLogger.warn("api_invalid_body", {
          error_code: "E_INPUT_INVALID",
          reason: ERROR_CODES.E_INPUT_INVALID.reason,
          hints: ERROR_CODES.E_INPUT_INVALID.hints,
          path,
        });
        span.end({ status: 400, path });
        return jsonResponse({ ok: false, error: "invalid_body" }, 400);
      }
      await D1.updateRules(env.DB, operator.id, body, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_rules_update" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true });
    }
    if (request.method === "GET" && path === "/operators/me/domains") {
      const domains = await D1.listDomains(env.DB, operator.id, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, data: domains?.results || [] });
    }
    if (request.method === "POST" && path === "/operators/me/api-keys") {
      const body = await parseJsonBody(request, apiLogger);
      const rawKey = body?.key || crypto.randomUUID();
      const keyHash = await hashApiKey(rawKey);
      await D1.createApiKey(env.DB, operator.id, keyHash, body?.scopes ? JSON.stringify(body.scopes) : null, apiLogger);
      await D1.logAudit(env.DB, { operator_id: operator.id, event_type: "api_key_create" }, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, key: rawKey });
    }
    if (request.method === "POST" && path === "/admin/invite-codes") {
      if (!isAdmin(operator.telegram_user_id, env)) {
        apiLogger.warn("api_forbidden", {
          error_code: "E_AUTH_FORBIDDEN",
          reason: ERROR_CODES.E_AUTH_FORBIDDEN.reason,
          hints: ERROR_CODES.E_AUTH_FORBIDDEN.hints,
          path,
        });
        span.end({ status: 403, path });
        return jsonResponse({ ok: false, error: "forbidden" }, 403);
      }
      const code = crypto.randomUUID().split("-")[0];
      await D1.createInviteCode(env.DB, code, operator.id, apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true, code });
    }
    if (request.method === "POST" && path.startsWith("/admin/operators/") && path.endsWith("/approve")) {
      if (!isAdmin(operator.telegram_user_id, env)) {
        apiLogger.warn("api_forbidden", {
          error_code: "E_AUTH_FORBIDDEN",
          reason: ERROR_CODES.E_AUTH_FORBIDDEN.reason,
          hints: ERROR_CODES.E_AUTH_FORBIDDEN.hints,
          path,
        });
        span.end({ status: 403, path });
        return jsonResponse({ ok: false, error: "forbidden" }, 403);
      }
      const id = path.split("/")[3];
      await D1.updateOperatorStatus(env.DB, id, "active", apiLogger);
      span.end({ status: 200, path });
      return jsonResponse({ ok: true });
    }
    span.end({ status: 404, path });
    return jsonResponse({ ok: false, error: "not_found" }, 404);
  },
  async handleSubscription(request, env, url, ctx, logger, requestId) {
    const db = env.DB;
    const segments = url.pathname.split("/").filter(Boolean);
    const rawToken = segments[2] || segments[1] || "";
    const scopedLogger = (logger || Logger).child({ token_prefix: rawToken.slice(0, 6) });
    let subscriptionToken = null;
    let panelToken = null;
    let customerLink = null;
    let operatorId = null;

    if (segments.length >= 3) {
      const shareToken = segments[1];
      panelToken = segments[2];
      subscriptionToken = panelToken;
      customerLink = await D1.getCustomerLinkByToken(db, shareToken, scopedLogger);
      if (customerLink) operatorId = customerLink.operator_id;
    } else if (segments.length === 2) {
      const domain = await D1.getDomainByHostname(db, url.hostname, scopedLogger);
      if (domain?.operator_id) {
        operatorId = domain.operator_id;
        panelToken = segments[1];
        subscriptionToken = panelToken;
      } else {
        customerLink = await D1.getCustomerLinkByToken(db, segments[1], scopedLogger);
        if (customerLink) {
          operatorId = customerLink.operator_id;
          subscriptionToken = segments[1];
        }
      }
    }

    if (!operatorId || !subscriptionToken) {
      scopedLogger.warn("subscription_not_found", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
      });
      return new Response("not found", { status: 404 });
    }

    const span = (logger || Logger).span("subscription_request", { token_prefix: subscriptionToken.slice(0, 6) });
    const cacheKey = `sub:${subscriptionToken}`;
    let snapshot = null;
    let cachedBody = null;
    let cachedHeaders = null;
    let cacheSource = null;

    const cached = getCachedSub(cacheKey);
    if (cached?.snapshot) {
      snapshot = cached.snapshot;
      cachedBody = cached.body;
      cachedHeaders = cached.headers;
      cacheSource = "memory";
    }

    if (!snapshot || !isSnapshotFresh(snapshot)) {
      const cacheUrl = new URL(`https://cache.internal/snap/${subscriptionToken}`);
      const cache = caches.default;
      const cachedResponse = await cache.match(cacheUrl);
      if (cachedResponse) {
        const body = await cachedResponse.text();
        const headers = Object.fromEntries(cachedResponse.headers.entries());
        snapshot = {
          token: subscriptionToken,
          operator_id: headers["x-operator-id"],
          body_value: body,
          body_format: headers["x-snapshot-format"] || "base64",
          headers_json: JSON.stringify(headers),
          updated_at: headers["x-snapshot-updated"] || nowIso(),
          ttl_sec: Number(headers["x-snapshot-ttl"] || APP.snapshotTtlSec),
          quotas_json: headers["x-snapshot-quotas"] || null,
          notify_fetches: headers["x-snapshot-notify"] ? Number(headers["x-snapshot-notify"]) : APP.notifyFetchDefault,
          last_fetch_notify_at: headers["x-snapshot-last-notify"] || null,
          channel_id: headers["x-snapshot-channel"] || null,
        };
        cachedBody = body;
        cachedHeaders = headers;
        cacheSource = "edge";
        setCachedSub(cacheKey, body, headers, { snapshot });
      }
    }

    if (!snapshot) {
      snapshot = await SnapshotService.getSnapshot(env, subscriptionToken, scopedLogger);
      if (snapshot) {
        cachedBody = snapshot.body_value;
        cachedHeaders = buildSnapshotHeaders(snapshot, requestId, scopedLogger);
        cacheSource = env.SNAP_KV ? "kv" : "db";
        setCachedSub(cacheKey, snapshot.body_value, cachedHeaders, { snapshot });
      }
    }

    if (snapshot?.operator_id && snapshot.operator_id !== operatorId) {
      scopedLogger.warn("subscription_operator_mismatch", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
        operator_id: operatorId,
        snapshot_operator_id: snapshot.operator_id,
      });
    }
    const operatorLogger = scopedLogger.child({ operator_id: operatorId });
    const settings = snapshot?.quotas_json ? null : await D1.getSettings(db, operatorId, operatorLogger);
    const quotas = safeJsonParse(snapshot?.quotas_json || settings?.quotas_json, {}, operatorLogger, { error_code: "E_JSON_PARSE", context: "quotas" });
    const perIp = quotas?.per_ip ?? APP.rateLimitMax;
    const perToken = quotas?.per_token ?? APP.rateLimitMax;
    const perOperator = quotas?.per_operator ?? APP.rateLimitMax * 10;
    const ip = request.headers.get("cf-connecting-ip") || "unknown";

    if (!rateLimit(`sub-ip:${ip}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-ip:${ip}`, APP.rateLimitWindowMs, perIp, operatorLogger);
      if (!ok) {
        operatorLogger.warn("subscription_rate_limited_ip", {
          error_code: "E_RATE_LIMIT",
          reason: ERROR_CODES.E_RATE_LIMIT.reason,
          hints: ERROR_CODES.E_RATE_LIMIT.hints,
          ip,
        });
        return new Response("rate limit", { status: 429 });
      }
    }
    if (!rateLimit(`sub-token:${subscriptionToken}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-token:${subscriptionToken}`, APP.rateLimitWindowMs, perToken, operatorLogger);
      if (!ok) {
        operatorLogger.warn("subscription_rate_limited_token", {
          error_code: "E_RATE_LIMIT",
          reason: ERROR_CODES.E_RATE_LIMIT.reason,
          hints: ERROR_CODES.E_RATE_LIMIT.hints,
          token_prefix: subscriptionToken.slice(0, 6),
        });
        return new Response("rate limit", { status: 429 });
      }
    }
    if (!rateLimit(`sub-op:${operatorId}`)) {
      const ok = await D1.bumpRateLimit(db, `sub-op:${operatorId}`, APP.rateLimitWindowMs, perOperator, operatorLogger);
      if (!ok) {
        operatorLogger.warn("subscription_rate_limited_operator", {
          error_code: "E_RATE_LIMIT",
          reason: ERROR_CODES.E_RATE_LIMIT.reason,
          hints: ERROR_CODES.E_RATE_LIMIT.hints,
          operator_id: operatorId,
        });
        return new Response("rate limit", { status: 429 });
      }
    }

    if (snapshot && cachedBody && isSnapshotFresh(snapshot)) {
      const notifyFetches = snapshot?.notify_fetches ?? settings?.notify_fetches ?? APP.notifyFetchDefault;
      if (notifyFetches !== 0) {
        const lastAt = snapshot?.last_fetch_notify_at || settings?.last_fetch_notify_at;
        const last = lastAt ? Date.parse(lastAt) : 0;
        if (Date.now() - last > APP.notifyFetchIntervalMs) {
          await AuditService.notifyOperator(
            env,
            settings || { operator_id: operatorId, channel_id: snapshot?.channel_id },
            `🧊 اشتراک دریافت شد: <b>${safeHtml(subscriptionToken)}</b>`,
            operatorLogger
          );
          await D1.updateSettings(db, operatorId, { last_fetch_notify_at: nowIso() }, operatorLogger);
        }
      }
      if (Math.random() < APP.auditSampleRate) {
        await D1.logAudit(
          db,
          {
            operator_id: operatorId,
            event_type: "subscription_fetch",
            ip,
            country: request.headers.get("cf-ipcountry"),
            user_agent: request.headers.get("user-agent"),
            request_path: new URL(request.url).pathname,
            response_status: 200,
            meta_json: JSON.stringify({ cache: cacheSource || "snapshot", request_id: requestId }),
          },
          operatorLogger
        );
      }
      span.end({ status: 200, cache: cacheSource || "snapshot" });
      const upstreamStatus = settings?.last_upstream_status || (snapshot ? "ok" : "unset");
      return new Response(cachedBody, {
        headers: withStatusHeaders({ ...cachedHeaders, "x-request-id": requestId }, "snapshot_hit", upstreamStatus),
      });
    }

    if (ctx) ctx.waitUntil(refreshSnapshot(env, operatorId, subscriptionToken, panelToken, request, requestId, customerLink, operatorLogger));

    const lastGoodMem = getLastGoodMem(cacheKey);
    if (lastGoodMem) {
      await D1.logAudit(
        db,
        {
          operator_id: operatorId,
          event_type: "subscription_fallback",
          ip,
          country: request.headers.get("cf-ipcountry"),
          user_agent: request.headers.get("user-agent"),
          request_path: new URL(request.url).pathname,
          response_status: 200,
          meta_json: JSON.stringify({ cache: "memory_lkg", request_id: requestId }),
        },
        scopedLogger
      );
      span.end({ status: 200, cache: "memory_lkg" });
      const upstreamStatus = settings?.last_upstream_status || "ok";
      return new Response(lastGoodMem.body, {
        headers: withStatusHeaders({ ...lastGoodMem.headers, "x-request-id": requestId }, "lkg_hit", upstreamStatus),
      });
    }

    const lastGood = await SnapshotService.getLastKnownGood(env, operatorId, subscriptionToken, operatorLogger);
    if (lastGood?.body_value) {
      const headersParsed = lastGood.headers_json
        ? safeJsonParse(lastGood.headers_json, DEFAULT_HEADERS, operatorLogger, { error_code: "E_JSON_PARSE", context: "last_known_good_headers" })
        : DEFAULT_HEADERS;
      const body = lastGood.body_value;
      setLastGoodMem(cacheKey, body, headersParsed, { body_format: lastGood.body_format });
      await D1.logAudit(
        db,
        {
          operator_id: operatorId,
          event_type: "subscription_fallback",
          ip,
          country: request.headers.get("cf-ipcountry"),
          user_agent: request.headers.get("user-agent"),
          request_path: new URL(request.url).pathname,
          response_status: 200,
          meta_json: JSON.stringify({ cache: "lkg", request_id: requestId }),
        },
        operatorLogger
      );
      span.end({ status: 200, cache: "lkg" });
      const upstreamStatus = settings?.last_upstream_status || "ok";
      return new Response(body, {
        headers: withStatusHeaders({ ...headersParsed, "x-request-id": requestId }, "lkg_hit", upstreamStatus),
      });
    }

    if (!snapshot) {
      const [rules, extras, upstreams] = await Promise.all([
        D1.getRules(db, operatorId, operatorLogger),
        D1.listEnabledExtras(db, operatorId, operatorLogger),
        D1.listUpstreams(db, operatorId, operatorLogger),
      ]);
      let failureReason = "upstream_invalid";
      let failureUpstreamStatus = settings?.last_upstream_status || "error";
      try {
        const assembled = await assembleWithTimeout(
          SubscriptionAssembler.assemble(
            env,
            db,
            operatorId,
            panelToken,
            request,
            requestId,
            customerLink,
            { settings, rules, extras, upstreams },
            operatorLogger
          ),
          APP.upstreamTimeoutMs
        );
        if (assembled.valid) {
          const { responseHeadersBase } = await persistSnapshot(
            env,
            db,
            { operatorId, subscriptionToken, assembled, settings, rules, request, requestId },
            operatorLogger
          );
          span.end({ status: 200, cache: "assembled_sync" });
          return new Response(assembled.body, {
            headers: withStatusHeaders(
              { ...responseHeadersBase, "x-request-id": requestId },
              "assembled_sync",
              assembled.upstreamStatus || "ok"
            ),
          });
        }
        failureReason = assembled.reason || "upstream_invalid";
        failureUpstreamStatus = assembled.upstreamStatus || failureUpstreamStatus;
        await D1.logAudit(
          db,
          {
            operator_id: operatorId,
            event_type: "subscription_error",
            ip,
            country: request.headers.get("cf-ipcountry"),
            user_agent: request.headers.get("user-agent"),
            request_path: new URL(request.url).pathname,
            response_status: 502,
            meta_json: JSON.stringify({ reason: failureReason, request_id: requestId }),
          },
          operatorLogger
        );
      } catch (err) {
        const reason = err?.name === "TimeoutError" ? "timeout" : "upstream_invalid";
        failureReason = reason;
        failureUpstreamStatus = reason === "timeout" ? "error" : failureUpstreamStatus;
        await D1.logAudit(
          db,
          {
            operator_id: operatorId,
            event_type: "subscription_error",
            ip,
            country: request.headers.get("cf-ipcountry"),
            user_agent: request.headers.get("user-agent"),
            request_path: new URL(request.url).pathname,
            response_status: 502,
            meta_json: JSON.stringify({ reason, request_id: requestId }),
          },
          operatorLogger
        );
      }
      span.end({ status: 200, cache: "assembled_sync_failed" });
      return new Response(utf8SafeEncode("# upstream_invalid"), {
        headers: withStatusHeaders({ ...DEFAULT_HEADERS, "x-request-id": requestId }, "upstream_invalid", failureUpstreamStatus),
        status: 200,
      });
    }

    if (snapshot) {
      await D1.logAudit(
        db,
        {
          operator_id: operatorId,
          event_type: "subscription_fallback",
          ip,
          country: request.headers.get("cf-ipcountry"),
          user_agent: request.headers.get("user-agent"),
          request_path: new URL(request.url).pathname,
          response_status: 200,
          meta_json: JSON.stringify({ cache: "stale_snapshot", request_id: requestId }),
        },
        operatorLogger
      );
      span.end({ status: 200, cache: "stale_snapshot" });
      const upstreamStatus = settings?.last_upstream_status || "ok";
      const headers = buildSnapshotHeaders(snapshot, requestId, operatorLogger);
      return new Response(snapshot.body_value || "", {
        headers: withStatusHeaders(headers, "snapshot_hit", upstreamStatus),
      });
    }

    await D1.logAudit(
      db,
      {
        operator_id: operatorId,
        event_type: "subscription_error",
        ip,
        country: request.headers.get("cf-ipcountry"),
        user_agent: request.headers.get("user-agent"),
        request_path: new URL(request.url).pathname,
        response_status: 502,
        meta_json: JSON.stringify({ reason: "no_snapshot", request_id: requestId }),
      },
      operatorLogger
    );
    span.end({ status: 200, cache: "none" });
    return new Response(utf8SafeEncode("# upstream_invalid"), {
      headers: withStatusHeaders({ ...DEFAULT_HEADERS, "x-request-id": requestId }, "upstream_invalid", settings?.last_upstream_status || "error"),
      status: 200,
    });
  },
  handleRedirect(url, logger) {
    const span = (logger || Logger).span("redirect_request");
    const target = url.searchParams.get("target") || "";
    if (!target) {
      span.end({ status: 400 });
      return new Response("bad request", { status: 400 });
    }
    if (target.length > APP.maxRedirectTargetBytes || hasCRLF(target)) {
      (logger || Logger).warn("redirect_blocked", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
        blocked_reason: "length_or_crlf",
      });
      span.end({ status: 400 });
      return new Response("blocked", { status: 400 });
    }
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      (logger || Logger).warn("redirect_invalid_url", {
        error_code: "E_INPUT_INVALID",
        reason: ERROR_CODES.E_INPUT_INVALID.reason,
        hints: ERROR_CODES.E_INPUT_INVALID.hints,
      });
      span.end({ status: 400 });
      return new Response("invalid", { status: 400 });
    }
    if (!SAFE_REDIRECT_SCHEMES.includes(parsed.protocol.replace(":", ""))) {
      (logger || Logger).warn("redirect_blocked", {
        error_code: "E_SSRF_BLOCKED",
        reason: ERROR_CODES.E_SSRF_BLOCKED.reason,
        hints: ERROR_CODES.E_SSRF_BLOCKED.hints,
        blocked_reason: "scheme",
      });
      span.end({ status: 403 });
      return new Response("blocked", { status: 403 });
    }
    if (parsed.protocol === "https:" && isBlockedHost(parsed.hostname)) {
      (logger || Logger).warn("redirect_blocked", {
        error_code: "E_SSRF_BLOCKED",
        reason: ERROR_CODES.E_SSRF_BLOCKED.reason,
        hints: ERROR_CODES.E_SSRF_BLOCKED.hints,
        blocked_reason: "blocked_host",
        host: parsed.hostname,
      });
      span.end({ status: 403 });
      return new Response("blocked", { status: 403 });
    }
    span.end({ status: 302 });
    return Response.redirect(parsed.toString(), 302);
  },
  async handleVerifyDomain(request, env, url, logger) {
    const span = (logger || Logger).span("verify_domain");
    const domainId = url.pathname.split("/").pop();
    const token = url.searchParams.get("token");
    if (!domainId || !token) {
      span.end({ status: 400 });
      return jsonResponse({ ok: false, error: "missing" }, 400);
    }
    const domain = await D1.getDomainById(env.DB, domainId, logger);
    if (!domain || domain.token !== token) {
      span.end({ status: 403 });
      return jsonResponse({ ok: false, error: "unauthorized" }, 403);
    }
    const doh = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain.domain)}&type=TXT`;
    const res = await fetchWithLogs(doh, { headers: { accept: "application/dns-json" } }, { label: "dns_query" }, logger);
    const data = await res.json();
    const answers = (data.Answer || []).map((ans) => ans.data.replace(/"/g, ""));
    const match = answers.some((value) => value.includes(token));
    if (match) {
      await D1.updateDomainVerified(env.DB, domainId, true, logger);
    }
    span.end({ status: 200, verified: match });
    return jsonResponse({ ok: match, domain: domain.domain });
  },
  async handleHealth(env, logger) {
    const span = (logger || Logger).span("health");
    let dbOk = true;
    let operators = [];
    const telegramResult = await Telegram.getMeCached(env, logger);
    const telegramOk = telegramResult?.ok && telegramResult?.telegram?.ok;
    try {
      await dbFirst(env.DB, "health.ping", () => env.DB.prepare("SELECT 1").first(), logger);
      const rows = await dbAll(
        env.DB,
        "health.operator_settings",
        () =>
          env.DB
            .prepare("SELECT operator_id, last_upstream_status, last_upstream_at FROM operator_settings ORDER BY last_upstream_at DESC LIMIT 5")
            .all(),
        logger
      );
      operators = rows?.results || [];
    } catch {
      dbOk = false;
    }
    const payload = {
      status: "ok",
      version: APP.version,
      db: dbOk ? "ok" : "error",
      telegram: telegramOk ? "ok" : "error",
      cache: { memory: SUB_CACHE.size, last_good: LAST_GOOD_MEM.size },
      last_upstream: operators,
    };
    span.end({ status: 200, db_ok: dbOk, telegram_ok: telegramOk });
    return jsonResponse(payload);
  },
  async handleHealthFull(env, logger) {
    const span = (logger || Logger).span("health_full");
    let dbOk = true;
    let operators = [];
    let errors = [];
    const telegramResult = await Telegram.getMeCached(env, logger);
    const telegramOk = telegramResult?.ok && telegramResult?.telegram?.ok;
    try {
      await dbFirst(env.DB, "health_full.ping", () => env.DB.prepare("SELECT 1").first(), logger);
      const rows = await dbAll(
        env.DB,
        "health_full.operator_settings",
        () =>
          env.DB
            .prepare("SELECT operator_id, last_upstream_status, last_upstream_at FROM operator_settings ORDER BY last_upstream_at DESC LIMIT 5")
            .all(),
        logger
      );
      operators = rows?.results || [];
      const errRows = await dbAll(
        env.DB,
        "health_full.audit_logs",
        () => env.DB.prepare("SELECT event_type, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 5").all(),
        logger
      );
      errors = errRows?.results || [];
    } catch {
      dbOk = false;
    }
    const payload = {
      status: "ok",
      version: APP.version,
      db: dbOk ? "ok" : "error",
      telegram: telegramOk ? "ok" : "error",
      cache: { memory: SUB_CACHE.size, last_good: LAST_GOOD_MEM.size },
      last_upstream: operators,
      last_errors: errors,
    };
    span.end({ status: 200, db_ok: dbOk, telegram_ok: telegramOk });
    return jsonResponse(payload);
  },
  handleLanding(request, env, logger) {
    const span = (logger || Logger).span("landing");
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
    .hidden { display:none; }
    .links { margin-top: 12px; display:flex; flex-direction:column; gap:12px; }
    .link-row { display:flex; flex-direction:column; gap:8px; padding:12px; border-radius: 14px; background: rgba(15,23,42,0.5); }
    .badge { display:inline-flex; padding:4px 8px; border-radius:999px; background: rgba(255,255,255,0.12); font-size:12px; }
    .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:space-between; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>پنل اشتراک برند برای اپراتورها</h1>
      <p class="muted">ورود از طریق Telegram Login Widget و کد دعوت مدیر.</p>
      <div class="panel" id="login-panel">
        <div id="telegram-login"></div>
        <p class="muted">کد دعوت (اختیاری)</p>
        <input id="invite-code" placeholder="Invite code" />
      </div>
      <div class="panel hidden" id="dashboard">
        <div class="row">
          <strong>داشبورد اپراتور</strong>
          <button class="glass-btn" id="logout-btn">خروج</button>
        </div>
        <p class="muted" id="status-text">در حال دریافت اطلاعات...</p>
        <div class="links" id="links"></div>
      </div>
      <div class="grid">
        <a class="glass-btn" href="https://t.me/${botUsername}">🧊 ورود از تلگرام</a>
        <a class="glass-btn" href="${base}/health">🧊 وضعیت سلامت</a>
      </div>
    </div>
  </div>
  <script>
    const inviteInput = document.getElementById('invite-code');
    const dashboard = document.getElementById('dashboard');
    const loginPanel = document.getElementById('login-panel');
    const linksEl = document.getElementById('links');
    const statusText = document.getElementById('status-text');
    const logoutBtn = document.getElementById('logout-btn');
    const tokenKey = 'osm_session_token';

    const setToken = (token) => localStorage.setItem(tokenKey, token);
    const getToken = () => localStorage.getItem(tokenKey);
    const clearToken = () => localStorage.removeItem(tokenKey);

    const apiFetch = async (path, options = {}) => {
      const token = getToken();
      const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
      if (token) headers['Authorization'] = 'Bearer ' + token;
      const res = await fetch('${base}' + path, { ...options, headers });
      return res.json();
    };

    const renderDashboard = async () => {
      loginPanel.classList.add('hidden');
      dashboard.classList.remove('hidden');
      const [linksRes, statusRes] = await Promise.all([
        apiFetch('/api/v1/operators/me/customer-links'),
        apiFetch('/api/v1/operators/me/status'),
      ]);
      if (!linksRes.ok) {
        statusText.textContent = 'خطا در دریافت لینک‌ها';
        return;
      }
      const status = statusRes.ok ? statusRes.data : {};
      statusText.textContent =
        'وضعیت آپ‌استریم: ' +
        (status.last_upstream_status || '-') +
        ' | دامنه: ' +
        (status.domain_status || '-') +
        ' | آخرین اسنپ‌شات: ' +
        (status.snapshot_updated_at || '-');
      linksEl.innerHTML = '';
      (linksRes.data || []).forEach((link) => {
        const row = document.createElement('div');
        row.className = 'link-row';
        const prefix = status.domain_status === 'verified' && status.domain_name
          ? 'https://' + status.domain_name + '/sub/'
          : '${base}/sub/' + link.public_token + '/';
        row.innerHTML = \`
          <div class="row">
            <span class="badge">\${link.label || 'مشتری'}</span>
            <span class="muted">\${link.enabled ? 'فعال' : 'غیرفعال'}</span>
          </div>
          <div class="muted">\${prefix}TOKEN</div>
          <div class="row">
            <button class="glass-btn" data-copy="\${prefix}">کپی پیشوند</button>
            <button class="glass-btn" data-rotate="\${link.id}">چرخش لینک</button>
          </div>
        \`;
        linksEl.appendChild(row);
      });
      linksEl.querySelectorAll('button[data-copy]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await navigator.clipboard.writeText(btn.dataset.copy);
          alert('کپی شد');
        });
      });
      linksEl.querySelectorAll('button[data-rotate]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const res = await apiFetch('/api/v1/operators/me/customer-links/' + btn.dataset.rotate + '/rotate', { method: 'POST' });
          if (res.ok) renderDashboard();
          else alert('خطا در چرخش');
        });
      });
    };

    logoutBtn.addEventListener('click', () => {
      clearToken();
      dashboard.classList.add('hidden');
      loginPanel.classList.remove('hidden');
    });

    window.onTelegramAuth = async (user) => {
      const payload = { ...user, invite_code: inviteInput.value || undefined };
      const res = await fetch('${base}/auth/telegram', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.ok) {
        setToken(data.token);
        await renderDashboard();
      } else {
        alert('خطا: ' + data.error);
      }
    };

    if (getToken()) {
      renderDashboard();
    }
  </script>
  <script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="${botUsername}" data-size="large" data-userpic="false" data-onauth="onTelegramAuth(user)" data-request-access="write"></script>
</body>
</html>`;
    span.end({ status: 200 });
    return htmlResponse(html);
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
  async fetch(request, env, ctx) {
    return withRequestLogger(request, env, async (logger, requestId) => Router.handle(request, env, ctx, logger, requestId));
  },
  async scheduled(event, env, ctx) {
    const logger = createLogger(env).child({ scope: "scheduled" });
    ctx.waitUntil(D1.purgeOldRecords(env.DB, APP.purgeRetentionDays * 24 * 60 * 60 * 1000, logger));
    if (!env.NOTIFY_QUEUE) {
      ctx.waitUntil(NotificationService.processPendingJobs(env, logger));
    }
  },
  async queue(batch, env) {
    const logger = createLogger(env).child({ scope: "queue" });
    for (const message of batch.messages) {
      await NotificationService.processQueueMessage(env, message, logger);
    }
  },
};
