
const Logger = {
  info: (msg, data = {}) => console.log(JSON.stringify({ level: "INFO", msg, ...data, ts: new Date().toISOString() })),
  warn: (msg, data = {}) => console.warn(JSON.stringify({ level: "WARN", msg, ...data, ts: new Date().toISOString() })),
  error: (msg, err, data = {}) => console.error(JSON.stringify({ 
    level: "ERROR", msg, error: err?.message || err, ...data, ts: new Date().toISOString() 
  })),
};
const SUB_CACHE = new Map();
const CACHE_TTL = 60 * 1000; // 60 ثانیه





function getCachedSub(key) {
  const entry = SUB_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) {
    SUB_CACHE.delete(key);
    return null;
  }
  return entry;
}

function setCachedSub(key, body, headers) {
  // جلوگیری از رشد بی‌رویه حافظه
  if (SUB_CACHE.size > 1000) SUB_CACHE.clear();
  
  SUB_CACHE.set(key, {
    body,
    headers,
    timestamp: Date.now()
  });
}
// --- UTF-8 SAFE ENCODING HELPERS ---
function utf8SafeEncode(str) {
  try {
    return btoa(new TextEncoder().encode(str).reduce((data, byte) => data + String.fromCharCode(byte), ''));
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

function utf8SafeDecode(b64) {
  try {
    // تمیزکاری بیس ۶۴ قبل از دیکود
    const clean = b64.replace(/[\n\r\s]/g, '');
    return new TextDecoder().decode(Uint8Array.from(atob(clean), c => c.charCodeAt(0)));
  } catch (e) {
    // فال‌بک قدیمی
    return decodeURIComponent(escape(atob(b64)));
  }
}

const AuditService = {
  async logFetch(request, username, subId, env, configNames = []) {
    const requestId = crypto.randomUUID();
    
    try {
      // بررسی وجود شیء env برای جلوگیری از کرش
      if (!env || !env.LOG_CHANNEL_ID) {
        Logger.warn("Audit Log skipped: env.LOG_CHANNEL_ID is not defined", { requestId });
        return;
      }

      const safeConfigNames = Array.isArray(configNames) ? configNames : [];
      const logContent = AuditFormatter.formatSubscriptionFetch(request, username, subId, safeConfigNames);
      
      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: env.LOG_CHANNEL_ID,
          text: logContent,
          parse_mode: "HTML",
          disable_web_page_preview: true
        }),
      });

    } catch (err) {
      // در محیط پرواد، خطا در لاگر نباید باعث توقف پروسه اصلی شود
      Logger.error("Background Audit Logging Failed", err, { requestId });
    }
  }
};
const TelegramFormatter = {
  prepareSubscriptionResponse(baseUrl, username, subId) {
    // 1. لینک اصلی (Main Link) - که همان Worker فعلی است
    const mainSubLink = `${baseUrl}/sub/${subId}`;
    
    // 2. لینک ملی/نیم‌بها (Meli Link) - آدرس جدید آروان
    // اگر subId شامل اسلش باشد (مثلا user/uuid)، ساختار درست در می‌آید
    const arvanBase = "https://sahabtech.mehradinanlu-rchff.arvanedge.ir";
    const meliSubLink = `${arvanBase}/sub/${subId}`;

    // انکود کردن برای دکمه‌های اشتراک‌گذاری
    const encodedMain = encodeURIComponent(mainSubLink);
    
    // نام‌گذاری برای اپلیکیشن‌ها
    const nameConfig = username; 
    const nameForApp = `Sub_${username}`;
    
    const text = `
✨ <b>سرویس اشتراک اختصاصی هایدنِت</b> ✨

👤 <b>نام کاربری</b>
<code>${username}</code>

🌐 <b>لینک اصلی (اینترنت آزاد)</b>
ℹ️ <i>پایداری بالا - مناسب برای اکثر اپراتورها</i>
<code>${mainSubLink}</code>

🇮🇷 <b>لینک ملی (نیم‌بها / آروان)</b>
ℹ️ <i>مناسب برای زمان اختلال یا اینترنت ملی</i>
<code>${meliSubLink}</code>

🚀 <b>اتصال سریع (One-Click)</b>
⚡ با لمس دکمه‌های پایین، اشتراک (لینک اصلی) به‌صورت خودکار به اپلیکیشن شما اضافه می‌شود.

📘 <b>راهنمای افزودن دستی</b>

1️⃣ <b>کپی لینک</b>  
🔹 یکی از لینک‌های بالا (ترجیحاً اصلی) را کپی کنید.

2️⃣ <b>باز کردن اپلیکیشن</b>  
📱 برنامه v2rayNG، NekoBox یا v2Box را باز کنید.

3️⃣ <b>افزودن اشتراک</b>  
➕ وارد بخش Subscriptions شده و گزینه <b>Add Subscription</b> یا علامت <b>+</b> را بزنید.

4️⃣ <b>جایگذاری و ذخیره</b>  
📌 لینک را Paste کرده و نام دلخواه بگذارید.
💾 سپس دکمه <b>Save</b> را زده و حتماً <b>Update</b> کنید.
    `.trim();
    
    // دکمه‌ها معمولاً روی لینک اصلی تنظیم می‌شوند تا از مشکلات SSL آروان جلوگیری شود
    // اما کاربر در متن به هر دو لینک دسترسی دارد
    const keyboard = {
      inline_keyboard: [
        [
          { text: "🤖 افزودن به v2rayNG", url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2rayng://install-config?url=${mainSubLink}#💠Premium_${nameConfig}`)}` },
          { text: "🐱 افزودن به NekoBox", url: `${baseUrl}/redirect?target=${encodeURIComponent(`sn://subscription?url=${mainSubLink}&name=${nameForApp}`)}` }
        ],
        [
          { text: "🍎 افزودن به Streisand", url: `${baseUrl}/redirect?target=${encodeURIComponent(`streisand://import/${mainSubLink}`)}` },
          { text: "📱 افزودن به v2Box", url: `${baseUrl}/redirect?target=${encodeURIComponent(`v2box://install-sub?url=${mainSubLink}&name=${nameConfig}`)}` }
        ],
        [
          { text: "📋 اشتراک‌گذاری لینک اصلی", url: `https://t.me/share/url?url=${encodedMain}` }
        ]
      ]
    };

    return { text, keyboard };
  },
  
  prepareUnauthorizedResponse() {
    return {
      text: `
⚠️ <b>خطای عدم دسترسی</b>
───────────────────
❌ کاربر گرامی، شما ادمین نیستید و اجازه استفاده از این ربات را ندارید.

🆔 شناسه کاربری شما: <code>{user_id}</code>
      `.trim(),
      keyboard: null
    };
  }
};

const DateTimeService = {
  /**
   * تعریف فرمتر به صورت مستقیم در بدنه کلاس برای بهینه‌سازی CPU
   * استفاده از مقادیر به صورت inline باعث می‌شود تایپ‌اسکریپت آن‌ها را به عنوان Literal تشخیص دهد.
   */
  
  _formatter: new Intl.DateTimeFormat("fa-IR", {
    timeZone: "Asia/Tehran",
    year: "numeric",
    month: "long",
    day: "numeric",
    weekday: "long",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }),

  /**
   * تولید تاریخ فارسی با رعایت اصول پایداری و کارایی
   */
  getPersianLongDate() {
    try {
      // استفاده مستقیم از متد format برای دریافت رشته کامل
      const formatted = this._formatter.format(new Date());
      
      // پاکسازی فاصله‌های مجازی (ZWNJs) احتمالی برای نمایش بهتر در تلگرام
      const cleanDate = formatted.replace(/[\u200c\u200b]/g, ' ');
      
      return `${cleanDate} (‎+۳:۳۰ گرینویچ)`;

    } catch (err) {
      // در محیط شرکت، خطا نباید بی‌پاسخ بماند
      if (typeof Logger !== 'undefined') {
        Logger.error("DateTime Generation Failure", err);
      }
      return `${new Date().toISOString()} (UTC Fallback)`;
    }
  }
};

const AuditFormatter = {
  formatSubscriptionFetch(request, username, subId, configNames = []) {
    const url = new URL(request.url);
    const ip = request.headers.get("cf-connecting-ip") || "Unknown";
    const country = request.headers.get("cf-ipcountry") || "??";
    const org = request.cf?.asOrganization || "ISP Unknown";
    const ua = request.headers.get("user-agent") || "Unknown Agent";
    const time = DateTimeService.getPersianLongDate();

    const flag = country.toUpperCase().replace(/./g, char =>
      String.fromCodePoint(char.charCodeAt(0) + 127397)
    );

    // لینک اشتراک (کلیک‌خور)
    const subscriptionUrl = `https://${url.hostname}/sub/${subId}`;

    const safeConfigs = Array.isArray(configNames) ? configNames : [];

    const configList = safeConfigs.length > 0
      ? safeConfigs.map((name, index) => {
          const isLast = index === safeConfigs.length - 1;
          const prefix = isLast ? "  └─ 🏷️ " : "  ├─ 🏷️ ";
          return `${prefix}<code>${name}</code>`;
        }).join("\n")
      : "  └─ <i>لیستی یافت نشد</i>";

    return `
💎 <b>Premium Subscription Fetch Detected</b>
───────────────────
📦 <b>سرویس:</b> <code>پنل پرمیوم</code>
👤 <b>نام کاربر:</b> <code>${username}</code>
🆔 <b>شناسه:</b> <code>${subId}</code>

🔗 <b>لینک اشتراک:</b>
<a href="${subscriptionUrl}">${subscriptionUrl}</a>

🛠 <b>کانفیگ‌های ارسال شده (${safeConfigs.length}):</b>
${configList}

───────────────────
🌐 <b>آدرس:</b> <code>${url.hostname}</code>
📍 <b>مشخصات شبکه:</b>
${flag} <code>${ip}</code>
🏢 <code>${org}</code>

🖥️ <b>کلاینت:</b>
<code>${ua}</code>

🗓️ <b>زمان:</b>
${time}
    `.trim();
  }
};


// --- 1. THE HYPER-QUANTUM GENERATOR (SWEDEN PRO MAX 🇸🇪) ---
/**
 * Simulates Real-User behavior including Filters, Campaigns, and Ad-Clicks.
 * Chaos Level: Extreme. Memory Leak: Zero.
 */
const generateQuantumSpx = () => {
  const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
  
  const dict = {
    cats: ["dam", "herr", "divided", "barn", "hm-home", "sport", "beauty"],
    subcats: ["klanningar", "byxor", "hoodies-sweatshirts", "jackor-kappor", "skjortor", "jeans", "skor", "accessoires"],
    colors: ["svart", "vit", "beig", "bla", "gron", "rod", "rosa", "guld"],
    sorts: ["ascPrice", "descPrice", "newArrivals", "stock"],
    campaigns: ["summer-sale", "new-season", "members-prices", "sustainability-edit"]
  };

  const genArtId = () => `${rnd(10, 12)}${rnd(100000, 999999)}${rnd(100, 999)}`; 

  // Scenario 1: Deep Product View (40%)
  const scenarioProduct = () => `/se/${pick(dict.cats)}/${pick(dict.subcats)}/productpage.${genArtId()}.html`;

  // Scenario 2: Listing with Filters (30%)
  const scenarioListing = () => {
    const filters = [
      `colorWithNames=${pick(dict.colors)}`,
      `sizes=${rnd(34, 46)}`,
      `sort=${pick(dict.sorts)}`,
      `offset=${rnd(0, 4) * 48}`
    ];
    const activeFilters = filters.sort(() => 0.5 - Math.random()).slice(0, rnd(1, 3)).join("&");
    return `/se/${pick(dict.cats)}/shop-by-product/${pick(dict.subcats)}/?${activeFilters}`;
  };

  // Scenario 3: Ad/Campaign Click (20%)
  const scenarioAdClick = () => {
    const sources = ["google", "instagram", "facebook", "newsletter"];
    return `/se/${pick(dict.cats)}/productpage.${genArtId()}.html?utm_source=${pick(sources)}&utm_medium=cpc&utm_campaign=${pick(dict.campaigns)}`;
  };

  // Scenario 4: Static Pages (10%)
  const scenarioStatic = () => pick([
      "/se/cart", "/se/favourites", "/se/customer-service/kontakta-oss", 
      "/se/member/my-account", "/se/customer-service/retur-och-aterbetalning"
  ]);

  const dice = Math.random();
  let finalPath = "";
  if (dice < 0.40) finalPath = scenarioProduct();
  else if (dice < 0.70) finalPath = scenarioListing();
  else if (dice < 0.90) finalPath = scenarioAdClick();
  else finalPath = scenarioStatic();

  return encodeURIComponent(finalPath);
};

// --- 2. CONFIGURATION ---
const CONFIG = {
  UPSTREAM_BASE: "https://xyz.subscriptionlink.xyz:2053",
  UPSTREAM_HOST: "xyz.subscriptionlink.xyz",

  PERSIAN_EXPIRY_CONFIG: `vless://expired-id@127.0.0.1:8888?encryption=none&security=none#⚠️_حجم_یا_تاریخ_انقضا_تمام_شده_@HideNet_SpeedVPN`,
  FIXED_SUBSCRIPTIONS_URLS: [
  // "https://solitary-fire-19a0.opcelon.workers.dev/sublarim/lxr8nya2x1is0qlg",
  // "https://solitary-fire-19a0.opcelon.workers.dev/sublarim/wjvwwshut1juqszp",
 //  "https://solitary-fire-19a0.opcelon.workers.dev/sublarim/gwk0wtyielpjwa0l",
  //"https://solitary-fire-19a0.opcelon.workers.dev/sublarim/c6a3gf7i1awbr3mw",
  // "https://ger.linud.ajax-cdn.xyz:2096/sub/jnwztj249zrah8vy",
  // "https://ger.linud.ajax-cdn.xyz:2096/sub/jnwztj249zrah8vi",
  // "https://ger.linud.ajax-cdn.xyz:2096/sub/jnwztj249zrah8vp",
  // "https://api.linud.ajax-cdn.xyz:2096/sub/jxx29mwy0f8auje3"
  //  "https://twilight-poetry-9590.opcelon.workers.dev/",
  //"https://solitary-fire-19a0.opcelon.workers.dev/sublarim/lyp430prdvyai3vr",
   // "https://sub.myvipnet.com/sub/NTA5NDgzNzgzM184Nzk0LDE3Njk4MzM1NDcu7B5Q9Ir4L",
    //"https://subscription-Representation-price.a-coin-black.com:443/sub/R29sZG1hcmtldCwxNzY5OTY4MDA4oGeQItjnyL",
   // "https://cdn.fildl.ir/sub/Uk5fQ0FQWElfODcyNiwxNzY3ODI4OTYxeU0Vh9zmBg",
 
    
  ],
  FILTER_KEYWORDS: [
    "expire", "traffic", "gb", "date", "reset", "email", "website", 
    "زمان", "حجم", "انقضا", "باقیمانده", "name config", "profile", "days",
    "وضعیت", "اشتراک", "لینک", "ترافیک", "کاربر", "تمدید", "هشدار"
  ],
  
  EXTRA_CONFIGS: [
 // "vless://51bd5ebc-1f78-4e49-9b05-83810fa1b408@shahriar.netmorek.site:1011?encryption=none&security=none&type=tcp&headerType=http&host=Uewuy.divarcdn.com#%F0%9F%87%A9%F0%9F%87%AA%F0%9D%91%87%F0%9D%91%A2%F0%9D%91%9B%F0%9D%91%9B%F0%9D%91%92%F0%9D%91%99%F0%9F%87%AE%F0%9F%87%B7-Tabriz",
  "vless://fae6d449-b6cb-406a-801d-0a233426e062@127.0.0.1:1010?encryption=none&security=none&type=tcp&headerType=none#%D9%BE%D8%B4%D8%AA%DB%8C%D8%A8%D8%A7%D9%86%DB%8C%20%F0%9F%9F%A2%20%3A%20%40SpeedVPNsale"
  ],

  CLIENT_KEYWORDS: [
    "v2ray", "xray", "sing-box", "clash", "shadowrocket", "surge", "quantumult", "stash", "ktor-client",
    "v2rayng", "v2rayn", "nekoray", "nekobox", "hiddify", "surfboard", "napsternetv",
    "foxray", "v2box", "karing", "streisand", "okhttp", "dart", "go-http", "cfnetwork", "electron"
  ]
};


const DeceptiveUI = {
  getHtml() {
    return `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پلتفرم ابری سحاب‌تک | زیرساخت توسعه‌دهندگان</title>
    <meta name="description" content="مرجع مستندات API و زیرساخت ابری مقیاس‌پذیر برای کسب‌وکارهای ایرانی. ارائه دهنده خدمات CDN، رایانش ابری و امنیت سایبری.">
    <meta name="robots" content="noindex, nofollow">
    <style>
        :root {
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --secondary: #0f172a;
            --text-main: #334155;
            --text-light: #64748b;
            --bg-light: #f8fafc;
            --border: #e2e8f0;
            --code-bg: #1e293b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Tahoma', 'Segoe UI', sans-serif; }
        body { background: #fff; color: var(--text-main); line-height: 1.7; overflow-x: hidden; font-size: 15px; }
        
        /* Header */
        header { background: rgba(255,255,255,0.95); backdrop-filter: blur(12px); position: fixed; width: 100%; top: 0; z-index: 1000; border-bottom: 1px solid var(--border); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.02); }
        .nav-container { max-width: 1200px; margin: 0 auto; padding: 0 2rem; height: 70px; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-weight: 900; font-size: 1.6rem; color: var(--secondary); text-decoration: none; display: flex; align-items: center; gap: 10px; }
        .logo span { color: var(--primary); }
        .nav-links { display: flex; gap: 2.5rem; }
        .nav-links a { text-decoration: none; color: var(--text-main); font-weight: 500; font-size: 0.95rem; transition: 0.2s; position: relative; }
        .nav-links a:hover { color: var(--primary); }
        .cta-btn { background: var(--primary); color: white; padding: 0.6rem 1.8rem; border-radius: 6px; text-decoration: none; font-weight: bold; transition: 0.3s; font-size: 0.9rem; }
        .cta-btn:hover { background: var(--primary-dark); transform: translateY(-1px); }

        /* Hero */
        .hero { padding: 140px 2rem 80px; text-align: center; background: radial-gradient(circle at 50% 0%, #e0f2fe 0%, #ffffff 60%); }
        .badge { background: #e0f2fe; color: var(--primary-dark); padding: 5px 15px; border-radius: 50px; font-size: 0.85rem; font-weight: 600; display: inline-block; margin-bottom: 1.5rem; border: 1px solid #bae6fd; }
        h1 { font-size: 3rem; font-weight: 900; color: var(--secondary); margin-bottom: 1.5rem; letter-spacing: -0.5px; line-height: 1.3; }
        p.lead { font-size: 1.2rem; color: var(--text-light); max-width: 700px; margin: 0 auto 3rem; }
        
        /* Code Terminal */
        .terminal-container { max-width: 900px; margin: 0 auto 5rem; text-align: left; direction: ltr; box-shadow: 0 20px 50px rgba(0,0,0,0.15); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }
        .terminal-header { background: #0f172a; padding: 12px 20px; display: flex; gap: 8px; align-items: center; border-bottom: 1px solid #334155; }
        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot.red { background: #ef4444; } .dot.yellow { background: #f59e0b; } .dot.green { background: #22c55e; }
        .terminal-title { margin-left: auto; color: #94a3b8; font-size: 0.8rem; font-family: monospace; }
        .terminal-body { background: #1e293b; padding: 25px; color: #e2e8f0; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.95rem; line-height: 1.6; }
        .keyword { color: #c084fc; } .string { color: #86efac; } .function { color: #60a5fa; } .comment { color: #64748b; }

        /* Services Grid */
        .section-title { text-align: center; margin-bottom: 4rem; }
        .section-title h2 { font-size: 2.2rem; color: var(--secondary); margin-bottom: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; max-width: 1200px; margin: 0 auto 6rem; padding: 0 2rem; }
        .card { padding: 2.5rem; border: 1px solid var(--border); border-radius: 12px; transition: 0.3s; background: white; position: relative; overflow: hidden; }
        .card:hover { border-color: var(--primary); box-shadow: 0 10px 40px rgba(0,0,0,0.08); }
        .card h3 { margin: 1rem 0; font-size: 1.3rem; color: var(--secondary); }
        .card p { color: var(--text-light); font-size: 0.95rem; }
        .icon-box { width: 50px; height: 50px; background: #f0f9ff; color: var(--primary); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; }

        /* API Docs (Fake Table) */
        .docs-section { background: var(--bg-light); padding: 5rem 2rem; border-top: 1px solid var(--border); }
        .table-container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; text-align: right; }
        th { background: #f1f5f9; padding: 1.2rem; font-weight: 600; color: var(--secondary); border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        td { padding: 1.2rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; color: var(--text-main); }
        tr:last-child td { border-bottom: none; }
        .method { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; font-family: monospace; }
        .get { background: #dcfce7; color: #166534; } .post { background: #dbeafe; color: #1e40af; } .put { background: #ffedd5; color: #9a3412; }
        .endpoint { font-family: monospace; color: var(--primary-dark); direction: ltr; display: inline-block; }

        /* Fake Logs (Infinite Scroll Illusion) */
        .logs-section { max-width: 1200px; margin: 4rem auto; padding: 0 2rem; }
        .log-box { background: #000; color: #0f0; padding: 1rem; border-radius: 8px; height: 300px; overflow-y: hidden; font-family: monospace; font-size: 0.8rem; position: relative; opacity: 0.8; }
        .log-box::after { content: ''; position: absolute; bottom: 0; left: 0; width: 100%; height: 50px; background: linear-gradient(to top, #000, transparent); }
        #log-content { display: flex; flex-direction: column; justify-content: flex-end; }

        /* Footer */
        footer { background: var(--secondary); color: white; padding: 4rem 2rem 2rem; margin-top: auto; }
        .footer-grid { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 3rem; margin-bottom: 3rem; }
        .footer-col h4 { margin-bottom: 1.5rem; font-size: 1.1rem; color: white; }
        .footer-col ul { list-style: none; }
        .footer-col li { margin-bottom: 0.8rem; }
        .footer-col a { color: #94a3b8; text-decoration: none; font-size: 0.9rem; transition: 0.2s; }
        .footer-col a:hover { color: white; }
        .copy { text-align: center; color: #64748b; padding-top: 2rem; border-top: 1px solid #1e293b; font-size: 0.85rem; }

        @media (max-width: 768px) {
            h1 { font-size: 2rem; }
            .nav-links { display: none; }
            .grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

    <header>
        <div class="nav-container">
            <a href="#" class="logo">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
                سحاب‌<span>تک</span>
            </a>
            <div class="nav-links">
                <a href="#">محصولات ابری</a>
                <a href="#">مستندات API</a>
                <a href="#">تعرفه‌ها</a>
                <a href="#">وبلاگ فنی</a>
                <a href="#">پشتیبانی سازمانی</a>
            </div>
            <a href="#" class="cta-btn">ورود به پنل</a>
        </div>
    </header>

    <section class="hero">
        <span class="badge">نسخه جدید API v3.4 منتشر شد</span>
        <h1>زیرساخت ابری هوشمند<br>برای کسب‌وکارهای مدرن</h1>
        <p class="lead">پلتفرم جامع مدیریت میکروسرویس‌ها، CDN توزیع شده و امنیت لایه ۷ برای توسعه‌دهندگانی که به مقیاس‌پذیری اهمیت می‌دهند.</p>
        
        <div class="terminal-container">
            <div class="terminal-header">
                <div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div>
                <span class="terminal-title">bash — curl</span>
            </div>
            <div class="terminal-body">
                <span class="comment"># دریافت وضعیت سرویس‌ها از نود تهران</span><br>
                <span class="function">curl</span> -X GET https://api.sahabtech.ir/v1/status \<br>
                &nbsp;&nbsp;-H <span class="string">"Authorization: Bearer sk_live_..."</span><br><br>
                <span class="comment">// Response (200 OK)</span><br>
                {<br>
                &nbsp;&nbsp;<span class="keyword">"region"</span>: <span class="string">"ir-thr-1"</span>,<br>
                &nbsp;&nbsp;<span class="keyword">"status"</span>: <span class="string">"operational"</span>,<br>
                &nbsp;&nbsp;<span class="keyword">"latency"</span>: <span class="string">"12ms"</span>,<br>
                &nbsp;&nbsp;<span class="keyword">"services"</span>: [<span class="string">"compute"</span>, <span class="string">"storage"</span>, <span class="string">"cdn"</span>]<br>
                }
            </div>
        </div>
    </section>

    <section class="grid">
        <div class="card">
            <div class="icon-box">⚡</div>
            <h3>رایانش لبه‌ای (Edge)</h3>
            <p>اجرای کدهای سرورلس در نزدیک‌ترین نقطه جغرافیایی به کاربران شما با تاخیر زیر ۲۰ میلی‌ثانیه در سراسر کشور.</p>
        </div>
        <div class="card">
            <div class="icon-box">🛡️</div>
            <h3>دیواره آتش ابری (WAF)</h3>
            <p>محافظت هوشمند در برابر حملات DDoS لایه ۳، ۴ و ۷ با قابلیت تشخیص خودکار ترافیک مخرب و بات‌ها.</p>
        </div>
        <div class="card">
            <div class="icon-box">🔄</div>
            <h3>لود بالانسینگ خودکار</h3>
            <p>توزیع هوشمند ترافیک بین سرورهای ابری و فیزیکی برای تضمین آپتایم ۹۹.۹۹٪ سرویس‌های حیاتی.</p>
        </div>
    </section>

    <div class="section-title">
        <h2>مستندات فنی و اندپوینت‌ها</h2>
        <p style="color: #64748b;">راهنمای کامل اتصال به سرویس‌های زیرساخت</p>
    </div>

    <section class="docs-section">
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th width="15%">متد</th>
                        <th width="35%">آدرس (Endpoint)</th>
                        <th>توضیحات عملکرد</th>
                        <th width="15%">وضعیت</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="method get">GET</span></td>
                        <td><span class="endpoint">/v1/instances</span></td>
                        <td>دریافت لیست ماشین‌های مجازی فعال در دیتاسنتر</td>
                        <td><span style="color: #166534; font-size: 0.85rem;">● پایدار</span></td>
                    </tr>
                    <tr>
                        <td><span class="method post">POST</span></td>
                        <td><span class="endpoint">/v1/deploy/container</span></td>
                        <td>ایجاد و راه‌اندازی کانتینر جدید (Docker/Podman)</td>
                        <td><span style="color: #166534; font-size: 0.85rem;">● پایدار</span></td>
                    </tr>
                    <tr>
                        <td><span class="method put">PUT</span></td>
                        <td><span class="endpoint">/v1/dns/records/{id}</span></td>
                        <td>بروزرسانی رکوردهای DNS دامنه متصل شده</td>
                        <td><span style="color: #ca8a04; font-size: 0.85rem;">● در حال تعمیر</span></td>
                    </tr>
                    <tr>
                        <td><span class="method get">GET</span></td>
                        <td><span class="endpoint">/v1/metrics/bandwidth</span></td>
                        <td>گزارش لحظه‌ای مصرف پهنای باند شبکه</td>
                        <td><span style="color: #166534; font-size: 0.85rem;">● پایدار</span></td>
                    </tr>
                    <tr>
                        <td><span class="method post">POST</span></td>
                        <td><span class="endpoint">/v1/auth/token/refresh</span></td>
                        <td>تمدید توکن دسترسی (OAuth2)</td>
                        <td><span style="color: #166534; font-size: 0.85rem;">● پایدار</span></td>
                    </tr>
                     <tr>
                        <td><span class="method get">GET</span></td>
                        <td><span class="endpoint">/v1/storage/buckets</span></td>
                        <td>لیست باکت‌های ذخیره‌سازی ابری S3</td>
                        <td><span style="color: #166534; font-size: 0.85rem;">● پایدار</span></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Fake Logs Section to simulate heavy activity -->
        <div class="logs-section">
            <h3 style="margin-bottom: 1rem; color: #334155;">وضعیت لحظه‌ای شبکه (Live Logs)</h3>
            <div class="log-box" id="log-box">
                <div id="log-content"></div>
            </div>
        </div>
    </section>

    <footer>
        <div class="footer-grid">
            <div class="footer-col">
                <h4>سحاب‌تک</h4>
                <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.8;">
                    پیشرو در ارائه خدمات زیرساخت ابری و دیتاسنترهای نرم‌افزاری در خاورمیانه. ما به توسعه‌دهندگان کمک می‌کنیم تا بدون دغدغه زیرساخت، خلق کنند.
                </p>
            </div>
            <div class="footer-col">
                <h4>خدمات</h4>
                <ul>
                    <li><a href="#">سرور ابری (VPS)</a></li>
                    <li><a href="#">کانتینر سرویس</a></li>
                    <li><a href="#">فضای ابری S3</a></li>
                    <li><a href="#">پلتفرم CI/CD</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h4>منابع</h4>
                <ul>
                    <li><a href="#">مستندات فنی</a></li>
                    <li><a href="#">وضعیت سرورها</a></li>
                    <li><a href="#">کتابخانه‌های کلاینت</a></li>
                    <li><a href="#">انجمن توسعه‌دهندگان</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h4>تماس با ما</h4>
                <ul>
                    <li style="color: #94a3b8; font-size: 0.9rem;">تهران، میدان ونک، خیابان ملاصدرا، برج فناوری سحاب، طبقه ۴</li>
                    <li><a href="#">support@sahabtech.ir</a></li>
                    <li><a href="#">+98 21 8800 0000</a></li>
                </ul>
            </div>
        </div>
        <div class="copy">
            © ۱۴۰۳ شرکت توسعه فناوری سحاب‌تک (سهامی خاص). تمامی حقوق محفوظ است. | <a href="#" style="color: #64748b;">قوانین و مقررات</a>
        </div>
    </footer>

    <script>
        // Script to generate fake system logs
        const logContainer = document.getElementById('log-content');
        const actions = ['[INFO] Health check passed', '[WARN] Latency spike detected', '[INFO] Container created', '[INFO] DNS propagated', '[DEBUG] Cache miss', '[INFO] Scaling group updated'];
        const regions = ['ir-thr-1', 'ir-tbz-2', 'ir-mhd-1', 'ir-shz-3'];
        
        function addLog() {
            const now = new Date().toISOString();
            const action = actions[Math.floor(Math.random() * actions.length)];
            const region = regions[Math.floor(Math.random() * regions.length)];
            const logLine = document.createElement('div');
            logLine.style.marginBottom = '4px';
            logLine.textContent = \`\${now} \${region} \${action} - node-\${Math.floor(Math.random() * 9000) + 1000}\`;
            
            logContainer.appendChild(logLine);
            
            if (logContainer.children.length > 15) {
                logContainer.removeChild(logContainer.children[0]);
            }
        }

        // Fill initial logs
        for(let i=0; i<10; i++) addLog();
        
        // Add new logs periodically
        setInterval(addLog, 1500);
    </script>
</body>
</html>
    `;
  }
};

function base64Encode(str) {
  return btoa(new TextEncoder().encode(str).reduce((data, byte) => data + String.fromCharCode(byte), ''));
}

function base64Decode(b64) {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0)));
}

// --- 3. MAIN WORKER LOGIC ---
// --- UPDATED MAIN WORKER LOGIC ---
// --- 3. MAIN WORKER LOGIC ---
// --- 3. MAIN WORKER LOGIC ---
export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();
    try {
      const url = new URL(request.url);
      const pathParts = url.pathname.split('/').filter(Boolean);

      // --- Handle Telegram Webhook ---
      if (request.method === "POST" && pathParts[0] === "webhook") {
        return await handleTelegramWebhook(request, env);
      }

      // --- Handle Redirects ---
      if (url.pathname === "/redirect") {
        const target = url.searchParams.get("target");
        if (target) return new Response(null, { status: 302, headers: { "Location": target } });
      }

      // --- Logic for determining username/subId ---
      let username = "", subId = "";
      
      // Case 1: /sub/TOKEN
      if (pathParts[0] === "sub" && pathParts.length === 2) {
          subId = pathParts[1];
          username = "User"; 
      }
      // Case 2: /sub/username/uuid
      else if (pathParts[0] === "sub" && pathParts.length >= 3) {
          [username, subId] = [pathParts[1], pathParts[2]];
      }
      // Case 3: /username/uuid
      else if (pathParts.length === 2) {
          [username, subId] = pathParts;
      }
      // Case 4: /TOKEN (Short link)
      else if (pathParts.length === 1) {
          subId = pathParts[0];
          username = "User";
      }

      // --- 1. SUBSCRIPTION HANDLING ---
      // اگر لینک اشتراک معتبر تشخیص داده شد
      if (username && subId) {
        return await SubscriptionEngine.handle(request, username, subId, env, ctx);
      }

      // --- 2. ROOT PATH HANDLING (NEW) ---
      // اگر کاربر دقیقاً صفحه اصلی سایت را زده بود (بدون هیچ مسیری)
      if (url.pathname === "/" || pathParts.length === 0) {
        return new Response(DeceptiveUI.getHtml(), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow"
          }
        });
      }

      // --- 3. PROXY ENGINE (FALLBACK) ---
      // برای سایر مسیرها (مثل فایل‌های استاتیک پنل، عکس‌ها و...)
      return await ProxyEngine.handle(request, username, subId);

    }  catch (err) {
      Logger.error("Critical System Error", err, { requestId });
      return new Response(JSON.stringify({ error: "Internal Error" }), { status: 500 });
    }
  }
};

// --- 4. SUBSCRIPTION ENGINE (Updated for Quantum SPX) ---
/**
 * موتور مدیریت اشتراک (نسخه Production)
 * دارای قابلیت تزریق کوانتومی، شناسایی انقضا و سیستم نظارت پس‌زمینه
 */
// --- 4. SUBSCRIPTION ENGINE (Fixed: No Expiry Check, Force Merge) ---
// ============================
// SubscriptionEngine — Quantum Safe Edition
// کش داخلی ۱۰ ثانیه‌ای، بدون وابستگی به Cloudflare
// ============================

const SubManager = {
  /**
   * دریافت لینک‌های ثابت با کشینگ هوشمند ۱ ساعته
   */
  async fetchFixedSubs(requestId, ctx) {
    if (!CONFIG.FIXED_SUBSCRIPTIONS_URLS || CONFIG.FIXED_SUBSCRIPTIONS_URLS.length === 0) {
      return [];
    }

    const promises = CONFIG.FIXED_SUBSCRIPTIONS_URLS.map(async (url) => {
      try {
        // دریافت متن (یا از کش یا از شبکه)
        const text = await this.fetchWithCache(url, ctx);
        
        if (!text) return [];

        // پردازش و تمیزکاری
        const decoded = SubscriptionEngine.decodeContent(text);
        return this.sanitizeConfigs(decoded);
      } catch (e) {
        return []; 
      }
    });

    const results = await Promise.all(promises);
    return results.flat();
  },

  /**
   * سیستم کش اختصاصی برای پایداری در اختلالات
   * اگر لینک خارجی قطع باشد، تا 1 ساعت از کش می‌خواند
   */
  async fetchWithCache(url, ctx) {
    const cache = caches.default;
    const cacheKey = new Request(url, { method: "GET" }); // کلید کش بر اساس URL

    // 1. تلاش برای خواندن از کش کلادفلر
    let response = await cache.match(cacheKey);

    if (response) {
      // اگر در کش بود، همان را برگردان (بدون درخواست به اینترنت)
      // Logger.info("SubLink Cache Hit", { url });
      return await response.text();
    }

    // 2. اگر در کش نبود، درخواست به سرور اصلی (Network Fetch)
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 6000); // تایم‌اوت 6 ثانیه (کمی بیشتر برای شانس موفقیت)
      
      const freshResponse = await fetch(url, { 
        signal: controller.signal,
        headers: { "User-Agent": "v2rayNG/Teams-Worker-Cache" }
      });
      clearTimeout(id);

      if (freshResponse.ok) {
        const text = await freshResponse.text();
        
        // 3. ذخیره در کش برای 1 ساعت (3600 ثانیه)
        const responseToCache = new Response(text, {
          headers: { 
            "Content-Type": "text/plain",
            "Cache-Control": "public, max-age=3600" // دستور حیاتی برای ماندگاری 1 ساعته
          }
        });
        
        // استفاده از ctx.waitUntil برای جلوگیری از کند شدن پاسخ به کاربر هنگام نوشتن در کش
        if (ctx && ctx.waitUntil) {
          ctx.waitUntil(cache.put(cacheKey, responseToCache));
        }

        return text;
      }
    } catch (e) {
      // اگر اینترنت کلاً قطع بود و کش هم نداشتیم، متاسفانه هیچی برمی‌گرده
      // Logger.error("SubLink Network Fail", { url });
    }
    return null;
  },

  /**
   * حذف کانفیگ‌های مزاحم با اسکن عمیق (Deep Scan)
   */
  sanitizeConfigs(contentOrArray) {
    const lines = Array.isArray(contentOrArray) 
      ? contentOrArray 
      : contentOrArray.split(/\r?\n/);

    return lines.filter(line => {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.includes("://")) return false;

      // --- فیلتر مرحله 1: بررسی ظاهری ---
      if (
        trimmed.includes("@127.0.0.1") || 
        trimmed.includes("@localhost") || 
        trimmed.includes("@user:") ||
        trimmed.includes("0.0.0.0") 
      ) {
        return false;
      }

      // --- فیلتر مرحله 2: بررسی عمیق VMess ---
      if (trimmed.startsWith("vmess://")) {
        try {
          const b64 = trimmed.substring(8);
          const jsonStr = utf8SafeDecode(b64);
          const config = JSON.parse(jsonStr);

          // حذف اگر آدرس فیک باشد
          if (["0.0.0.0", "127.0.0.1", "localhost"].includes(config.add)) return false;

          // حذف اگر نام تبلیغاتی باشد
          if (config.ps) {
            const name = config.ps.toLowerCase();
            const isSpam = CONFIG.FILTER_KEYWORDS.some(kw => name.includes(kw));
            if (isSpam) return false;
          }
        } catch (e) {}
      }

      // --- فیلتر مرحله 3: بررسی نام کانفیگ در URL ---
      try {
        const hashIndex = trimmed.lastIndexOf('#');
        if (hashIndex !== -1) {
          const remark = decodeURIComponent(trimmed.substring(hashIndex + 1)).toLowerCase();
          const cleanRemark = remark.replace(/[:|_\-\s]/g, ' '); 
          const isInfo = CONFIG.FILTER_KEYWORDS.some(kw => cleanRemark.includes(kw));
          if (isInfo) return false;
        }
      } catch (e) {}

      return true;
    });
  }
};

const SubscriptionEngine = {
  async handle(request, username, subId, env, ctx) {
    const requestId = crypto.randomUUID();

    // 1. کش
    const cached = getCachedSub(subId);
    if (cached) {
      return new Response(cached.body, {
        status: 200,
        headers: {
          ...cached.headers,
          "X-Cache": "HIT-Worker",
          "X-Request-ID": requestId,
          "Cache-Control": "no-store, no-cache, must-revalidate",
        }
      });
    }

    const url = new URL(request.url);
    const targetPath = !username || username === "User" ? `/sub/${subId}` : `/sub/${username}/${subId}`;
    const upstreamUrl = `${CONFIG.UPSTREAM_BASE}${targetPath}${url.search}`;

    let allConfigNames = [];

    try {
      const [upstreamRes, fixedConfigs] = await Promise.all([
        fetch(upstreamUrl, {
          headers: {
            "Host": CONFIG.UPSTREAM_HOST,
            "User-Agent": request.headers.get("User-Agent") || "v2rayNG/1.8.19",
            "X-Request-ID": requestId
          }
        }),
        SubManager.fetchFixedSubs(requestId, ctx) 
      ]);

      const rawUpstream = await upstreamRes.text();
      const decodedUpstream = this.decodeContent(rawUpstream);
      const valid = isValidSubscription(upstreamRes, decodedUpstream);

      // ⛔⛔⛔ SECURITY GATE ⛔⛔⛔
      if (!valid) {
         // اگر اشتراک معتبر نیست، پرتاب به catch
         throw new Error("Subscription Invalid");
      }

      // MERGE (Only if Valid)
      let finalConfigs = [];
      const rawLines = decodedUpstream.split(/\r?\n/).filter(line => line.trim().length > 0);
      finalConfigs.push(...rawLines);

      if (fixedConfigs && fixedConfigs.length > 0) finalConfigs.push(...fixedConfigs);

      const quantumExtras = CONFIG.EXTRA_CONFIGS.map(cfg =>
        cfg.includes("{{SPX}}") ? cfg.replace("{{SPX}}", generateQuantumSpx()) : cfg
      );
      finalConfigs.push(...quantumExtras);

      finalConfigs = [...new Set(finalConfigs)];

      const finalBody = this.encodeContent(finalConfigs);
      allConfigNames = this.extractRemarks(finalConfigs.join("\n"));

      const commonHeaders = {
        "Content-Type": "text/plain; charset=utf-8",
        "Subscription-Userinfo": upstreamRes.headers.get("Subscription-Userinfo") || "",
        "X-Processed-By": "Quantum-Pure-Engine",
        "Cache-Control": "no-store",
        "Pragma": "no-cache"
      };

      setCachedSub(subId, finalBody, commonHeaders);
      ctx.waitUntil(AuditService.logFetch(request.clone(), username, subId, env, allConfigNames));

      return new Response(finalBody, {
        status: 200,
        headers: { ...commonHeaders, "X-Cache": "MISS-Worker" }
      });

    } catch (err) {
      // --------------------------
      // STEP 8 — INTELLIGENT DECEPTION
      // --------------------------
      const ua = (request.headers.get("User-Agent") || "").toLowerCase();
      
      // تشخیص: آیا این یک مرورگر واقعی است یا یک اپلیکیشن VPN؟
      // اگر کلمات کلیدی VPN (مثل v2rayng) در یوزر ایجنت نباشد، فرض می‌کنیم مرورگر/ناظر است.
      const isVpnClient = CONFIG.CLIENT_KEYWORDS.some(k => ua.includes(k));

      if (!isVpnClient) {
        // 🎭 نمایش UI فریبنده برای مرورگرها و ناظران
        return new Response(DeceptiveUI.getHtml(), {
          status: 200, // استاتوس 200 برای عادی جلوه دادن سایت
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow" // ایندکس نشدن توسط گوگل
          }
        });
      }

      // اگر VPN Client بود، همان کانفیگ انقضا را می‌دهیم
      const fallbackBody = CONFIG.PERSIAN_EXPIRY_CONFIG ? [CONFIG.PERSIAN_EXPIRY_CONFIG] : [];
      return new Response(this.encodeContent(fallbackBody), {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "X-Fallback-Mode": "Access-Denied",
          "Cache-Control": "no-store"
        }
      });
    }
  },

  // ... (توابع کمکی بدون تغییر) ...
  extractRemarks(content) {
    return content.split(/\r?\n/)
      .map(line => {
        const parts = line.split('#');
        if (parts.length <= 1) return null;
        try { return decodeURIComponent(parts[1]).trim(); } 
        catch { return parts[1].trim(); }
      })
      .filter(Boolean);
  },

  decodeContent(raw) {
    if (!raw) return "";
    try {
      const trimmed = raw.trim();
      if (trimmed.includes("://") || trimmed.startsWith("ss://")) return trimmed;
      const cleanBase64 = trimmed.replace(/[\n\r\s]/g, '');
      const decoded = atob(cleanBase64);
      if (!decoded.includes("://") && !decoded.includes("path=") && decoded.length > 50) {
        try { return atob(decoded.trim()); } catch { return decoded; }
      }
      return decoded;
    } catch {
      return raw;
    }
  },

  encodeContent(configs) {
    const text = configs.join("\n").trim();
    try {
      return btoa(text);
    } catch {
      return btoa(unescape(encodeURIComponent(text)));
    }
  },

  checkExpiry(decoded, raw) { return false; }
};

// --- 5. PROXY ENGINE ---
const ProxyEngine = {
  async handle(request, username, subId) {
    const url = new URL(request.url);
    let targetPath = url.pathname;
    if (username && subId && !targetPath.startsWith("/sub/")) {
      targetPath = `/sub/${username}/${subId}`;
    }
    const upstreamUrl = `${CONFIG.UPSTREAM_BASE}${targetPath}${url.search}`;
    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set("Host", CONFIG.UPSTREAM_HOST);
    proxyHeaders.set("Origin", CONFIG.UPSTREAM_BASE);
    proxyHeaders.set("Referer", CONFIG.UPSTREAM_BASE);

    try {
      const response = await fetch(upstreamUrl, {
        method: request.method,
        headers: proxyHeaders,
        body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
        redirect: "follow"
      });
      const newHeaders = new Headers(response.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      newHeaders.delete("Content-Security-Policy");
      newHeaders.delete("X-Frame-Options");
      return new Response(response.body, { status: response.status, headers: newHeaders });
    } catch (e) {
      return new Response("Connection Refused", { status: 502 });
    }
  }
};

const ADMIN_CONFIG = {
  // لیست ID های عددی تلگرام ادمین‌ها (مثلاً: 12345678)
  ALLOWED_IDS: [ 5094837833, 5899343308 , 1211725271 ], 
};

const AuthService = {
  isAdmin(userId) {
    return ADMIN_CONFIG.ALLOWED_IDS.includes(userId);
  }
};
const TelegramService = {
  async sendMessage(env, chatId, content, replyToId = null) {
    const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: content.text,
        parse_mode: "HTML",
        reply_markup: content.keyboard || {},
        disable_web_page_preview: true,
        reply_to_message_id: replyToId
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Telegram API Error: ${error}`);
    }
    return response;
  }
};


const CommandDispatcher = {
  // این رجکس کلی است تا هر پیامی که شبیه لینک یا توکن باشد را بگیرد
  // پردازش اصلی داخل تابع execute انجام می‌شود
  commands: [
    {
      name: "SubscriptionLink",
      regex: /.*/, // دریافت همه متن‌ها برای بررسی دقیق‌تر در تابع
      async execute(match, message, env) {
        const text = message.text.trim();
        
        // اگر پیام دستور /start بود، نادیده بگیر
        if (text.startsWith("/start")) return null;

        let subId = "";
        let username = "Premium User";

        try {
          // 1. استخراج توکن (Token) از داخل متن
          if (text.startsWith("http")) {
            // اگر لینک کامل بود (مثل https://site.com/sub/TOKEN)
            const urlObj = new URL(text);
            const pathParts = urlObj.pathname.split('/').filter(Boolean);
            // آخرین قسمت آدرس، توکن است
            subId = pathParts[pathParts.length - 1];
          } else if (text.includes("/")) {
            // اگر لینک ناقص بود (مثل /sub/TOKEN)
            const parts = text.split('/').filter(Boolean);
            subId = parts[parts.length - 1];
          } else {
            // اگر فقط خود توکن بود
            subId = text;
          }

          // اگر توکن پیدا نشد یا خیلی کوتاه بود، یعنی پیام اشتباه است
          if (!subId || subId.length < 10) return null;

          // 2. تلاش برای استخراج نام کاربری از داخل توکن (Base64 Decoding)
          // توکن‌های جدید معمولاً Base64 هستند که داخلشان فرمت USER,UUID دارند
          try {
            // استانداردسازی Base64
            let base64 = subId.replace(/-/g, '+').replace(/_/g, '/');
            // اضافه کردن Padding در صورت نیاز
            while (base64.length % 4) base64 += '=';
            
            const decoded = atob(base64);

            // جستجوی الگوهای نام کاربری
            if (decoded.includes(',')) {
              // فرمت: username,uuid
              const parts = decoded.split(',');
              if (parts[0] && parts[0].length < 50) username = parts[0].trim();
            } else if (decoded.includes(':')) {
              // فرمت: username:uuid
              const parts = decoded.split(':');
              if (parts[0] && parts[0].length < 50) username = parts[0].trim();
            } else if (/^[a-zA-Z0-9._]+$/.test(decoded) && decoded.length < 30) {
              // اگر خود توکن، یک نام کاربری ساده بود
              username = decoded.trim();
            }
          } catch (e) {
            // اگر دیکود نشد، همان نام پیش‌فرض می‌ماند
            // Logger.warn("Token decode failed", { subId });
          }

        } catch (e) {
          return null;
        }

        const workerUrl = new URL(message.url).origin;
        const content = TelegramFormatter.prepareSubscriptionResponse(workerUrl, username, subId);
        return await TelegramService.sendMessage(env, message.chat.id, content, message.message_id);
      }
    }
  ],

  async findAndExecute(message, env, requestUrl) {
    for (const cmd of this.commands) {
      // فقط اگر پیام خالی نباشد اجرا می‌شود
      if (message.text && message.text.length > 5) {
        message.url = requestUrl; 
        // چون رجکس .* است، همیشه مچ می‌شود، اما داخل تابع فیلتر می‌کنیم
        const result = await cmd.execute(null, message, env);
        if (result) return result;
      }
    }
    return null;
  }
};

/**
 * مدیریت Webhook تلگرام با اطلاع‌رسانی عدم دسترسی
 */
/**
 * مدیریت Webhook تلگرام (نسخه Production)
 * پیاده‌سازی شده با استانداردهای امنیتی و قابلیت مشاهده‌‌پذیری بالا
 */
async function handleTelegramWebhook(request, env) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  
  // متا-دیتای پایه برای لاگ‌های ساختاریافته
  const logContext = { requestId, method: "webhook_process" };

  try {
    // 1. امنیت: تایید اصالت منبع درخواست (Webhook Secret Token)
    // پیشنهادی: مقدار TELEGRAM_SECRET را در کنسول Cloudflare تنظیم کنید
    if (env.TELEGRAM_SECRET) {
      const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
      if (secret !== env.TELEGRAM_SECRET) {
        Logger.warn("Security Breach: Invalid Webhook Secret Token", { ...logContext, ip: request.headers.get("CF-Connecting-IP") });
        return new Response("Unauthorized", { status: 403 });
      }
    }

    // 2. پارس کردن امن بدنه درخواست
    const payload = await request.json().catch(() => null);
    if (!payload) {
      Logger.warn("Invalid Payload: Empty or malformed JSON", logContext);
      return new Response("OK"); // بازگشت OK برای جلوگیری از Retry تلگرام
    }


    const message = payload.message || payload.edited_message;
    if (!message?.text || !message?.from?.id) {
      return new Response("OK");
    }

    const userId = message.from.id;
    const chatId = message.chat.id;
    const username = message.from.username || "unknown";

    // 3. کنترل دسترسی (Authorization)
    if (!AuthService.isAdmin(userId)) {
      Logger.warn("Unauthorized Access Attempt", { ...logContext, userId, username });

      const unauthorizedContent = TelegramFormatter.prepareUnauthorizedResponse();
      // جایگذاری ایمن دیتا در قالب
      const finalHtml = unauthorizedContent.text.replace("{user_id}", userId);
      
      await TelegramService.sendMessage(env, chatId, { ...unauthorizedContent, text: finalHtml }, message.message_id);
      return new Response("OK");
    }

    // 4. اجرای دستور با سیستم دیسپچر
    const result = await CommandDispatcher.findAndExecute(message, env, request.url);

    // 5. مانیتورینگ کارایی و موفقیت
    const duration = Date.now() - startTime;
    Logger.info("Webhook Processing Successful", { 
      ...logContext, 
      userId, 
      duration: `${duration}ms`,
      commandFound: !!result 
    });

  } catch (err) {
    // مدیریت خطاهای بحرانی بدون فاش کردن اطلاعات حساس در پاسخ
    Logger.error("Critical Webhook Failure", err, { 
      ...logContext,
      stack: err.stack 
    });
  } finally {
    // طبق استاندارد Telegram Bot API، باید همیشه 200 برگردانیم تا سیستم Retry غیرفعال شود
    return new Response("OK", {
      headers: { "X-Request-ID": requestId }
    });
  }
}
const isValidSubscription = (response, decodedContent) => {
  // 1. HTTP Status
  if (!response.ok) return false;

  // 2. محتوای خالی یا خیلی کوتاه
  if (!decodedContent || decodedContent.trim().length < 30) return false;

  // 3. بررسی اینکه واقعا کانفیگ داره
  if (!decodedContent.includes("://")) return false;

  // 4. بعضی پنل‌ها پیام خطا متنی می‌دن
  const lower = decodedContent.toLowerCase();
  if (
    lower.includes("not found") ||
    lower.includes("invalid") ||
    lower.includes("expired")
  ) return false;

  return true;
};
