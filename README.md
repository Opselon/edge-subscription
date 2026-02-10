# edge-subscription

Operator / Seller Subscription Manager (Cloudflare Worker + D1 + Telegram Bot UI)

## Overview
This service is a multi-tenant subscription manager for VPN sellers/operators. It provides:

- Snapshot-based subscription delivery for massive scale
- Multi-upstream subscription mixing + extras
- Dynamic upstream URL templates per panel token with normalization (`origin`, `/sub/`, `/sub/<TOKEN>`, `{{TOKEN}}`)
- Customer subscription links with per-link overrides
- **Open onboarding (no invite code required)** for Telegram bot and web login
- Secure API for automation with JWT or API keys
- SSRF guard + DoH domain verify + rate limiting + audit logs
- Telegram Bot UI wizard with glass-style Persian UX

## Architecture

**Core components**
- **Worker**: HTTP + Telegram webhook + API layer
- **D1**: multi-tenant data model (operators, upstreams, extras, links, rules, domains, keys, snapshots)
- **KV (optional)**: snapshot storage for `/sub` at scale (`SNAP_KV`)
- **Queues (optional)**: notification pipeline (`NOTIFY_QUEUE`)
- **Telegram Bot UI**: wizard for operator actions
- **Health/Doctor**: `/health`, `/api/v1/health/full`, and `scripts/doctor.js`

## Data Model (D1)
Key tables:
- `operators`
- `operator_settings`
- `operator_upstreams`
- `extra_configs`
- `subscription_rules`
- `customer_links`
- `customers`
- `subscription_links`
- `domains`
- `api_keys`
- `last_known_good`
- `snapshots`
- `audit_logs`
- `invite_codes` (kept for optional future admin workflows; not required)
- `app_state` (used for bot command sync timestamp)
- `rate_limits`
- `notify_jobs`

See `schema.sql` for full details.

## Authentication

### Telegram Login (web)
- `/` renders Telegram Login Widget.
- `/auth/telegram` validates Telegram login payload.
- Session tokens are signed with `SESSION_SECRET`.
- **No invite code is required.**
- Login sessions are stored in `localStorage` for the glassmorphism dashboard.

### API Auth
- `Authorization: Bearer <JWT>` (from `/auth/telegram`)
- `X-API-Key: <key>` (stored hashed)

## Operator Onboarding

### Open self-onboarding
- Any Telegram user who sends a message is auto-created as an `active` operator.
- Defaults are provisioned automatically:
  - `operator_settings`
  - `subscription_rules`
  - default `customer_link`

### Smart Paste
Send panel subscription URL/token directly in bot chat:
- Bot extracts panel token (+ best-effort username decode)
- Generates branded link:
  - verified domain: `https://OP_DOMAIN/sub/<PANEL_TOKEN>`
  - worker domain: `https://WORKER/sub/<OPERATOR_SHARE_TOKEN>/<PANEL_TOKEN>`
- Returns premium Persian message + one-click app buttons
- Triggers snapshot refresh in background for instant usability
- Upstream normalization:

- `/set_upstream https://host:port/sub/` => `https://host:port/sub/{{TOKEN}}`
- `/set_upstream https://host:port/sub/<TOKEN>` => stores template + sample token test
- `/set_upstream https://host:port` => `https://host:port/sub/{{TOKEN}}`
- After save, status is `testing` (with sample token) or `pending_test` (without sample).

Customer links:
- Verified domain customer links: `https://<domain>/sub/<customer_public_token>`
- Worker customer links: `https://<worker>/sub/<shareToken>/u/<customer_public_token>`
- `/sub/<token>` on verified domain first checks customer token, then legacy panel token.

Subscription links:
- Add operator-level sources with `/add_sub_link`
- Add customer-level source during `/add_customer` wizard by sending a full URL
- Merge order: upstream + subscription links + extras (default)

## Telegram Commands

- `/panel` - پنل اپراتور
- `/help` - راهنمای کامل
- `/set_upstream` - تنظیم آپ‌استریم
- `/set_domain` - تنظیم دامنه
- `/verify_domain` - بررسی تایید دامنه
- `/set_channel` - تنظیم کانال اعلان‌ها
- `/link` - ساخت لینک مشتری / مشاهده prefix
- `/extras` - مدیریت افزودنی‌ها
- `/add_extra` - افزودن کانفیگ
- `/rules` - قوانین خروجی
- `/set_rules` - تنظیم قوانین
- `/rotate` - ساخت لینک جدید اپراتور/مشتری
- `/logs` - لاگ‌های اخیر
- `/customers` - لیست مشتری‌ها
- `/add_customer` - افزودن مشتری
- `/customer` - جزئیات مشتری
- `/del_customer` - حذف نرم مشتری
- `/toggle_customer` - فعال/غیرفعال مشتری
- `/add_sub_link` - افزودن لینک اشتراک
- `/subs` - لیست لینک‌های اشتراک
- `/del_sub_link` - حذف لینک اشتراک
- `/toggle_sub_link` - فعال/غیرفعال لینک اشتراک
- `/cancel` - لغو عملیات در جریان
- `/admin_sync_commands` - آپلود مجدد دستورات ربات (admin)

## Bot command sync (`setMyCommands`)
- Worker syncs commands via Telegram `setMyCommands` and stores timestamp in `app_state.commands_synced_at`.
- Sync is performed only if older than 7 days.
- Force sync immediately with admin command:
  - `/admin_sync_commands`

## Security & Operations Notes
- SSRF guard: HTTPS only, private IP blocks, allow/deny list
- Rate limits: per IP, per user, per token
- Output limits: line/size controls and sanitization
- Domain verification via Cloudflare DoH TXT lookup
- Snapshot + LKG fallback architecture preserved
- Encrypted upstream URLs at rest (`ENCRYPTION_KEY` or `SESSION_SECRET`)
- Audit logging retained for operator/admin actions
- Optional channel notifications with queue/backoff

## Development

Install dependencies:
```bash
npm install
```

Run tests:
```bash
npm test
```

## E2E checklist
1) Fresh Telegram user sends `hi` → operator auto-created active + bot hint (`/panel` or `/help`).
2) Fresh user sends panel URL → premium smart-paste response + branded link.
3) `/panel` shows upstream status (`unset` then `ok/invalid/error`) and snapshot state.
4) `/help` works directly and via panel button.
5) `setMyCommands` sync is persisted and `/admin_sync_commands` forces refresh.
