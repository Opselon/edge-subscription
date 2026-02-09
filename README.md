# edge-subscription

Operator / Seller Subscription Manager (Cloudflare Worker + D1 + Telegram Bot UI)

## Overview
This service is a multi-tenant subscription manager for VPN sellers/operators. It provides:

- Snapshot-based subscription delivery for massive scale
- Multi-upstream subscription mixing + extras
- Dynamic upstream URL templates per panel token (template/base/full modes)
- Customer subscription links with per-link overrides
- Telegram login + invite approval flow
- Secure API for automation with JWT or API keys
- SSRF guard + rate limiting + audit logs
- Telegram Bot UI wizard with glass-style buttons

## Architecture

**Core components**
- **Worker**: HTTP + Telegram webhook + API layer
- **D1**: multi-tenant data model (operators, upstreams, extras, links, rules, domains, keys, snapshots)
- **KV (optional)**: snapshot storage for `/sub` at scale (`SNAP_KV`)
- **Queues (optional)**: notification pipeline (`NOTIFY_QUEUE`)
- **Telegram Bot UI**: wizard for operator actions
- **Health/Doctor**: `/health`, `/api/v1/health/full`, and `scripts/doctor.js`

### Snapshot-based `/sub` architecture
- `/sub/:panel_token` (on verified custom domain) or `/sub/:operator_token/:panel_token` (on worker domain) serves a precomputed snapshot (KV/Cache/D1) whenever possible.
- If the snapshot is missing or stale, the Worker returns the last-known-good response immediately and refreshes in the background.
- If no snapshot or last-known-good exists, the Worker performs one synchronous assemble (strict timeout) and stores the snapshot so the first hit succeeds.
- Snapshot refresh performs all upstream fetch and rule processing, then stores:
  - `body_value`, `body_format` (`plain` or `base64`)
  - headers JSON
  - `updated_at` + `ttl_sec`
  - last-known-good fallback

### Upstream URL modes
Upstreams support dynamic token substitution via `operator_upstreams.format_hint`:
- `template`: URL contains `{{TOKEN}}` and is replaced with the panel token (e.g. `https://host/sub/{{TOKEN}}`).
- `base`: URL is treated as a base and expanded to `/sub/{panel_token}`.
- `full`: URL is used as-is (fixed token).

### URL-safe base64 upstreams
Upstream responses that are URL-safe base64 (`-`/`_`, missing padding) are detected, normalized, decoded, and merged when the decoded payload contains `://`.

## Data Model (D1)
Key tables:
- `operators`
- `operator_settings`
- `operator_upstreams`
- `extra_configs`
- `subscription_rules`
- `customer_links`
- `domains`
- `api_keys`
- `last_known_good`
- `snapshots`
- `audit_logs`
- `invite_codes`
- `rate_limits`
- `notify_jobs` (when Queue is not configured)

See `schema.sql` for full details.

## Authentication

### Telegram Login (web)
- `/` renders Telegram Login Widget.
- `/auth/telegram` validates Telegram login payload.
- Session tokens are signed with `SESSION_SECRET`.
- Invite codes can be supplied on login for non-admins.
- Login sessions are stored in `localStorage` for the glassmorphism dashboard.

### API Auth
- `Authorization: Bearer <JWT>` (from `/auth/telegram`)
- `X-API-Key: <key>` (stored hashed)

## REST API (sample)

### Upstreams
- `POST /api/v1/operators/me/upstreams`
- `GET /api/v1/operators/me/upstreams`

### Extras
- `POST /api/v1/operators/me/extras`

### Customer Links
- `POST /api/v1/operators/me/customer-links`
- `GET /api/v1/operators/me/customer-links`
- `POST /api/v1/operators/me/customer-links/{id}/rotate`

### Operator Status
- `GET /api/v1/operators/me/status`

### Rules
- `PATCH /api/v1/operators/me/rules`

### Health
- `GET /api/v1/health/full`

### Admin
- `POST /api/v1/admin/invite-codes`
- `POST /api/v1/admin/operators/{id}/approve`
- `POST /admin/purge?days=30` (purge old audit logs + rate limits)

## Merge Policies
Supported policies in `subscription_rules.merge_policy`:

- `append`
- `round_robin`
- `weighted`
- `failover`
- `upstream_only`
- `extras_only`
- `replace`

## Operator UX
- **Telegram bot panel (Persian)** shows:
  - Domain verification status
  - Upstream status and last update time
  - Snapshot freshness
  - Buttons for Upstreams, Customer Links, Extras, Rules, Domain Verify, Notifications
- **Web dashboard** (after Telegram login):
  - Stores the session token in `localStorage`
  - Lists customer links with copy + rotate actions
  - Shows last upstream status and domain verification

## Security Highlights
- SSRF guard: HTTPS only, private IP blocks, allow/deny list
- Response size and line size limits
- Rate limiting: per IP, per token, per operator
- Redacted logging
- API keys stored hashed
- Encrypted upstream URLs at rest (`ENCRYPTION_KEY` or `SESSION_SECRET`)
- CSP + security headers on HTML pages

## Operations

### Doctor
```
npm run doctor
```

### Health
```
GET /health
GET /api/v1/health/full
```

### Retention + purge
- Scheduled handler purges audit logs and rate limit rows older than 30 days.
- Manual purge endpoint: `POST /admin/purge?days=30`

### Notifications
- Default: `notify_fetches = 0` (only errors by default).
- When enabled, notifications are queued and throttled using `notifyFetchIntervalMs`.

## Environment Variables

Required:
- `TELEGRAM_TOKEN`
- `ADMIN_IDS`
- `SESSION_SECRET`

Optional:
- `TELEGRAM_SECRET`
- `TELEGRAM_BOT_USERNAME`
- `LOG_CHANNEL_ID`
- `BASE_URL`
- `NATIONAL_BASE_URL` (optional secondary base for “Meli/National” links)
- `SNAP_KV` (KV namespace for snapshots at scale)
- `NOTIFY_QUEUE` (Queue binding for Telegram notifications)
- `ENCRYPTION_KEY` (optional override key for upstream URL encryption)

## Development

Install dependencies:
```
npm install
```

Run tests:
```
npm test
```

## E2E Test Plan

### Telegram smart paste
- Operator pastes a panel subscription URL → bot replies with premium Persian message, branded link, and one-click buttons (no “unknown command”).
- When no upstream is configured → upstream status shows `unset` in `/panel` and `/link`.
- Pasted panel links auto-create a template upstream and trigger a snapshot refresh.

### First-hit subscription
- When a branded `/sub/<operator>/<panel>` link is opened without any snapshot/LKG, the Worker assembles synchronously (strict timeout) and returns merged upstream + extras immediately.

### Upstream encoding
- URL-safe base64 upstreams decode into valid subscription lines and avoid `upstream_invalid` on first fetch.

### Link routing
- Verified domain present → subscription link uses `/sub/<PANEL_TOKEN>`.
- No verified domain → subscription link uses `/sub/<OPERATOR_TOKEN>/<PANEL_TOKEN>`.
