# edge-subscription

Operator / Seller Subscription Manager (Cloudflare Worker + D1 + Telegram Bot UI)

## Overview
This service is a multi-tenant subscription manager for VPN sellers/operators. It provides:

- Snapshot-based subscription delivery for massive scale
- Multi-upstream subscription mixing + extras
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
- `/sub/:token` serves a precomputed snapshot (KV/Cache/D1) whenever possible.
- If the snapshot is missing or stale, the Worker returns the last-known-good response immediately and refreshes in the background.
- Snapshot refresh performs all upstream fetch and rule processing, then stores:
  - `body_value`, `body_format` (`plain` or `base64`)
  - headers JSON
  - `updated_at` + `ttl_sec`
  - last-known-good fallback

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
