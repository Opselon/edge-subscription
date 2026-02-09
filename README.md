# edge-subscription

Operator / Seller Subscription Manager (Cloudflare Worker + D1 + Telegram Bot UI)

## Overview
This service is a multi-tenant subscription manager for VPN sellers/operators. It provides:

- Multi-upstream subscription mixing + extras
- Customer subscription links with per-link overrides
- Telegram login + invite approval flow
- Secure API for automation with JWT or API keys
- SSRF guard + rate limiting + audit logs
- Telegram Bot UI wizard with glass-style buttons

## Architecture

**Core components**
- **Worker**: HTTP + Telegram webhook + API layer
- **D1**: multi-tenant data model (operators, upstreams, extras, links, rules, domains, keys)
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
- `domains`
- `api_keys`
- `audit_logs`
- `invite_codes`

See `schema.sql` for full details.

## Authentication

### Telegram Login (web)
- `/` renders Telegram Login Widget.
- `/auth/telegram` validates Telegram login payload.
- Session tokens are signed with `SESSION_SECRET`.
- Invite codes can be supplied on login for non-admins.

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

### Rules
- `PATCH /api/v1/operators/me/rules`

### Health
- `GET /api/v1/health/full`

### Admin
- `POST /api/v1/admin/invite-codes`
- `POST /api/v1/admin/operators/{id}/approve`

## Merge Policies
Supported policies in `subscription_rules.merge_policy`:

- `append`
- `round_robin`
- `weighted`
- `failover`
- `upstream_only`
- `extras_only`
- `replace`

## Security Highlights
- SSRF guard: HTTPS only, private IP blocks, allow/deny list
- Response size and line size limits
- Rate limiting: per IP, per token, per operator
- Redacted logging
- API keys stored hashed

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

## Development

Install dependencies:
```
npm install
```

Run tests:
```
npm test
```

