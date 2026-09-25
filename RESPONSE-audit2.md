# Response to Second Security Audit

Thank you for the thorough second review. Below is our point-by-point response to every
concern raised, including what was fixed, what was accepted as-is, and two new features
planned in response to the broader architectural feedback.

---

## Blockers — all three fixed

### 1. `X-Accel-Expires: 0` killing the page cache

**Your finding:** `log_page_visit()` in `class-baskerville-stats.php:466` unconditionally
emitted `X-Accel-Expires: 0` on every HTML page view, draining the nginx fastcgi_cache
within five hours of activation.

**Fix:** Removed `header('X-Accel-Expires: 0')` from `log_page_visit()` entirely.
The header remains in place only where it is needed: 403 responses (firewall, honeypot)
and `ensure_baskerville_cookie()` — but only when `!$this->had_cookie_on_arrival`, meaning
the response was already a cache miss.

---

### 2. Honeypot banning Googlebot

**Your finding:** `verify_crawler_ip()` was gated on `is_ai_bot_user_agent()`. Since
`googlebot` is not in the AI bot UA list, Googlebot was never verified and always banned.

**Fix:** Moved `verify_crawler_ip()` outside the `$is_ai_bot` gate. It now runs
unconditionally for every honeypot visit. The ban is skipped when both `$vc['claimed']`
and `$vc['verified']` are true — requiring both rDNS claim and confirmation, not just one.

---

### 3. `/baskerville-challenge` path bypass

**Your finding:** `strpos($request_path, '/baskerville-challenge')` matched any path
containing that substring — unthrottled, polluting the cache with 404s.

**Fix:** Replaced with anchored `preg_match('~^/baskerville-(challenge|verify|altcha-challenge)/?$~', $request_path)` matching only the exact registered rewrite rules.

---

## Other concerns — status

### `ensure_baskerville_cookie()` `X-Accel-Expires: 0`

Conditional on `!$this->had_cookie_on_arrival`. New visitors are cache misses by definition
(no cookie → nginx bypass), so the header only fires on responses nginx would not have
cached anyway. Correct behavior, no change needed.

### `baskerville_visit_key` cookie on cacheable pages

`setcookie()` fires without `X-Accel-Expires: 0`. With EQPress `fastcgi_ignore_headers
Set-Cookie`, nginx caches the response regardless and strips the Set-Cookie header for
cached viewers. Not a cache killer. The cookie is a 5-minute visit correlation token —
not auth, not security-critical. Accepted as-is.

### `is_api_request()` path substring — Issue 3b

`strpos()` still used at `core.php:504` for `/v1/`, `/api/` etc. You acknowledged this
is covered by the 100/60s rate limiter and "much less severe." Accepted as partial — will
anchor these in a future cleanup.

### Stats table growth cap

Removed the `for ($i = 0; $i < 20; $i++)` hard cap (20,000 rows/day max). Replaced with
`while (true)` loop that runs until the retention window is clear.

### Object cache — Issue 4

Confirmed: no Redis and no APCu on EQPress. The `fc_*` abstraction is correct code that
will pay off if a drop-in is ever added. For now, all calls fall to the file branch —
behavior identical to 1.0.5. Acknowledged as fully open on EQPress.

### Duplicate condition in firewall

`strpos($reason, 'nojs-burst')` appeared twice — second branch was unreachable. Fixed:
second instance changed to `strpos($reason, 'nonbrowser-ua-burst')`.

### Deflect trust flag "only read, not written"

Your concern that `trust_deflect_country` is only read but not written appears to be
incorrect. The installer writes it at `class-baskerville-installer.php:224-225` inside
`maybe_autodetect_cdn()` which runs on activation.

### New issues you identified in 1.0.6

| Issue | Status |
|-------|--------|
| Stats table unbounded growth | Fixed — while(true) loop |
| Deflect GeoIP fast-path opt-in off by default | Installer writes flag on activation — working as intended |
| Nine cron events | Informational, accepted |
| Inline fingerprint script grew to 15,762 bytes | Accepted — jQuery removal is a net win |

---

## Two new features in response to architectural feedback

### 1. AI Bot Control redesign (SPEC-disallow-ai-training.md)

Your feedback highlighted that the current 4-mode system (allow_all / block_all / whitelist
/ blacklist) is abstract. Replacing it with per-company toggles grouped by three categories
matching Cloudflare's September 2026 model:

- **AI Training** — bots that scrape content for model development (GPTBot, ClaudeBot, etc.)
- **AI Search** — bots that answer user questions (OAI-SearchBot, PerplexityBot, etc.)
- **AI Assistant** — real-time agents acting on behalf of a user (ChatGPT-User, Claude-User, etc.)

Verified companies (OpenAI, Anthropic, Meta, Google AI) show a "verified ✓" badge — IP
confirmed via rDNS or published IP ranges before blocking. Unverified companies are grouped
under a single "Unknown AI Bots" toggle. Search bots (Googlebot, Bingbot, Applebot) are
always allowed and not shown in the blocking UI.

### 2. DDoS Protection mode switch (SPEC-ddos-protection-mode.md)

Directly addresses the EQPress deployment concern about duplicate blocking functionality
with Banjax/Deflect.

Replaces the current "Master Protection" toggle with two separate switches:

**Bot & Access Control** (identity-based, always available):
AI Bot Control, GeoIP blocking, Honeypot, Fingerprint collection and scoring.

**DDoS Protection** (pattern-based, switchable):
Burst rate limiting, session score → challenge enforcement, CAPTCHA, Under Attack mode.

When Deflect is detected (`X-Deflect-Country-Code` header present on activation),
DDoS Protection is automatically disabled and the admin is notified. Baskerville continues
to fingerprint and classify all traffic in **shadow mode** — high-score requests are logged
as "would challenge" / "would block" in Live Feed and Stats, giving operators full visibility
without active blocking.

---

## Summary

| # | Issue | Status |
|---|-------|--------|
| Blocker 1 | `X-Accel-Expires: 0` cache regression | ✅ Fixed |
| Blocker 2 | Honeypot banning Googlebot | ✅ Fixed |
| Blocker 3 | `/baskerville-challenge` path bypass | ✅ Fixed |
| Partial 3b | `is_api_request()` path substring | ⚠️ Accepted — rate-limited |
| Issue 4 | Object cache inert without Redis | ⚠️ Open — no Redis on EQPress |
| New | Stats table growth cap | ✅ Fixed |
| New | Duplicate firewall condition | ✅ Fixed |
| Architectural | 4-mode AI bot system too abstract | 🔧 Redesign planned (1.0.7) |
| Architectural | Duplicate DDoS blocking with Banjax | 🔧 DDoS mode switch planned (1.0.7) |
