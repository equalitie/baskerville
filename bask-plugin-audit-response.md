# Baskerville — Audit Response (1.0.6)

Response to the EQPress code review in `bask-plugin-eqpress-issues.md`.
Each item references the original issue number.

---

## Fixed in 1.0.6

### Issue 2 — Block pages get cached and served to real users
`send_403_and_exit()` and `send_403_geo_and_exit()` now send `X-Accel-Expires: 0`, which nginx
honors regardless of `fastcgi_ignore_headers`. The honeypot 403 path was fixed the same way.
The challenge redirect already had this header; now all exit paths do.

### Issue 3a — Challenge URL bypass skips firewall
The substring match on `REQUEST_URI` was replaced with exact `$_GET` key presence checks
(`isset($_GET['baskerville_challenge'])`). A request like `GET /?foo=baskerville_verify` no longer
bypasses the firewall.

### Issue 3b — `is_api_request()` matches query string
`is_api_request()` now strips the query string before path matching. `GET /?utm_source=/v1/` is
no longer treated as an API request.

### Issue 6 — 15 synchronous outbound HTTPS calls on the request path
AI bot IP ranges are now fetched exclusively via WP-Cron (hourly), never on the request path.
A thundering-herd lock prevents concurrent refreshes. The file cache is pre-populated on
plugin activation. `verify_crawler_ip()` rDNS calls remain synchronous (they are only triggered
for UAs that claim to be Googlebot/Bingbot/Applebot/DuckDuckBot).

### Issue 7 — Systematic +15 score penalty on all traffic behind a reverse proxy
The HTTP/1.x score penalty is now skipped when the request arrives through a reverse proxy
(`HTTP_X_FORWARDED_FOR` present). Deflect and nginx edge→origin hops are HTTP/1.1 by design;
the penalty was never meaningful there.

### Issue 8 — Honeypot 24-hour-bans verified Googlebot
`handle_honeypot_visit()` now calls `verify_crawler_ip()` before issuing a ban. Verified bots
(Googlebot, Bingbot, Applebot, DuckDuckBot with matching rDNS and IP range) are not banned.

### Issue 9 — Unauthenticated AJAX endpoints leak visitor data
`ajax_get_live_feed` and `ajax_get_live_stats` now require `manage_options` capability and a
valid nonce. Both queries are bounded by a time window (no more unbounded full-table aggregations).
The JS poll interval was increased from 10s to 60s.

### Issue 13 — X-Country-Code and CF-IPCountry trusted from client
Both headers are no longer trusted by default. `CF-IPCountry` is now an explicit opt-in setting
in Country Control (disabled by default). `X-Country-Code` is no longer read at all.
CDN auto-detection on activation sets the correct trust flags automatically.

### Issue 13 — Remote-controlled blocking is a default-on hidden behaviour
Cloud action enforcement (country/UA blocks pushed from the Baskerville API) is now an explicit
opt-in setting, visible and configurable in Settings. Default: on (preserves existing behaviour),
but the operator can see and disable it.

### Issue 13 — jQuery forced on the frontend for a no-op
jQuery dependency removed from the frontend fingerprinting script.

---

## Partially addressed

### Issue 1 — `fastcgi_ignore_headers Set-Cookie` shares cookies across visitors
The `Set-Cookie`/cache interaction is an nginx configuration issue that cannot be fully fixed
from within the plugin. What we did:
- `X-Accel-Expires: 0` on all 403 and challenge responses prevents those from being cached.
- `baskerville_pass` (the challenge pass cookie) is excluded from cached responses by design —
  it is only set after a challenge, which always bypasses cache.
- `baskerville_id` and `baskerville_visit_key` are still set on ordinary cacheable pages.
  The recommended fix remains on the nginx side: add
  `baskerville_id|baskerville_visit_key` to the `$do_not_set_cache` cookie regex in
  `common_fastcgi.conf`, or use `fastcgi_cache_bypass $cookie_baskerville_id`.

### Issue 4 — No APCu → flat-file cache
`fc_set / fc_get / fc_inc_in_window / fc_delete` now go through `wp_cache_*` when a persistent
object cache is active (`wp_using_ext_object_cache()` returns true). On boxes with Redis or
Memcached as the WP object cache backend, the flat-file inode problem disappears.
Without a persistent cache the plugin still falls back to files — the behaviour is unchanged.
See `eqpress-sysadmin-tasks.md` §2 for the Redis setup instructions.

### Issue 12 — Cron and DB load on shared box
- Snapshot aggregation is now skipped when there is no traffic in the current 5-minute window
  (saves the 6 aggregate queries on quiet sites/windows).
- Stats cleanup uses batched `DELETE` (1000 rows per batch) instead of a single unbounded query.
- Redundant indexes (`asn`, `score`, `block_reason`, `top_factor`) are now dropped automatically
  via `maybe_upgrade_schema()` — reduces write overhead on the table.
- `baskerville_process_log_files` (every-minute cron) and `baskerville_cloud_analyze`
  (every-5-min) remain. These are needed for correctness; per-site cost is low when the
  snapshot guard (above) is active and log-mode is set to `database`.

---

## Not addressed (known, accepted, or out of scope)

### Issue 1 — Cookie identity model broken by nginx fastcgi cache (nginx side)
Full fix requires nginx config change per-vhost. Documented in `eqpress-sysadmin-tasks.md`.

### Issue 5 — GeoIP databases are large PHP source files loaded with `include`
The `var_export()` + `include` approach is a known limitation. The ASN database is only loaded
when ASN lookup is needed (lazy load). Opcache impact depends on the specific server's
`opcache.memory_consumption`. Measure before deploying to a shared box.

### Issue 10 — Cache files publicly readable over HTTP
One-line nginx fix. Documented in `eqpress-sysadmin-tasks.md` §1 — this is intentionally an
nginx task, not a plugin task (the plugin cannot control nginx `location` blocks).

### Issue 11 — Detection coverage vs. nginx fastcgi cache
Inherent to the architecture. A disclaimer is now shown in the Live Traffic Feed: counts reflect
PHP-reached requests only and undercount by the cache hit ratio. No code fix possible.

### Issue 13 — No `uninstall.php`
Intentional. Destroying 14 days of attack history and blocked IP data on plugin deletion is
worse than leaving it behind. Manual cleanup SQL is documented in `eqpress-sysadmin-tasks.md`.

### Issue 13 — No multisite awareness
Out of scope for 1.0.x.

### Issue 13 — Altcha loaded on every singular post with comments open
Performance tradeoff. Altcha is 67 KB but is needed before the user scrolls to comments.
Deferred loading risks a layout shift. Accepted for now.

### Issue 13 — Missing Deflect edge IP → self-DoS
Cannot be fixed from within the plugin. Documented in `eqpress-sysadmin-tasks.md` Known Risks.

---

## Deployment checklist (from Bottom Line)

Status of the five pre-deployment items listed in the audit:

| # | Item | Status |
|---|------|--------|
| 1 | `X-Accel-Expires: 0` on all 403/cookie responses | ✅ Done in 1.0.6 |
| 2 | Fix two substring firewall bypasses | ✅ Done in 1.0.6 |
| 3 | `manage_options` + nonce + time-bound on AJAX endpoints | ✅ Done in 1.0.6 |
| 4 | Deny `wp-content/cache/baskerville/` in nginx; measure GeoIP opcache impact | ⚙️ Nginx task — see sysadmin-tasks.md §1 |
| 5 | Back `fc_*` with Redis/Memcached, or accept flat-file growth | ⚙️ Optional — plugin uses WP object cache automatically if configured |
