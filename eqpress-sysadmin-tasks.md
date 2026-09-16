# Baskerville — EQPress sysadmin tasks

Server-side changes required before enabling Baskerville on production vhosts.
These cannot be done from within the WordPress plugin.

---

## 1. Block direct HTTP access to the file cache

Baskerville's file-cache entries (`ban:<ip>`, `rdns:<ip>`, `turnstile_pass:<ip>`, etc.) are
stored as `wp-content/cache/baskerville/<sha1>.cache`. The filenames are deterministic — anyone
can compute the SHA-1 and probe whether a given IP is banned, has a valid challenge pass, etc.
They also don't match any existing `deny all` rule in `common_location.conf`.

**Add to `common_location.conf` (or per-vhost server block):**

```nginx
location ~* /wp-content/cache/baskerville/ {
    deny all;
}
```

Place it before the catch-all `location /` block.

---

## 2. Scrub spoofable GeoIP headers at the nginx edge

`X-Country-Code` can be forged by any client (`curl -H 'X-Country-Code: US'`). Strip it at the
edge as defence-in-depth so it never reaches PHP.

`CF-IPCountry` is trustworthy **only when this site is behind Cloudflare** (orange-cloud).
Cloudflare strips any client-supplied copy of this header before injecting its own. Without
Cloudflare upstream, a client can freely forge it.

**For EQPress sites (behind Deflect, not behind Cloudflare):**

Add to `common_fastcgi.conf` or the per-vhost fastcgi location:

```nginx
# Prevent clients from spoofing GeoIP headers.
fastcgi_param HTTP_X_COUNTRY_CODE  "";
fastcgi_param HTTP_CF_IPCOUNTRY    "";
```

Then enable **Settings > Country Control > Trust X-Deflect-Country-Code header** in the plugin.
Deflect injects this header at the edge; with the scrub above in place, only the Deflect-injected
value can reach PHP.

**For EQPress sites that are ALSO behind Cloudflare (Cloudflare → EQPress nginx → PHP):**

Cloudflare injects `CF-IPCountry` and `CF-Connecting-IP` before the request reaches nginx. Since
Cloudflare is a trusted upstream (its IP ranges are in `set_real_ip.conf`), these headers arrive
at nginx already authenticated — do NOT scrub them. Do NOT add `fastcgi_param HTTP_CF_IPCOUNTRY ""`
for these vhosts.

- Enable **Settings > Country Control > Trust CF-IPCountry header** in the plugin.
- Baskerville's CDN auto-detection (runs on plugin activation) sets this automatically.
- Ensure Cloudflare IP ranges are in `set_real_ip.conf` so nginx unwraps `X-Forwarded-For`
  correctly (otherwise the real visitor IP is not available to PHP).

**For sites that ARE behind Cloudflare (orange-cloud, no nginx in front):**

- Do NOT scrub `HTTP_CF_IPCOUNTRY` (Cloudflare delivers directly to origin — there is no nginx).
- Enable **Settings > Country Control > Trust CF-IPCountry header** in the plugin.
- Cloudflare strips any client-supplied copies before injecting its own value.

**For standalone sites (no CDN):**

Scrub both headers and enable neither setting. Use the MaxMind or Deflect GeoIP database instead.

```nginx
fastcgi_param HTTP_X_COUNTRY_CODE       "";
fastcgi_param HTTP_CF_IPCOUNTRY         "";
fastcgi_param HTTP_X_DEFLECT_COUNTRY_CODE "";
```

The plugin trusts `GEOIP2_COUNTRY_CODE` / `GEOIP_COUNTRY_CODE` unconditionally — these are
nginx fastcgi_params injected server-side, never forwarded from the client.

---

## 3. Enable Redis as the WordPress object cache backend

Without a persistent object cache Baskerville falls back to flat files for every counter, ban
entry, GeoIP result, and rDNS result — roughly 10–14 file reads/writes per uncached page view.
On a large crawl (100k+ unique IPs) this creates hundreds of thousands of files in one directory,
which affects inode quotas for all tenants on the box and makes the daily glob-based cleanup
a significant IO event.

Redis is already installed on the box. The change is:

1. **Install a Redis object-cache drop-in** for WordPress. Options:
   - [redis-cache](https://wordpress.org/plugins/redis-cache/) plugin (activates `object-cache.php` drop-in automatically)
   - Or drop `object-cache.php` manually into `wp-content/` pointing at the local Redis socket/port.

2. **Configure `WP_REDIS_HOST` / `WP_REDIS_PORT`** (or `WP_REDIS_PATH` for a Unix socket) in
   `wp-config.php` or via the plugin's settings.

3. **Verify** the drop-in is active — `wp_using_ext_object_cache()` must return `true`. Baskerville
   checks this at runtime and switches `fc_set / fc_get / fc_inc_in_window / fc_delete` from file
   operations to `wp_cache_*` calls automatically.

Once Redis is active, the `wp-content/cache/baskerville/` directory is no longer used for runtime
data (it may still be used for the GeoIP database files). The cron-based file cleanup becomes a
no-op.

---

## 4. Trim redundant indexes on wp_baskerville_stats (per site, low-traffic window)

`wp_baskerville_stats` has 11 single-column indexes on a write-heavy table. Four of them are
never the leading column in any actual query — they add write overhead on every INSERT/UPDATE
without helping any read path.

Run during a low-traffic window (InnoDB rebuilds the table in place):

```sql
ALTER TABLE wp_baskerville_stats
  DROP INDEX asn,
  DROP INDEX score,
  DROP INDEX block_reason,
  DROP INDEX top_factor;
```

**Why these four:**
- `asn` — GROUP BY aggregations always filter by `timestamp_utc` first; MySQL uses the time index
- `score` — no query does a range scan on score as the primary filter
- `block_reason` — mostly NULL (low selectivity), used only as an OR condition in the live feed
- `top_factor` — nullable, always accessed via time-bounded GROUP BY

The remaining indexes (`ip`, `timestamp_utc`, `classification`, `event_type`, `baskerville_id`,
`visit_key`, `fingerprint_hash`, `country_code`) all serve active query patterns and should stay.

Note: on MySQL 5.7 this locks the table briefly. On MySQL 8.0+ it is online (`ALGORITHM=INPLACE`).
Check the table size first:

```sql
SELECT table_rows, ROUND(data_length/1024/1024,1) AS data_mb,
       ROUND(index_length/1024/1024,1) AS index_mb
FROM information_schema.tables
WHERE table_name = 'wp_baskerville_stats';
```

---

## Known risks (no code fix possible — operational awareness)

### Deflect edge IP lag → instant self-DoS

`set_real_ip.conf` is a static list of Deflect edge IPs. When Deflect adds a new edge that is
not yet in this list, nginx doesn't recognise it as a trusted proxy and does not unwrap
`X-Forwarded-For`. Every user behind that edge appears to Baskerville as the same IP — the edge
itself. The `no-cookie-burst` threshold (10 requests / 60 s) fires within seconds and bans the
edge IP for 10 minutes, serving 403 to everyone behind it.

**There is no way to detect or prevent this from within the PHP plugin.**

Mitigation options (discuss with Deflect):
1. **Keep `set_real_ip.conf` updated** — primary fix. Automate if Deflect publishes a machine-readable edge IP list.
2. **Add all Deflect edge IPs to `baskerville_ip_whitelist`** — safety net. If the edge IP is whitelisted the burst ban never fires. Downside: while that edge is missing from `set_real_ip.conf`, all users behind it are also effectively whitelisted (they all look like one IP), so bot protection is blind for that edge until nginx config is updated.
3. Confirm whether `common_cdn_realip.conf` being empty is intentional — the comment in the file says "No cdn_real_ips list defined", which suggests it was meant to carry additional trusted proxy ranges.

### nginx fastcgi_cache — the plugin only sees a fraction of traffic

This is an inherent consequence of running a PHP plugin behind a full-page nginx cache. It is not
a bug and cannot be fixed in PHP. Operators should be aware:

- **`no-cookie-burst` and `no-js` counters** only count cache misses. A bot crawling cached article
  pages accumulates no score and triggers no burst ban. The counters are only meaningful for
  query-string requests, POSTs, and the first hit on each URL every 5 hours.

- **Live Traffic Feed and all statistics** undercount by the cache hit ratio. On a well-cached
  site (80–90% hit ratio) the dashboard shows 10–20% of actual traffic. The data is still useful
  for triage — blocked IPs, suspicious patterns — but the absolute numbers are not representative.

- **Under Attack Mode** challenges visitors whose requests reach PHP. Visitors served from cache
  receive no challenge. UAM is still effective against the requests that actually load the origin
  (query strings, POSTs, uncached URLs) — which are exactly the requests that create load. A pure
  cache hit costs the origin nothing, so there is no load to protect against.

In summary: the cache is doing its job. The plugin protects the origin from the traffic that
reaches it. This is the correct division of labour on this stack.

### Plugin deletion leaves data behind — intentionally

Baskerville has no `uninstall.php`. Deleting the plugin leaves behind:
- `wp_baskerville_stats` and four cloud tables (`snapshots`, `daily`, `incidents`, `reports`)
- ~25 `wp_options` entries
- GeoIP database files in `wp-content/uploads/baskerville-geoip/`
- File cache in `wp-content/cache/baskerville/` (only relevant if Redis is not enabled)

This is a deliberate decision. The stats table contains up to 14 days of attack history, blocked
IPs, and traffic patterns. Destroying it automatically on plugin deletion would be irreversible
and unexpected — especially during reinstalls or plugin swaps.

**If a site is permanently decommissioned** and you want to clean up, run manually:

```sql
DROP TABLE IF EXISTS
  wp_baskerville_stats,
  wp_baskerville_snapshots,
  wp_baskerville_daily,
  wp_baskerville_incidents,
  wp_baskerville_reports;

DELETE FROM wp_options WHERE option_name LIKE 'baskerville_%';
DELETE FROM wp_options WHERE option_name LIKE '_transient_baskerville_%';
DELETE FROM wp_options WHERE option_name LIKE '_transient_timeout_baskerville_%';
```

And remove the directories:
```bash
rm -rf wp-content/uploads/baskerville-geoip/
rm -rf wp-content/cache/baskerville/
```

