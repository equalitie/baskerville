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

## 2. Enable Redis as the WordPress object cache backend

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

