# Baskerville WordPress Plugin

A WordPress security plugin with AI bot detection, GeoIP access control, CAPTCHA challenge, and optional AI cloud analysis. Free, open source, works out of the box.

## Features

- 🛡️ **AI-Powered Bot Detection** - Classification of bots vs. humans with configurable thresholds
- 🤖 **AI Spoofer Detection** - Catches bots that fake legitimate AI crawler User-Agents (GPTBot, ClaudeBot, etc.) by verifying their IP ranges against published ASN data
- 🌍 **GeoIP Access Control** - Block or allow traffic by country, multiple data sources, works out of the box
- 🔍 **Browser Fingerprinting** - Advanced client-side fingerprinting with Canvas, WebGL, Audio and other environment signals; bot score 0–100
- ☁️ **CAPTCHA Challenge** - Built-in challenge system, no third-party account or API key required
- 🍯 **Honeypot Detection** - Hidden links to catch AI crawlers
- 📊 **Live Traffic Feed** - Real-time visual dashboard showing every request, score, and decision as it happens
- 🔒 **High-Risk Page Protection** - Login, registration, and comment pages hardened automatically
- 🔐 **Per-Provider Bot Rules** - Allow Googlebot, block GPTBot, challenge everything in between; custom allowlist for trusted bots
- ⚡ **Near-Zero Latency** - Firewall runs entirely from local cache (APCu or file), ~1ms overhead with page cache active. LLM analysis is fully asynchronous — no visitor ever waits for an AI call
- 🚀 **No Configuration Required** - Sensible defaults protect from the moment the plugin is activated
- 🚨 **Under Attack Mode** - Emergency mode to challenge all visitors
- 🔐 **IP Whitelist** - Bypass firewall for trusted IPs

## Building

Run from the **parent directory** of the plugin folder:

```bash
cd ..   # from baskerville/ go to parent directory
zip -r9 baskerville.zip baskerville/ \
  -x "*.DS_Store" \
  -x "baskerville/.git/*" \
  -x "baskerville/.gitignore" \
  -x "baskerville/.idea/*" \
  -x "baskerville/.claude/*" \
  -x "baskerville/vendor/*" \
  -x "*.log" \
  -x "*.txt" \
  -x "*.sh" \
  -x "*.html" \
  -x "baskerville/test-*.php" \
  -x "baskerville/composer.json" \
  -x "baskerville/deployment.md" \
  -x "baskerville/bot-detector*.js" \
  -x "baskerville/ab" \
  -x "baskerville/done" \
  -x "baskerville/sleep"
```

**Note**: The `vendor/` folder is excluded. After plugin installation, go to **Settings → Baskerville → Settings** and click "Install MaxMind Library" to enable GeoIP features.

## Installation

1. Upload `baskerville.zip` in WordPress Admin → Plugins → Add New → Upload Plugin
2. Activate the plugin
3. Go to Settings → Baskerville to configure

## Configuration

### GeoIP Setup

1. Go to **Settings → Baskerville → Settings**
2. Install MaxMind GeoLite2 database (one-click installer)
3. Configure access mode:
   - **Allow All** (default) - No country restrictions
   - **Blacklist** - Block specific countries
   - **Whitelist** - Allow only specific countries

### IP Whitelist

1. Go to **Settings → Baskerville → IP Whitelist**
2. Click "Add My IP" to whitelist your current IP
3. Or manually add IPs (one per line or comma-separated)

**Use cases**:
- Load testing with Apache Bench
- Whitelisting office network
- Development environments
- Monitoring services

### Cloudflare Turnstile

Turnstile provides a CAPTCHA-like challenge for visitors with borderline bot scores, allowing legitimate users to prove they're human instead of being blocked outright.

1. Go to **Settings → Baskerville → Turnstile**
2. Get your Site Key and Secret Key from [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)
3. Enter the keys and enable Turnstile
4. Configure the borderline score range (default: 40-70)

**Settings**:
- **Bot Score Challenge** - Show Turnstile to visitors with scores in the borderline range
- **Score Range** - Define min/max bot score for challenge (e.g., 40-70)
- **Under Attack Mode** - Emergency mode that challenges ALL visitors (use during attacks)
- **Form Protection** - Protect login, registration, and comment forms

**Score interpretation**:
- 0-39: Likely human (allowed)
- 40-70: Borderline (show Turnstile challenge)
- 71-100: Likely bot (blocked)

**Precision Analytics**:
The Analytics tab shows Turnstile effectiveness:
- **Redirects** - Number of challenges shown
- **Passed** - Visitors who completed the challenge
- **Failed** - Visitors who failed or abandoned (likely bots)
- **Precision** - % of challenges that caught bots: `(redirects - passes) / redirects`

### Bot Control

Configure how bots are detected and banned.

1. Go to **Settings → Baskerville → Bot Control**

**Settings**:
- **Ban All Detected Bots** - Ban all `bot` classifications, not just `bad_bot`
- **Instant Ban Threshold** - Score threshold (0-100) for immediate ban without waiting for burst protection. Visitors with scores >= threshold are banned instantly if they don't look like a browser and aren't verified crawlers.

**Example**: With threshold set to 70, a visitor with score 75 and suspicious headers will be banned immediately.

### Performance Optimization Tips

#### 1. Enable Page Caching (Critical!)

**Impact**: -95% response time

```bash
# Install one of:
- WP Super Cache (free)
- W3 Total Cache (free)
- LiteSpeed Cache (free)
- WP Rocket (paid)
```

**Why it helps**:
- Cached pages bypass WordPress PHP execution
- Baskerville firewall is not executed for cached pages
- Overhead drops from 50ms → 0ms

---

#### 2. Enable APCu for Object Caching

**Impact**: 10x faster cache operations

```bash
# Ubuntu/Debian
sudo apt install php-apcu
sudo systemctl restart php-fpm

# Verify
php -m | grep apcu
```

**Why it helps**:
- GeoIP lookups cached in memory (not disk)
- Ban cache uses RAM (faster than file I/O)
- APCu: 0.05ms, File: 0.5ms per operation

---

#### 3. Use NGINX GeoIP2 Module

**Impact**: 10x faster GeoIP lookups

```nginx
# /etc/nginx/nginx.conf
load_module modules/ngx_http_geoip2_module.so;

http {
    geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
        auto_reload 5m;
        $geoip2_data_country_code country iso_code;
    }

    fastcgi_param GEOIP2_COUNTRY_CODE $geoip2_data_country_code;
}
```

**Why it helps**:
- NGINX does GeoIP lookup (not PHP)
- Result passed via `$_SERVER['GEOIP2_COUNTRY_CODE']`
- Baskerville uses NGINX result (no MaxMind DB lookup needed)

---

#### 4. Enable PHP OPcache

**Impact**: 30-50% faster PHP execution

```bash
# Check if enabled
php -i | grep opcache.enable

# Enable in php.ini
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.validate_timestamps=0 # Production only
```

### Logging Mode Comparison

| Mode | Overhead | Analytics | Shared Hosting | Recommended For |
|------|----------|-----------|----------------|-----------------|
| **File** | ~50-70ms (5%) | ✅ Full (5min delay) | ✅ Perfect | Production |
| **Disabled** | ~0ms (0%) | ❌ None | ✅ Perfect | Testing/Dev |
| **Database** | ~500ms (36%) | ✅ Instant | ❌ Slow | VPS only |

---

### Conclusion

Baskerville with **File Logging** adds **5% overhead** while providing:
- ✅ GeoIP-based access control
- ✅ AI-powered bot detection with configurable thresholds
- ✅ AI spoofer detection (IP range verification)
- ✅ Per-provider AI bot rules (OpenAI, Meta, Google, and others)
- ✅ Altcha built-in CAPTCHA or Cloudflare Turnstile for borderline cases
- ✅ Honeypot detection for AI crawlers
- ✅ Real-time traffic feed and analytics
- ✅ Rate limiting & ban management
- ✅ Optional AI cloud analysis (nightly watchdog, natural language queries)

**Recommendations**:
- ✅ Use **File Logging** mode for production (default)
- ✅ Enable page caching (WP Super Cache, etc.)
- ✅ Install APCu if available (10x faster cache)
- ✅ Whitelist monitoring/testing IPs
- ✅ Configure challenge range for borderline scores (40-70)
- ✅ Set Instant Ban Threshold for high-risk visitors (e.g., 85)

---

## Troubleshooting

### Slow Performance

**Symptom**: Page loads take >5 seconds

**Solutions**:
1. ✅ Enable page caching (WP Super Cache)
2. ✅ Install APCu: `apt install php-apcu`
3. ✅ Enable PHP OPcache
4. ✅ Use NGINX GeoIP2 module (optional)

### Cache Issues

**Symptom**: GeoIP shows wrong country after VPN change

**Solution**: Clear GeoIP cache
1. Go to **Settings → Baskerville → GeoIP Test**
2. Click "Clear GeoIP Cache" button
3. Page will reload with updated country

### Load Testing Blocked

**Symptom**: Apache Bench gets 403 errors

**Solution**: Whitelist your IP
1. Go to **Settings → Baskerville → IP Whitelist**
2. Click "Add My IP" button
3. Run tests again

---

## Development

### File Structure

```
baskerville/
├── admin/
│   └── class-baskerville-admin.php      # Admin UI, settings, analytics
├── includes/
│   ├── class-baskerville-core.php       # Core functions, caching, GeoIP
│   ├── class-baskerville-firewall.php   # Firewall logic, blocking rules
│   ├── class-baskerville-ai-ua.php      # AI bot detection & classification
│   ├── class-baskerville-ai-bots.php    # Known AI bot registry & spoofer detection
│   ├── class-baskerville-cloud.php      # AI cloud integration (watchdog, query, actions)
│   ├── class-baskerville-stats.php      # Analytics & database logging
│   ├── class-baskerville-rest.php       # REST API for fingerprinting
│   ├── class-baskerville-turnstile.php  # Cloudflare Turnstile integration
│   ├── class-baskerville-altcha.php     # Altcha built-in CAPTCHA
│   └── class-baskerville-honeypot.php   # Honeypot for AI crawler detection
├── assets/
│   ├── js/baskerville.js                # Frontend fingerprinting script
│   └── css/                             # Styles
├── vendor/                              # MaxMind GeoIP2 library (auto-installed)
└── baskerville.php                      # Main plugin file
```

### Database Schema

```sql
CREATE TABLE wp_baskerville_stats (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    visit_key VARCHAR(64),
    ip VARCHAR(45),
    country_code VARCHAR(2),          -- Added in v1.0.0
    baskerville_id VARCHAR(32),
    timestamp_utc DATETIME,
    score INT,
    classification VARCHAR(32),
    user_agent TEXT,
    evaluation_json LONGTEXT,
    score_reasons TEXT,
    classification_reason TEXT,
    block_reason VARCHAR(120),
    event_type VARCHAR(16),
    had_fp TINYINT(1),
    INDEX idx_timestamp (timestamp_utc),
    INDEX idx_ip (ip),
    INDEX idx_country_code (country_code),  -- Added in v1.0.0
    INDEX idx_event_type (event_type)
);
```

---

## License

GPL v3 or later - Compatible with WordPress.org plugin directory requirements.

## Support

For issues and feature requests, please open an issue on GitHub.