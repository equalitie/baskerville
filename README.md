# Baskerville WordPress Plugin

A WordPress security plugin with GeoIP-based access control, AI-powered bot detection, CAPTCHA challenge support, and advanced fingerprinting.

## Features

- 🛡️ **AI-Powered Bot Detection** - Classification of bots vs. humans with configurable thresholds
- 🌍 **GeoIP Access Control** - Block or allow traffic by country (whitelist/blacklist)
- 🔍 **Browser Fingerprinting** - Advanced client-side fingerprinting with Canvas, WebGL, Audio
- 🧩 **Baskerville Gatekeeper** - Built-in state-space puzzle CAPTCHA (no API keys, powered by captcha.openports.dev)
- ☁️ **Cloudflare Turnstile** - Alternative CAPTCHA via Cloudflare (requires API keys)
- 🍯 **Honeypot Detection** - Hidden links to catch AI crawlers
- 📊 **Traffic Analytics** - Real-time statistics, live feed, and Turnstile precision metrics
- ⚡ **Performance Optimized** - Minimal overhead (~1ms with page cache, ~30-50ms without)
- 🔐 **IP Whitelist** - Bypass firewall for trusted IPs
- 🚀 **Caching** - APCu + file-based caching for GeoIP lookups
- 🚨 **Under Attack Mode** - Emergency mode to challenge all visitors

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

### Challenge Provider

Go to **Settings → Baskerville → Challenge** to select and configure the challenge system shown to borderline visitors.

**Providers**:
- **Baskerville Gatekeeper** — built-in state-space puzzle CAPTCHA, no API keys needed
- **Cloudflare Turnstile** — Cloudflare's CAPTCHA widget, requires API keys
- **Disabled** (default) — no challenge shown; borderline visitors are blocked outright

Both providers share the same trigger settings:
- **Bot Score Challenge** - Challenge visitors with scores in the borderline range
- **Score Range** - Define min/max bot score for challenge (default: 40-70)
- **Under Attack Mode** - Emergency mode that challenges ALL visitors

**Score interpretation**:
- 0-39: Likely human (allowed)
- 40-70: Borderline (optional challenge)
- 71-100: Likely bot (blocked)

#### Baskerville Gatekeeper

A puzzle-based CAPTCHA that uses a state-space search problem as the challenge. No third-party account required. Challenges are served **inline** at the original URL (no redirect to a separate page).

When enabled, the plugin contacts `captcha.openports.dev` (operated by eQualitie) to generate and verify challenges.

#### Cloudflare Turnstile

1. Get your Site Key and Secret Key from [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Select **Cloudflare Turnstile** as the provider and enter your keys
3. Configure the borderline score range (default: 40-70)

**Precision Analytics**:
The Analytics tab shows challenge effectiveness:
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
- ✅ Cloudflare Turnstile for borderline cases
- ✅ Honeypot detection for AI crawlers
- ✅ Advanced fingerprinting
- ✅ Real-time traffic analytics with precision metrics
- ✅ Rate limiting & ban management

**Recommendations**:
- ✅ Use **File Logging** mode for production (default)
- ✅ Enable page caching (WP Super Cache, etc.)
- ✅ Install APCu if available (10x faster cache)
- ✅ Whitelist monitoring/testing IPs
- ✅ Configure Turnstile for borderline scores (40-70)
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
│   ├── class-baskerville-stats.php      # Analytics & database logging
│   ├── class-baskerville-rest.php       # REST API for fingerprinting
│   ├── class-baskerville-gatekeeper.php # Baskerville Gatekeeper CAPTCHA integration
│   ├── class-baskerville-turnstile.php  # Cloudflare Turnstile integration
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


---


# Prediction Pipeline Baskerville WordPress Plugin Integration

## Table of Contents

- [Overview](#overview)
- [How the Two Components Work Together](#how-the-two-components-work-together)
- [Component 1: `baskerville-class-prediction-pipeline.php`](#component-1-baskerville-class-prediction-pipelinephp)
  - [Purpose](#purpose)
  - [What It Collects](#what-it-collects)
  - [How It Sends Data to Baskerville](#how-it-sends-data-to-baskerville)
  - [Why This Exists Separately from the Gatekeeper](#why-this-exists-separately-from-the-gatekeeper)
- [Component 2: `baskerville-class-gatekeeper.php`](#component-2-baskerville-class-gatekeeperphp)
  - [Purpose](#purpose-1)
  - [What Requests Pass Through This Path](#what-requests-pass-through-this-path)
  - [High-Level Decision Flow](#high-level-decision-flow)
  - [Challenge Issuance](#challenge-issuance)
  - [Challenge Refresh](#challenge-refresh)
  - [Challenge Verification](#challenge-verification)
  - [Pass-Token Introspection](#pass-token-introspection)
  - [Why Asset and Secondary Requests Are Skipped](#why-asset-and-secondary-requests-are-skipped)
- [End-to-End Flow Summary](#end-to-end-flow-summary)

---

# Overview

The WordPress integration is split into two distinct responsibilities:

1. **Prediction pipeline integration** — responsible for collecting request data at the WordPress origin and sending it to the Baskerville machine learning pipeline.
2. **Gatekeeper enforcement** — responsible for enforcing challenge decisions on subsequent requests once the WordPress side has been told that a requester should be challenged.

These two pieces solve different problems:

- The **prediction pipeline** is about **observability and classification**.
- The **gatekeeper** is about **policy enforcement and challenge handling**.

This separation is intentional. It keeps the data collection path independent from the challenge enforcement path, which makes the plugin easier to reason about and easier to evolve over time. The main plugin file initializes logging, loads the gatekeeper, defines the clearinghouse endpoint, gathers request metadata, and sends that metadata asynchronously to the Baskerville service on each request.

---

# How the Two Components Work Together

At a high level, the flow works like this:

1. A request arrives at the WordPress origin.
2. The **prediction pipeline** collects request metadata and sends it to Baskerville for ML processing.
3. Server-side Baskerville systems process those logs and eventually determine whether that requester should be challenged.
4. That prediction or enforcement state is then pushed and stored on the WordPress side.
5. On later requests, the **gatekeeper** checks that stored state and decides whether to:
   - allow the request through normally,
   - issue a challenge,
   - refresh an active challenge,
   - verify a submitted challenge solution,
   - or validate a previously issued pass token.

So in aggregate:

- `baskerville-class-prediction-pipeline.php` answers:  
  **“What data do we need to gather from this request so Baskerville can classify it?”**
- Note that I refer to `baskerville-class-prediction-pipeline.php` as `prediction pipeline`

- `baskerville-class-gatekeeper.php` answers:  
  **“Given what we already know about this requester, what should happen to this request right now?”**
- Note that I refer to `baskerville-class-gatekeeper.php` as `gatekeeper`

The gatekeeper runs during `template_redirect` and acts as the enforcement entrypoint for normal frontend requests, while the prediction pipeline runs during `init` and handles the data collection path for ML ingestion.

---

# Component 1: `baskerville-class-prediction-pipeline.php`

## Purpose

This file is the **main entrypoint for the Baskerville ML pipeline integration on the WordPress side**.

Its responsibility is to gather all of the request metadata the Baskerville backend expects, package that data into the server-side schema, and send it asynchronously to the Baskerville clearinghouse endpoint for downstream ML processing. It is not responsible for issuing or verifying CAPTCHA challenges. Instead, it is the origin-side logging and telemetry component that feeds the prediction system.

## What It Collects

The prediction pipeline gathers request-level fields from `$_SERVER`, request headers, cookies, and other request metadata to construct the payload expected by the Baskerville backend.

Examples include:

- request method
- URL and query string
- host and original host
- content type
- user agent
- client IP
- accepted encodings
- language
- direct-traffic/referrer information
- conditional GET information
- Cloudflare-related fields when present
- placeholder user-agent and geo structures
- a cookie structure for fields the server-side schema expects

These are assembled by helper functions such as:

- `wpsec_get_all_headers()`
- `wpsec_build_worker_request()`

which normalize incoming request data into the schema expected by the server-side ML pipeline.

## How It Sends Data to Baskerville

Once the request payload is built, the plugin sends it to the clearinghouse endpoint using `wp_remote_post()` with:

- `Content-Type: application/json`
- the site API key
- the site URL

The call is intentionally made with `blocking => false`, which means WordPress does not wait for the ML system to finish processing before continuing the page request. This keeps the origin-side request lightweight while still feeding the Baskerville backend with the data needed for classification.

## Why This Exists Separately from the Gatekeeper

The prediction pipeline and the gatekeeper solve different problems and operate on different timelines.

The prediction pipeline:
- gathers raw request features,
- sends them to Baskerville,
- and enables later classification.

The gatekeeper:
- consumes stored policy state on later requests,
- and decides whether to enforce a challenge.

Keeping these concerns separate makes the plugin easier to understand:

- one path is **classification input**
- the other is **classification enforcement**

---

# Component 2: `baskerville-class-gatekeeper.php`

## Purpose

This file is the **enforcement engine**.

It runs on ordinary frontend requests and decides whether the requester should:

- be allowed through,
- be challenged,
- have an active challenge refreshed,
- have a submitted challenge solution verified,
- or be allowed through because they already hold a valid challenge-pass token.

Its main enforcement function is `wpsec_enforce_captcha_policy()`, which acts as the gatekeeper decision tree for nearly every normal frontend request.

## What Requests Pass Through This Path

Conceptually, almost every normal frontend page request will pass through this function.

However, it intentionally bypasses certain classes of requests because challenging them would break WordPress behavior or create inconsistent challenge state. These bypasses include:

- admin requests
- REST requests
- AJAX requests
- privileged logged-in users
- asset-like requests
- favicon requests

This is especially important because secondary asset requests must not trigger fresh challenge issuance. If they did, the browser could receive new challenge cookies after the original challenge HTML had already embedded a different puzzle state, which would break puzzle verification.

## High-Level Decision Flow

Once the request has passed the early bypass checks, the gatekeeper evaluates it in this order:

1. **Does the requester already carry a CAPTCHA pass token?**
   - If yes, introspect it using the token verification endpoint.
   - If valid, allow the request.
   - If invalid, expired, replayed, or malformed, clear it and continue.

2. **Should this requester be challenged at all?**
   - If not, allow the request normally.
   - If yes, continue into challenge-handling logic.

3. **Is this request asking to refresh the current challenge state?**
   - If yes, clear challenge cookies and fetch a fresh puzzle state.

4. **Does this request carry a CAPTCHA solution submission?**
   - If yes, send the challenge cookies upstream for verification and relay the result.

5. **Otherwise**
   - issue a fresh challenge.

This makes the gatekeeper the central policy router for all challenge-related behavior.

## Challenge Issuance

If the requester should be challenged and has not already submitted a valid solution, the gatekeeper issues a fresh challenge by calling the upstream challenge generation endpoint.

That issuance flow:

- fetches the full challenge HTML from the CAPTCHA service,
- forwards upstream cookies back to the browser,
- and returns the challenge HTML instead of allowing the original page to render.

This is how the origin serves a challenge page in place of the requested content while still keeping the browser talking only to the WordPress origin.

## Challenge Refresh

The challenge UI supports refreshing the puzzle state without replacing the full page.

The gatekeeper detects refresh requests via a request header and, when asked to refresh:

- clears the current challenge cookies,
- calls the upstream refresh endpoint,
- forwards the new cookies,
- and returns fresh puzzle state JSON for the client-side puzzle UI to apply in place.

This keeps refresh behavior entirely within the same origin-mediated design.

## Challenge Verification

When the browser submits a solution, the gatekeeper detects the expected verification cookies and sends them upstream to the CAPTCHA verification endpoint.

The upstream service verifies:

- the original challenge cookie
- the solution hash
- the click-chain cookies
- any rate-limit, integrity, or replay logic

The gatekeeper then relays the result back to the browser:

- `403 invalid solution` → plain error message to the challenge UI
- `429` → rate-limit response with `Retry-After` and JSON body
- `400` → instruct client to refresh/reissue challenge
- `200` → solution passed, forward the challenge-pass cookie, clear temporary challenge cookies, then allow the request

This is the main “submit puzzle and prove you solved it” path.

## Pass-Token Introspection

Once a user has successfully solved the challenge, they receive a pass-token cookie.

On every later request, the gatekeeper checks whether that cookie is present and, if so, introspects it against the upstream token verification endpoint.

This is important because the token must not be trusted merely by its presence. The introspection step ensures the token is:

- valid
- unexpired
- untampered with
- and still bound to the requester properties it was issued for

If token introspection returns success, the request is allowed. Otherwise, the token is cleared and the request falls back into ordinary challenge policy evaluation. 

## Why Asset and Secondary Requests Are Skipped

The gatekeeper intentionally skips asset-like requests and favicon requests because they can occur immediately after the challenge page is served.

If those secondary requests also triggered challenge issuance, the browser could receive new challenge cookies that no longer match the puzzle state embedded in the already-rendered challenge HTML. That would cause later verification failures because:

- the click-chain genesis in the rendered puzzle would belong to one challenge,
- while the browser cookies would belong to another.

Skipping these request types is therefore necessary to preserve challenge-state consistency.

---

# End-to-End Flow Summary

Putting it all together:

1. A request hits the WordPress origin.
2. The **prediction pipeline** collects request metadata and sends it to Baskerville.
3. Baskerville classifies the requester and pushes/stores the result on the WordPress side.
4. On later requests, the **gatekeeper** checks that stored enforcement state.
5. If the requester should not be challenged, WordPress renders normally.
6. If the requester should be challenged:
   - the gatekeeper may issue a challenge,
   - refresh an active challenge,
   - verify a challenge submission,
   - or validate a previously issued pass token.
7. Once the requester successfully solves the challenge, they receive a pass token.
8. On every later request, that pass token is introspected to confirm that the requester is still legitimate.

So the plugin integration as a whole can be understood as:

- **prediction pipeline** = data collection and ML input
- **gatekeeper** = request-time enforcement and challenge lifecycle management

---

# CAPTCHA Puzzle

## Table of Contents

<details>
<summary> Introduction - <em>Overview of the type of puzzle and our goals.</em></summary>

- [Introduction](#introduction)
  - [State-Space Search Problem](#state-space-search-problem)
    - [Why State-Space Search?](#objective)
      - [The High Level Objective](#the-high-level-objective)
      - [What We Have Achieved & What Comes Next](#what-we-have-achieved--what-comes-next)
</details>

---


# Introduction

## State-Space Search Problem

- A state-space search problem is a computer science task that involves finding a solution by navigating through a set of states

#### Components of a state-space search problem 

- States: A set of possible configurations of a problem
- Start state: The initial configuration of the problem
- Goal state: The desired configuration of the problem
- Actions: The actions that can be taken to move from one state to another
- Goal test: A specification of what constitutes a solution

- Examples of state-space search:

    - Solving puzzles like the 8-puzzle or Rubik's cube
    - A robot navigating through a maze

[For more on State Space Search problems see wiki/State_space_search](https://en.wikipedia.org/wiki/State_space_search)

### Why State-Space Search?

- This puzzle was designed as an experiment—it is intentionally built as a state-space search problem.
- The motivation behind this is that bots, LLMs, and automated solvers are not particularly strong at this class of problem, but humans also struggle with it—just in different ways.
- The hypothesis is that humans and bots will approach the puzzle in fundamentally different ways, and by analyzing how they play, we may uncover meaningful differences.

#### The High Level Objective

- This is not a reverse Turing test—the objective isn’t just to prove whether someone is a bot or not. Instead, the goal is to study how people play compared to automated systems.
- In the future, we may develop an API for major LLMs to play, allowing us to collect gameplay data and run comparative analyses.
- The ultimate aim is to train an in-house model that uses gameplay behavior as a distinguishing factor, rather than relying solely on conventional CAPTCHA mechanisms.

#### What We Have Achieved & What Comes Next

- The puzzle itself is complete: we can cryptographically verify whether a submitted solution is correct or incorrect, with each challenge being unique to the user.
- However, correctness alone is only half the solution—the real challenge is distinguishing how the game is played and whether that behavior indicates a human or a bot.
- In theory, this could mean that getting the exact right solution may not even be necessary. If we weight behavioral analysis more heavily than correctness, we could allow slightly incorrect solutions as long as the player's interactions strongly indicate human behavior.
- The really neat part of the project will be in collecting and analyzing gameplay data, identifying patterns that separate human problem-solving strategies from automated solvers.

#### Cool fact about the puzzle:
- Finding a solution for n-puzzle is easy. However, finding a shortest solution is NP-hard.
