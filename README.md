# Baskerville WordPress Plugin

A WordPress security plugin with GeoIP-based access control, AI-powered bot detection, Cloudflare Turnstile integration, and advanced fingerprinting.

## Features

- 🛡️ **AI-Powered Bot Detection** - Classification of bots vs. humans with configurable thresholds
- 🌍 **GeoIP Access Control** - Block or allow traffic by country (whitelist/blacklist)
- 🔍 **Browser Fingerprinting** - Advanced client-side fingerprinting with Canvas, WebGL, Audio
- ☁️ **Cloudflare Turnstile** - CAPTCHA challenge for borderline bot scores with precision analytics
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

<details>
<summary> User Interaction and Client Side System Design - <em>How users engage with the puzzle & High-level design.</em></summary>

- [How the client side works](#how-the-client-side-works)
- [User Interaction Flow](#how-the-client-side-works)
  - [Receiving a Challenge](#receiving-a-challenge)
  - [Solving & Submitting](#solving-and-submitting)
  - [Accesssibility Considerations](#accessability-considerations)
</details>

<details>
<summary> Security - <em>How we prevent tampering & automated solvers.</em></summary>

- [Security Principles](#security-principles)
  - [Preventing Automated Solvers](#preventing-automated-solvers)
  - [Rate Limiting](#rate-limiting)
    - [Client Side Rate Limiting](#client-side-rate-limiting)
    - [Server Side Rate Limiting](#server-side-rate-limiting)
  - [Click-Chain Validation](#client-side-integrity-checking)
  - [Client-Side Integrity Checks](#client-side-integrity-checking)
  - [Trust Boundaries: Client vs. Server](#trust-boundaries)
</details>

   
<details open>
<summary> Developer Guide - <em>Understanding the filesystem & Instructions for setting up, deploying, and contributing to the project.</em></summary>

- [Developer Guide](#developer-guide)
  - [Languages & Tools](#languages--tools)
    - [Languages](#languages)
    - [Tools](#tools)
  - [Project Structure](#project-structure)
  - [Deployment Guide](#deployment-guide)
    - [Serving In Production](#serving-in-production)
  - [Contributing](#contributing)
    - [Setting up the development environment](#setting-up-the-development-environment)
        - [Package.json Commands](#package.json-commands)
        - [Typical Development Workflow](#typical-development-workflow)
        - [Typical Production Workflow](#typical-production-workflow)
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

---



# User Interaction and Client Side System Design

## How the Client Side Works

- The Deflect CAPTCHA client operates as a self-contained, pre-bundled system delivered to the user's browser in a single request. This ensures a seamless experience without requiring additional external dependencies or network requests beyond the initial page load.

## User Interaction Flow

### Receiving a Challenge

1) The client receives an `index.html` file containing:
    - Prebundled CSS, JavaScript, dependencies, and polyfills.  
    - The initial game state, injected at the time of delivery.
    - If no initial state is found, the puzzle phones home to request a challenge.
2) The puzzle immediately starts, prompting the user to solve it.
3) The challenge issued to the user has the following structure:

    ```
        type CAPTCHAChallenge struct {
            GameBoard          [][]*Tile         `json:"gameBoard"`
            ThumbnailBase64    string            `json:"thumbnail_base64"`
            MaxAllowedMoves    int               `json:"maxNumberOfMovesAllowed"`
            TimeToSolveMS      int               `json:"timeToSolve_ms"`
            CollectDataEnabled bool              `json:"collect_data"`
            ClickChain         []ClickChainEntry `json:"click_chain"`
        }
    ```

### Solving & Submitting

1) The puzzle consists of an nxn grid, where one tile is missing.
2) The user can only move tiles adjacent to the missing space by clicking on them. Clicking a tile swaps its position with the missing tile.
3) The objective is to rearrange the tiles until they recreate the original reference image.

4) Each tile contains:
    ```
    type Tile struct {
        Base64Image string `json:"base64_image"`
        TileGridID  string `json:"tile_grid_id"`
    }
    ```
- Where:
    - Base64Image: Encoded PNG of the puzzle segment.
    - TileGridID: A hashed identifier derived from:
        - Hmac(The tile's base64 image + The user's challenge cookie + A server-side secret)
    - The TileGridID ensures that each puzzle instance is unique and prevents replay attacks.

- When the user clicks Solve, the system:
    1) Extracts the TileGridID of each tile in order.
    2) Concatenates them into a single string.
    3) Computes an HMAC hash of the string using the challenge cookie as a key.
    4) Submits this computed hash as the solution.

### Accessibility Considerations
    
- These are as of yet not addressed and remain and important TODO
- Perhaps an auditory challenge for the visually impaired?


---



# Security

## Security Principles

- The following outlines the client-side security mechanisms implemented in Deflect CAPTCHA to prevent spam, mitigate automated solvers, and ensure the integrity of submitted solutions. 

### Preventing Automated Solvers

- State-Space Search Problem

    - Deflect CAPTCHA is designed as a state-space search problem—a well-studied class of problems in computer science where solving involves transitioning through valid states.

- As mentioned in the introduction:

    - Bots and LLMs struggle with this type of problem due to combinatorial complexity.
    - Humans also find it difficult, but they approach it differently, which allows us to analyze behavioral patterns.
    - We can study interactions over time to differentiate bots from real users based on how they play rather than solely correctness.

- Configurable Difficulty to Deter Bots:
    - Configurations dynamically adjust puzzle difficulty based on detected behavior. 
        - If a bot is suspected, we have the capability of making the puzzle exponentially harder:

            ```
            profiles:

                default:
                    nPartitions: 9 #3x3
                    nShuffles: [1, 2] #only one shuffle as per Antons suggestion
                    maxNumberOfMovesAllowed: 10
                    removeTileIndex: 4 #set to -1 if you want to instead enable randomly choosing from the board
                    timeToSolve_ms: 895_000 #14.91 mins (because cookie itself is valid for 15 mins by default)

                easy:
                    nPartitions: 9  # 3x3 grid
                    nShuffles: [5, 8]
                    maxNumberOfMovesAllowed: 160
                    timeToSolve_ms: 1_200_000  # 20 minutes

                medium:
                    nPartitions: 16  # 4x4 grid
                    nShuffles: [5, 8]
                    maxNumberOfMovesAllowed: 200
                    timeToSolve_ms: 900_000  # 15 minutes

                painful:
                    nPartitions: 49  # 7x7 grid
                    nShuffles: [30, 50]
                    maxNumberOfMovesAllowed: 300
                    timeToSolve_ms: 420_000

                nightmare_fuel:
                    nPartitions: 100  # 10x10 grid
                    nShuffles: [1000, 2000]
                    maxNumberOfMovesAllowed: 6000
                    timeToSolve_ms: 360_000
            ```

## How This Prevents Bots:

- The most important reason has to do with **several components working together**: 
    
    1) Click-Chain Validation & Uniqueness

        - A click-chain blockchain cryptographically proves that the user performed a valid sequence of moves leading to the final board state.
        - Each puzzle board is unique per user, preventing replay attacks.
        - Rate limiting ensures only a few submissions within the allotted time, making brute-force infeasible—getting rate-limited 3-4 times can drain the available time, forcing a restart.

    2) Dynamic Puzzle Adjustments

        - The system dynamically modifies puzzles by:
            - Changing the missing tile position.
            - Altering the image, time limit, and max moves.
            - Adjusting the grid size (number of partitions) and shuffle complexity.
        
        These parameters scale difficulty based on behavior, making automated solving exponentially harder.

    3) Built-in Anti-Cheat Mechanisms

        - Noise is deliberately added to the thumbnail image to prevent trivial reconstruction.
        - Even if an attacker partitions the thumbnail, the Base64-encoded pieces won’t match due to injected noise, preventing automated board reconstruction.
        - Each tile is also encoded with its own noise using different entropy from that which was applied to the thumbnail ensuring there is no correlation between the two
        - Each puzzle tile base64 encoded PNG is guarenteed to be unique per challenge per user
        - Each thumbnail is guarenteed to be unique per challenge per user
        - Each thumbnail is guarenteed to be different from the puzzle grid tile base64 images even when partitioned
        - This ensures even replay attacks are not possible as even if you record the base64 images you put into order in one puzzle, the next time you receive it,
        the base64 PNG will not be the same as they have different noise applied to them. Since the TileID's are derived from the base64 PNGs which as mentioned are unique
        we can guarentee that the solution that is derived from placing them in order is guarenteed to be unique as well.
        - Finally, for any given challenge, if there are tiles on the board that are the same, for example if there are blank tiles which have the same b64 data, then after adding noise
        they will continue to be the same ensuring they remain interchangeable! Between different challenges, these blank tiles, as with all other tiles are guarenteed to be different from one another!
        - Integrity checking and click-chain solution guarentee that no replay or forgery attacks can occur.
        - ClickChain also ensures that the solution itself is correct in that each step the user took while solving does indeed lead to the final result being what they submitted
        
    For more on the ClickChain or how integrity, noise or uniqueness are guarenteed, see [Server-Side Documentation](../internal/puzzle-util/README.md).

    4) Machine Learning (behaviour analysis) - NOT YET DONE

        - Once the data collection is complete, we wiil be able to collect data about gameplay and use it to make predictions about whether a human or bot was playing the game
        - A combination of the correct solution and human-like behaviour while playing will be used to produce the final decision

    This **layered approach** ensures that bots cannot brute-force, replay, or reconstruct the puzzle *while keeping it solvable for real users*.

### Rate Limiting

#### Client-Side Rate Limiting

- Client-side protections prevent spamming by users pressing submit repeatedly (especially useful under heavy load). This is enforced via delays and UI locking mechanisms to slow down consecutive attempts

#### Server-Side Rate Limiting

- Server-side rate limiting is designed to:

    1) Throttle requests to prevent brute-force guessing.
    2) Enforce a max of 4 solution submissions per unit time.
    3) Ensure users run out of time before brute-forcing a solution.

### Click-Chain Validation

- Each puzzle challenge is unique per user and validated via a cryptographic click-chain (similar to how a block chain works)

    - A unique puzzle board is generated for each user, where each tile has a hashed ID derived from the tile’s image and the user’s challenge cookie.
    - A Genesis Block (initial entry) is created, linked to the user’s challenge cookie and an internal secret.
    - Each valid move is appended to the click-chain, referencing the previous move's hash, ensuring an immutable sequence.
    - Solution validation: The final board state is verified against the expected target solution.

- Security Benefits:

    - Ensures puzzle integrity – every move is logged and cryptographically linked.
    - Prevents tampering – since the chain is HMAC-signed, users cannot forge solutions.
    - Stops replay attacks – the secret key ensures that click-chains are tied to individual challenges.


### Client-Side Integrity Checks

- To prevent tampering or bypassing, the server side will perform integrity checks:

    1) Ensuring the click-chain hash is valid.
    2) Confirming that move sequences are logically possible.
    3) Detecting unnatural solving patterns indicative of automation.

For more on how this works, see [Server-Side Documentation](../internal/puzzle-util/README.md).


### Trust Boundaries: Client vs. Server

- The client only knows its cookie and board state.
- The server holds the entropy for challenge verification (a secret only we know concatenated with the users challenge cookie)
    - Even with the entire click-chain, users cannot forge a solution because the secret key remains unknown to them.

---


# Developer Guide

## Languages & Tools

### Languages

- The Client-Side Puzzle UI is written in TypeScript (v4.0+ recommended).
- No frameworks (e.g., React, Vue) are used—event listeners are attached directly to ensure maximum compatibility with legacy browsers as these frameworks depend a lot on ES6+ features which break older environments even when using transpilation.

### Tools

#### Bundler: Rollup
    
- Rollup is used to bundle, optimize, and minify the client-side JavaScript, CSS, and dependencies into a single deliverable.
    
##### What is Being included by Rollup

- The following assets are bundled and optimized:

    1) JavaScript - All client-side logic and dependencies (when using production environment variables the JS will be obfuscated)
    2) CSS - Embedded directly into `index.html`.
    3) Polyfills - Ensures compatibility with older browsers. (The required polyfills are imported in the entrypoint-deflect-captcha.ts file such that rollup knows what is needed when bundling)
    4) utility functions required for compatibility with legacy environments.

###### How Rollup Works in This Project
    
- Entry Point: entrypoint-deflect-captcha.ts 
    - Specified in the `input` field of the rollup

- Bundling Process:
    - The script is compiled and minified.
    - Polyfills are included for older browsers.
    - The final bundle is injected into index.html.

- Rollup Configuration Breakdown:

    - JavaScript and TypeScript:

        - The entrypoint-deflect-captcha.ts script serves as the entry point.
        - Babel is used to transpile the code, ensuring compatibility with older browsers.
        - TypeScript is processed using @rollup/plugin-typescript.

    - CSS Handling:

        - By default, CSS is embedded directly into index.html.
        - If you want to bundle CSS inside bundle.js, uncomment the PostCSS plugin in rollup.config.js.

    - Legacy Browser Support:

        - Babel targets Internet Explorer 11+.
        - Ensures compatibility by using core-js for polyfills.
    
    - Security & Performance Enhancements:

        - The bundle is obfuscated in production (rollup-plugin-obfuscator).
        - Minification is done using terser.

##### Compatibility with Legacy Browsers

- One of the **most important requirements** for this project is ensuring that it runs on **legacy browsers**. 
- Some older browsers do not support modern cryptographic APIs and other tooling we take for granted today, so we must fallback to pre-bundled dependencies when necessary.

- These tools are all included in the `src/client/scripts/utils` directory and are imported by the event listener attachment functions that need them
    - Since these are being imported into the entrypoint (via these event listener attachment functions), rollup knows to include them in the `bundle.js`

    Example: Modern browsers support crypto.subtle, but legacy browsers do not. For this reason we have a util function:

    ```
    import {HmacSHA256, enc} from 'crypto-js'

    export async function generateHmacWithFallback(key: string, message: string): Promise<string> {
        if (window.crypto && window.crypto.subtle) {
            const encKey = new TextEncoder().encode(key)
            const encMessage = new TextEncoder().encode(message)
            const cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, encMessage)
            return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, '0')).join('')
        } else {
            return HmacSHA256(message, key).toString(enc.Hex)
        }
    }
    ```

    For browsers that support crypto.subtle, they will use the standard API provided by the browser. However, for those that do not, we have bundled `crypto-js`
    such that their browsers can still invoke the `generateHmacWithFallback()` function


###### Polyfills

- For legacy browsers that do not support native ES6+ features, rollup bundles all the polyfills needed

- At the top of the entrypoint-deflect-captcha.ts file, the necessary polyfills are explicitly imported:
    ```
    import 'core-js/stable'
    import 'regenerator-runtime/runtime'
    ```

- Each polyfill serves a different purpose, for example:
    
    - core-js/stable: Provides shims for missing JavaScript features.
    - regenerator-runtime/runtime: Ensures async/await support for older browsers.


## Project Structure

```
    .
    ├── README.md                        <- You are here
    ├── captchaRollup.config.mjs                            <- Rollup config for bundling
    ├── dist                                                <- Production-ready build output
    │   ├── client
    │   │   └── scripts
    │   │       └── bundle.js                               <- Bundled JS for the client
    │   └── index.html                                      <- Fully self-contained, bundled page. **This is the ONLY thing that need be served by the server.**
    ├── injectBundleJSToIndexHTML.js                        <- Post-bundling script injector
    ├── package-lock.json
    ├── package.json
    ├── src                                                 <- Main source directory
    │   ├── client
    │   │   ├── scripts                                     <- Client-side logic
    │   │   │   ├── attach-footer-and-header-info.ts
    │   │   │   ├── check-initial-state.ts
    │   │   │   ├── client-captcha-solver.ts
    │   │   │   ├── entrypoint-deflect-captcha.ts           <- Main entrypoint, initializes everything
    │   │   │   ├── inspect-target-image-modal.ts
    │   │   │   ├── puzzle-instructions-info-button.ts
    │   │   │   ├── request-different-puzzle.ts
    │   │   │   └── utils                                   <- Helper functions (containing functions with prebundled dependencies as fallbacks for legacy browsers)
    │   │   │       ├── cookie-utils.ts
    │   │   │       └── hmac-utils.ts
    │   │   └── styles                                      <- CSS for the UI (Note: Currently ALL css is already injected directly into the <style></style> tags of the `index.html` - these are here for convenience)
    │   │       ├── main.css
    │   │       ├── puzzle-container.css
    │   │       ├── puzzle-grid.css
    │   │       ├── puzzle-instructions.css
    │   │       ├── puzzle-messages-to-user.css
    │   │       ├── puzzle-refresh.css
    │   │       ├── puzzle-submission.css
    │   │       └── puzzle-thumbnail.css
    │   ├── deflect_logo.svg                                <- Deflect Logo (injected into `index.html` during bundling)
    │   └── index.html                                      <- The HTML template **before** bundling (**not to be served to user**)
    ├── tsconfig.json                                       <- TypeScript configuration
    └── types                                               <- Shared type definitions
        └── shared.d.ts 
```


### types (`puzzle_ui/types`)

- Contains TypeScript type definitions shared across the UI.

### src (`puzzle_ui/src`)

#### src/index.html

- `src/index.html` is the template HTML file **before** bundling. 
- It gets modified during the build process to embed scripts, styles, and the Deflect logo.

#### src/deflect_logo.svg

- The Deflect CAPTCHA logo injected into the final `index.html`.

#### src/client

- Houses all scripts and styles required for the CAPTCHA UI.

##### src/client/scripts

- The core client side logic that runs in the browser

- **Entrypoint:** `entrypoint-deflect-captcha.ts`
    - Initializes the CAPTCHA system.
    - Checks if an initial state was injected or needs to be fetched.
    - Handles error reporting and retry logic.
    - Implements a fallback mechanism for worst-case scenarios.

###### src/client/scripts/utils

- These are utilities that are prebundled with the dependencies required for legacy browsers to function. 
    - For example, not all browsers admit crypto.subtle API. Therefore, we provide `hmac-utils.ts` such that all browsers can either use their `crypto.subtle` API should they have it, or fallback to the pre bundled depdency (`crypto-js`)

- `cookie-utils.ts`: Handles cookies for authentication and state management.
- `hmac-utils.ts`: Cryptographic helper functions.

##### src/client/styles

- Defines the visual styling for different puzzle components.

- By default, styles are embedded directly into `index.html`.

- If you prefer to bundle CSS with JS, you must:
    1) Enable the postcss Rollup hook.
    2) Uncomment the import statements in `entrypoint-deflect-captcha.ts`.
    3) Remove the <style></style> tags from `src/index.html`.

### dist (`puzzle_ui/dist`)

- Contains the production-ready assets.

- Key files:
    - `dist/index.html`: The final, self-contained page (fully bundled).
    - `dist/client/scripts/bundle.js`: The compiled JavaScript bundle.

- **Note:**
    - The `index.html` already includes all required `scripts/styles`.
    - *Only* `index.html` and the user's cookie are needed for deployment.

### root (`puzzle_ui/`)

- houses `injectBundleJSToIndexHTML.js`
    
- This is a custom Rollup hook that modifies index.html after bundling.

- Automatically injects bundle.js into index.html, ensuring that:

    1) All assets are inline (to be served in a single request).
    2) The Deflect CAPTCHA system remains self-contained.

## Deployment Guide

### Serving in Production

- The bundling process ensures that all required assets are packaged into a **single deliverable** for easy deployment. This includes:

1) JavaScript - Bundled with Rollup, optimized, and obfuscated (for production only) & is injected directly into `index.html` via the `injectBundleJSToIndexHTML.js` script.
2) Deflect Logo SVG - Also injected directly into index.html via the `injectBundleJSToIndexHTML.js` script.
3) CSS - Embedded directly inside `index.html`. 
    **Note:** The css may also be included with the `bundle.js` if you:
        1) remmove it from `index.html`
        2) uncomment the entrypoint `*.css` imports
        3) uncomment the postcss() rollup code
4) Polyfills - Included to support legacy browsers (which is an important requirement).

#### What needs to be served?

- This means that the only *file* you need to serve is: `dist/index.html`
- You must also attach a *challenge cookie* along with the `dist/index.html` response payload using the cookie name: `deflect_challenge4`
- That's it. Nothing else is required.
    
#### You do **not** need to serve:

- Logos, JS, CSS, or external assets—they are already embedded in the `index.html`.
- Separate API endpoints for fetching assets—everything needed is in the single file.

#### What the Server Needs to Do

- To properly issue a unique challenge per user, the **server** can follow one of two procedures:

- **1) Recommended Approach (Production Best Practice):** inject the initial state into index.html
    - The server reads index.html before serving it.
    - The server injects a dynamically generated initial state (per user).
    - The user receives index.html with the puzzle state already embedded.
    - This is how Deflect works in production and ensures a seamless, efficient challenge issuance.
    

- **2) Alternative Approach:** do not inject the initial state into index.html, but have an endpoint prepared to handle a request for the puzzle state
    - If the initial state is not injected, the puzzle will immediately phone home requesting it from the server.
    - In this case, the server must provide an endpoint to handle these state requests dynamically.
    - This approach may be useful for development but is not recommended for production.
    

- **Note:** You *will* need to have the endpoint to serve a puzzle state on request regardless of what option you choose as the puzzle includes a rate limited "refresh" button that requets a new puzzle state and updates the current state. This was included to provide the user the option of trying a different one if they deem the current board too difficult. However, it is still recommended to inject the initial state into `index.html` as this is a requirement for how Deflect works.

- For details on how the server should inject the initial state, refer to the [Server-Side Documentation](../internal/puzzle-util/README.md).

## Contributing

### Setting Up the Development Environment
 
- Step 1) Clone this repository

- Step 2) Install dependencies

    ### The UI is built using Node.js and Rollup. Ensure you have Node.js installed (v18 or later). Then, install the required dependencies:
    ```
    cd puzzle_ui
    npm install
    ```

- Step 3) Create a **.env.production** and **.env.development** files

    #### .env.production:
    ```    
    MINIFY_CSS=true
    SOURCE_MAP=false
    OBFUSCATE=true
    ```

    #### .env.development:
    ```
    MINIFY_CSS=false
    SOURCE_MAP=true
    OBFUSCATE=false
    ```

- Step 4) run the following commands:
    ```
    npm run clean
    npm run build
    ```

#### Package.json Commands

- ```npm run dev```
    - deletes the dist/ directory and rebuilds from scratch, bundling all dependencies, and watching for changes to client side code before rebundling (uses dev env variables)

- ```npm run build```
    - runs Rollup to bundle client-side code (which injects the bundle into the` index.html`)

- ```npm run clean```
    - clears the dist/ directory if you want a fresh build

- ```npm run watch```
    - watches for changes in client code & automatically rebundles

- ```npm run prod```
    - deletes the dist/ directory and rebuilds from scratch using production environment variables



#### Typical Development Workflow

- Either run:
    ```
    1) npm run clean
    2) npm run build
    ```
- Or:
    ```
    1) npm run dev
    ```

- The only difference is that the npm run dev will continue monitoring for changes such that when you make a change, it will automatically clean and build such that your server serves the most recent one

- **In both cases**, you must serve from **`dist/index.html`**

- This will not only include the html, but also the css as well as the js and all dependencies and polyfills
- The only thing that remains to do when serving it is to inject the initial state at runtime. Since each puzzle is unique to the user, the initial state cannot be precomputed and must be dynamically generated. The server handles this by issuing a state-specific challenge upon request. This is injected directly into the `index.html` as per Deflect requirements. For more details, check the [Server-Side Documentation](../internal/puzzle-util/README.md).
    - **Note:** If the initial state is **not injected** at runtime, the puzzle **will automatically request it** from the server. In this case, you **must have an endpoint** to handle this request and provide the state dynamically.

#### Typical Production Workflow
 - run: 
    ```
        npm run prod
    ```
- You can now serve the CAPTCHA directly from `dist/index.html`
    - This will contain the HTML, CSS, JS, Polyfills & all dependencies (such as for calculating HMAC)
    - It is also obfuscated via rollup
    - The only thing that remains to do when serving it is to inject the initial state at runtime. Since each puzzle is unique to the user, the initial state cannot be precomputed and must be dynamically generated. The server handles this by issuing a state-specific challenge upon request. This is injected directly into the `index.html` as per Deflect requirements. For more details, check the [Server-Side Documentation](../internal/puzzle-util/README.md).
        - **Note:** If the initial state is **not injected** at runtime, the puzzle **will automatically request it** from the server. In this case, you **must have an endpoint** to handle this request and provide the state dynamically.

---