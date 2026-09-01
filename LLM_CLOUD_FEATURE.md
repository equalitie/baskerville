# Baskerville AI Cloud — LLM-Powered Incident Analysis

## Concept

Add an optional premium feature to the plugin: LLM-powered incident analysis and reporting, delivered as a hosted service. Users pay for a subscription, enter a license key, and immediately get AI-generated incident reports and automated defense recommendations — no API keys, no configuration, no infrastructure.

This is the WordPress premium plugin model (Gravity Forms, WP Rocket, ACF Pro): one license key, everything works out of the box.

---

## Problem with Connecting to Kubernetes

Connecting thousands of WordPress installs to a centralized Kubernetes cluster would require:
- Authentication per site
- Raw data leaving every WordPress site
- GDPR exposure for visitor data
- A support and ops burden that scales with installs

This is not viable at tens of thousands of installations. The plugin must remain autonomous.

---

## Architecture

```
WordPress site (plugin)
  │
  ├── Collects stats locally → wp_baskerville_stats
  ├── Every 5 min: saves snapshot → wp_baskerville_snapshots
  │     (traffic, blocks, challenges, country/fingerprint/ua/asn/session_length histograms)
  ├── Detects traffic spike OR block/challenge spike vs snapshot baseline
  ├── Builds payload: current snapshot + delta vs baseline + ip_overlap + no_cookie_pct
  │
  └── POST https://api.baskerville.ai/v1/analyze
              │
              └── Baskerville backend (FastAPI)
                    ├── Validates license key
                    ├── Calls OpenAI / Anthropic (switchable via LLM_PROVIDER)
                    └── Returns { job_id }  ← immediately, async

Plugin polls GET /v1/report/{job_id} every 2 min
  ├── status: pending → wait
  └── status: ready → { actions[], reasoning, report_markdown }
        ├── Apply actions locally (firewall rules, temporary blocks)
        └── Save to wp_baskerville_reports + wp_baskerville_incidents
```

**Key principle:** The plugin handles mechanics (data collection, snapshot storage, delta computation, applying blocks). The LLM handles all reasoning and decisions — including cases that rule-based logic would miss, such as distributed one-shot botnets where no individual IP looks suspicious.

The LLM never connects to the WordPress database. All SQL runs locally in PHP.

---

## Incident Lifecycle

```
1. DETECT — cron every 5 min detects traffic spike OR decision spike (3x factor)
2. CREATE  — incident record created (status: active, started_at)
3. ANALYZE — payload built, submitted to api.baskerville.ai, job_id stored
4. REASON  — LLM produces reasoning + actions (polled async)
5. APPLY   — temporary blocks applied with TTL (default 2h)
6. MONITOR — every 5 min: is traffic back to baseline?
7. CLOSE   — if yes: incident closed (ended_at), blocks lifted
```

### wp_baskerville_incidents table

```sql
id, started_at, ended_at, status (active|closed),
spike_type, spike_factor,
no_cookie_mode (none|challenge|block),
actions_json,    -- applied LLM actions
reasoning,       -- LLM reasoning text
report_markdown,
ip_overlap_json  -- overlap with previous incidents
```

---

## Snapshot Histograms

Every 5 minutes the plugin saves a snapshot to `wp_baskerville_snapshots`.
Snapshots are the foundation for spike detection, baseline comparison, and LLM payload.

### wp_baskerville_snapshots table

```sql
snapshot_at           DATETIME        -- timestamp of this 5-min window
traffic_count         INT             -- total requests
block_count           INT             -- event_type='block'
challenge_count       INT             -- challenge decisions
unique_ips            INT
unique_sessions       INT             -- distinct (ip, baskerville_id) tuples in window
immature_ratio        FLOAT           -- fraction of sessions with exactly 1 request (0.0–1.0)
no_cookie_pct         FLOAT           -- % requests without baskerville_id cookie

countries_json        JSON            -- { "SG": 847, "US": 12, "DE": 34 }
fingerprints_json     JSON            -- { "webdriver": 89, "http1_protocol": 340, ... }
ua_json               JSON            -- { "MJ12bot": 1240, "Chrome/124": 340, ... }
asn_json              JSON            -- { "ALIBABA-US (AS45102)": 890, ... }
classifications_json  JSON            -- { "human": 450, "bot": 120, "bad_bot": 380, "borderline": 8 }
known_bots_json       JSON            -- { "search_engines": {...}, "ai_training": {...}, "seo_tools": {...} }
ai_traffic_json       JSON            -- { "OpenAI": 234, "ByteDance": 890 }  flat, for daily rollup

PRIMARY KEY (snapshot_at)
```

Retention: 7 days. Cleaned up by daily cron. 7 days × 288 snapshots/day ≈ 2,016 rows max.

### immature_ratio — one-shot botnet detection

`immature_ratio` = fraction of unique sessions in the 5-minute window that made exactly 1 request.
Computed at snapshot time via SQL — no session tracking table required:

```sql
SELECT
  COUNT(DISTINCT session_key) AS total_sessions,
  SUM(CASE WHEN cnt = 1 THEN 1 ELSE 0 END) AS immature_sessions
FROM (
  SELECT COALESCE(baskerville_id, ip) AS session_key, COUNT(*) AS cnt
  FROM wp_baskerville_stats
  WHERE timestamp_utc >= :window_start AND timestamp_utc < :window_end
  GROUP BY session_key
) sub
```

`immature_ratio = immature_sessions / total_sessions`

**Why this is the key signal:** Distributed one-shot botnets (10,000 IPs × 1–2 requests each) are invisible to:
- Per-IP rule-based logic (each IP looks normal)
- IP overlap (fresh IPs, never seen before)

But `immature_ratio` immediately shows: "0.97 (97% of sessions = 1 request)" vs baseline "0.12".
Combined with country/ASN shift, the LLM identifies this as a distributed one-shot attack.

**Note on session_length_json:** A full bucketed distribution (`{"1": 89, "2": 45, ...}`) was considered but rejected:
- Sessions span more than one 5-min window, so per-window counts are partial
- `immature_ratio` captures the most important signal (1-hit pattern) without ambiguity
- Clearinghouse experience confirmed: immature/mature ratio is sufficient for LLM reasoning

### What each histogram catches

| Signal | Attack pattern detected |
|---|---|
| `countries_json` | Country concentration spike (SG: 2% → 97%) |
| `fingerprints_json` | Botnet fingerprint emergence (webdriver: 1% → 89%) |
| `ua_json` | Known bot UA surge (MJ12bot: 2 → 1,240) |
| `asn_json` | ASN concentration (Alibaba: 0.1% → 97%) |
| `immature_ratio` | One-shot botnet (0.12 baseline → 0.97 attack) |
| `block_count` | Decision spike — rule engine sees attack before traffic peaks |
| `no_cookie_pct` | Cookie-less bot flood |

---

## Spike Detection

Two independent triggers (either fires an incident):

**Traffic spike** — current snapshot `traffic_count` vs average of last 6 snapshots (30 min baseline) exceeds 3x.

**Decision spike** — current snapshot `block_count + challenge_count` vs baseline exceeds 3x. Fires earlier than traffic spike — the rule engine sees the attack before raw volume peaks.

Cooldown: 30 minutes between incidents to avoid re-triggering during active attack.

---

## Payload Sent to API

Aggregated statistics only — no raw IPs, no PII.

The payload contains the **current snapshot** plus **deltas vs baseline** (average of last 6 snapshots).
The LLM receives both absolute numbers and relative changes, enabling it to detect
attacks invisible to per-request rule-based logic (e.g. distributed one-shot botnets).

```json
{
  "license_key": "...",
  "domain": "example.com",
  "spike_type": "traffic | decisions | both",
  "spike_factor": 163.4,
  "unique_ips": 692,
  "no_cookie_pct": 94.2,

  "timeline": [
    { "bucket": "2026-08-11 14:05", "requests": 12, "blocks": 1, "challenges": 2 },
    { "bucket": "2026-08-11 14:10", "requests": 1958, "blocks": 847, "challenges": 312 }
  ],

  "current_snapshot": {
    "traffic_count": 1958,
    "block_count": 847,
    "challenge_count": 312,
    "unique_ips": 692,
    "unique_sessions": 680,
    "immature_ratio": 0.97,
    "no_cookie_pct": 94.2,
    "countries":        { "SG": 1840, "US": 12, "DE": 8 },
    "fingerprints":     { "webdriver": 89, "http1_protocol": 340, "lang_mismatch": 124 },
    "user_agents":      { "MJ12bot/v1.4.8": 1240, "Chrome/124.0": 340 },
    "asns":             { "ALIBABA-US (AS45102)": 1820, "CLOUDFLARENET (AS13335)": 12 }
  },

  "baseline_snapshot": {
    "traffic_count": 12,
    "block_count": 1,
    "challenge_count": 2,
    "unique_ips": 8,
    "unique_sessions": 7,
    "immature_ratio": 0.12,
    "no_cookie_pct": 6.1,
    "countries":        { "SG": 1, "US": 8, "DE": 3 },
    "fingerprints":     { "webdriver": 0, "http1_protocol": 1, "lang_mismatch": 0 },
    "user_agents":      { "MJ12bot/v1.4.8": 0, "Chrome/124.0": 9 },
    "asns":             { "ALIBABA-US (AS45102)": 0, "CLOUDFLARENET (AS13335)": 1 }
  },

  "top_urls": [
    { "url": "/wp-login.php", "count": 1240 }
  ],

  "auto_blocked_ips": {
    "count": 0,
    "pct_of_attack_traffic": 0,
    "action": "none"
  },

  "ip_overlap": {
    "previous_incidents": 3,
    "overlap_count": 340,
    "overlap_pct": 49.1,
    "last_seen": "2026-07-15"
  }
}
```

The LLM receives both `current_snapshot` and `baseline_snapshot` and computes its own
deltas — this gives it full context rather than pre-filtered summaries.

---

## LLM Actions

The backend LLM returns a list of actions (not just one):

```json
{
  "actions": [
    { "type": "block_asn",     "target": "ALIBABA-US (AS45102)", "ttl_hours": 2 },
    { "type": "block_country", "target": "SG",                   "ttl_hours": 2 },
    { "type": "raise_threshold", "value": 40 },
    { "type": "block_useragent", "pattern": "MJ12bot",           "ttl_hours": 4 }
  ],
  "reasoning": "97% of attack traffic originates from Alibaba Singapore...",
  "report_markdown": "## Incident Report..."
}
```

### Action types

| Action | What happens in plugin | Reversible |
|---|---|---|
| `block_country` | Firewall blocks by `country_code` | Yes, TTL |
| `block_asn` | Firewall blocks by `asn` field | Yes, TTL |
| `block_useragent` | Firewall blocks by UA pattern match | Yes, TTL |
| `raise_threshold` | Lowers challenge score threshold | Yes, restored on close |
| `none` | Report only, no action | — |

---

## No-Cookie Attack Mode

Many attacks are driven by bots that never return session cookies (`baskerville_id`). These bypass fingerprinting entirely since there is no JS execution.

### Auto-detection (no LLM needed)

Every 5 minutes, independently of incident detection:

```
IF (last 10 min: had_fp=0 records > 70% of total traffic)
AND (those sessions classified as bot/bad_bot > 60%)
THEN activate no-cookie mode
```

### Two levels depending on spike severity

| Spike factor | Response |
|---|---|
| < 10x | Challenge all no-cookie visitors with Altcha |
| ≥ 10x | Hard block (403) all no-cookie visitors |

Rationale: at low spike, VPN users and fresh visitors should get a chance to prove humanity via Altcha. At severe spike, the cost of false positives is acceptable — the site is under serious attack.

### Implementation

Runs in firewall at `plugins_loaded` — before any DB queries, before cookies are set:

```php
if ($no_cookie_mode && !isset($_COOKIE['baskerville_id'])) {
    if ($spike_severe) {
        http_response_code(403); exit;
    } else {
        // serve Altcha challenge inline
    }
}
```

Mode stored in transient (`baskerville_no_cookie_mode`, TTL 15 min, auto-renewed while attack continues).

---

## Automatic IP Block (Pre-LLM)

When attack is concentrated in a small number of IPs, block them deterministically
before sending to LLM — no tokens wasted on pure list processing.

**Trigger condition:**
- Top N IPs account for > 80% of attack traffic in the last 30 min
- AND N <= 50 (concentrated attack, not distributed botnet)

**Logic (runs in plugin before payload assembly):**

```sql
SELECT ip, COUNT(*) as cnt
FROM wp_baskerville_stats
WHERE timestamp_utc >= [cutoff]
  AND event_type IN ('page','fp','block')
GROUP BY ip
HAVING cnt > [per_ip_threshold]
ORDER BY cnt DESC
LIMIT 50
```

If condition met → block those IPs immediately via firewall cache (TTL 2h).
Add to payload as metadata only (LLM does not decide):

```json
"auto_blocked_ips": {
  "count": 8,
  "pct_of_attack_traffic": 84.2,
  "action": "blocked"
}
```

LLM is informed but does not receive the raw IP list. LLM then focuses on
ASN/country/fingerprint patterns for the remaining distributed traffic.

---

## IP Overlap with Previous Incidents

When building the payload, the plugin queries:

```sql
SELECT COUNT(DISTINCT s.ip) as overlap_count
FROM wp_baskerville_stats s
JOIN wp_baskerville_stats prev
  ON s.ip = prev.ip
WHERE s.timestamp_utc >= [attack_window_start]
  AND prev.timestamp_utc < [attack_window_start]
  AND prev.timestamp_utc >= DATE_SUB(NOW(), INTERVAL 90 DAY)
  AND prev.classification IN ('bad_bot','bot','bad_bot')
```

Result sent as `ip_overlap` in payload. LLM uses this for attribution: "49% of attacking IPs were seen in a previous attack 23 days ago — likely the same botnet."

---

## User Agent Analysis

`ua_distribution` (top 10 UAs) is included in the payload. The LLM prompt explicitly asks to:
- Identify spoofed UAs (claiming to be Chrome but other signals contradict it)
- Recognize known botnet UA patterns
- Flag UAs inconsistent with fingerprint signals (e.g. "claims mobile but no touch support")

This is part of Level 1 — no extra API calls, just richer prompt.

---

## AI Bot Intelligence (Conference Feature)

WordPress sites running the plugin passively collect data on which AI companies crawl their content.
This is valuable for CSOs, media, and anyone concerned about content scraping for AI training.

### Known Bot Map (plugin-side)

Maintained as a static PHP array — no external DB needed. Five categories:

**AI Training / Agents**

| User-Agent pattern | Company |
|---|---|
| `GPTBot`, `ChatGPT-User`, `OAI-SearchBot` | OpenAI |
| `ClaudeBot`, `Claude-Web` | Anthropic |
| `Google-Extended`, `GoogleOther` | Google AI |
| `Gemini` | Google Gemini |
| `Bytespider` | ByteDance |
| `PerplexityBot` | Perplexity |
| `CCBot` | Common Crawl |
| `Amazonbot` | Amazon |
| `Meta-ExternalAgent` | Meta |
| `Applebot-Extended` | Apple |
| `cohere-ai` | Cohere |
| `Diffbot` | Diffbot |

**Search Engines (verified bots)**

| User-Agent pattern | Company |
|---|---|
| `Googlebot` | Google |
| `bingbot` | Microsoft Bing |
| `Slurp` | Yahoo |
| `YandexBot` | Yandex |
| `DuckDuckBot` | DuckDuckGo |
| `Baiduspider` | Baidu |

**SEO / Data Tools**

| User-Agent pattern | Company |
|---|---|
| `AhrefsBot` | Ahrefs |
| `SemrushBot` | Semrush |
| `MJ12bot` | Majestic |
| `DotBot` | Moz |
| `DataForSeoBot` | DataForSEO |

**Social Crawlers**

| User-Agent pattern | Company |
|---|---|
| `facebookexternalhit`, `FacebookBot` | Meta |
| `Twitterbot` | Twitter/X |
| `LinkedInBot` | LinkedIn |
| `TelegramBot` | Telegram |

**Security Scanners**

| User-Agent pattern | Operator |
|---|---|
| `Shodan` | Shodan |
| `censys` | Censys |
| `masscan` | masscan |

### `known_bots_json` + `ai_traffic_json` in snapshots

Two separate histograms added to `wp_baskerville_snapshots`:

```json
"known_bots_json": {
  "search_engines": { "Googlebot": 340, "bingbot": 89 },
  "seo_tools":      { "AhrefsBot": 120, "SemrushBot": 45 },
  "social":         { "facebookexternalhit": 23 },
  "security":       { "Shodan": 8 },
  "ai_training":    { "GPTBot": 234, "ByteDance": 890, "CCBot": 120 }
}
"ai_traffic_json": {
  "OpenAI": 234,
  "ByteDance": 890,
  "CCBot": 120
}
```

`ai_traffic_json` is a flat summary for fast daily rollup aggregation.
`known_bots_json` is the full nested breakdown for LLM context.

### `classifications_json` in snapshots — bot vs human ratio

Aggregated from the `classification` column in `wp_baskerville_stats`:

```json
"classifications_json": {
  "human":     450,
  "bot":       120,
  "bad_bot":   380,
  "borderline": 8
}
```

This is one of the strongest signals for the LLM:
- `45% human / 40% bad_bot / 12% verified bots / 3% AI` → normal day with some attack
- `3% human / 90% bad_bot / 7% other` → active bot attack
- `60% human / 30% AI crawlers / 10% other` → heavy AI scraping day

### AI section in LLM payload

```json
"known_bots": {
  "search_engines": { "Googlebot": 340, "bingbot": 89 },
  "seo_tools":      { "AhrefsBot": 120 },
  "ai_training":    { "OpenAI": 234, "ByteDance": 890, "CCBot": 120 }
},
"known_bots_baseline": {
  "search_engines": { "Googlebot": 110, "bingbot": 30 },
  "ai_training":    { "OpenAI": 8, "ByteDance": 12 }
},
"classifications": {
  "human": 450, "bot": 120, "bad_bot": 380, "borderline": 8
},
"classifications_baseline": {
  "human": 820, "bot": 90, "bad_bot": 40, "borderline": 12
}
```

### LLM prompt additions

The system prompt asks the LLM to produce an `ai_report` section:
- Which AI companies are active on this site
- What content they are targeting (news, blog, API, media)
- Whether crawl rate is within normal parameters or aggressive
- Whether they appear to respect crawl signals (indirect: URL patterns, timing)
- Per-company recommendation: allow / rate-limit / block

### LLM response — `ai_report` field

```json
"ai_report": {
  "companies_detected": ["OpenAI", "ByteDance", "CCBot"],
  "most_aggressive": "ByteDance — 890 requests, 45% of traffic (8× above baseline)",
  "content_targeted": "News articles (/news/*), author pages",
  "assessment": "ByteDance is scraping aggressively. OpenAI within normal range.",
  "recommendations": [
    { "company": "ByteDance", "action": "rate_limit", "limit": "10 req/min" },
    { "company": "CCBot",     "action": "block", "reason": "training data harvesting" }
  ]
}
```

### Always-on (no spike required)

AI bot reporting runs on every snapshot cycle, not just during incidents.
The admin dashboard shows a persistent "AI Traffic" tab with:
- Per-company request counts (last 24h)
- Week-over-week trend
- LLM-generated summary (cached, refreshed daily)

### x402 Monetization angle

When an AI bot is identified, instead of blocking the plugin can return `402 Payment Required`
with an x402 payment header. The AI agent pays per-page in micropayments.

This is the monetization path for CSOs and media organizations:
- Allow AI access but make it paid
- Revenue stream from content that would otherwise be scraped for free
- Configurable per company: block / allow-free / require-payment

Implementation: x402 support is a future roadmap item (V3+), requires payment processor integration.

---

## Session Tracking

The plugin has no native session concept — `wp_baskerville_stats` stores individual requests.
To enable Level 2 LLM analysis, sessions are tracked in a separate table.

### Session Definition

- **Normal session**: grouped by `(ip, baskerville_id)` — cookie identifies the browser
- **Primary session**: `baskerville_id IS NULL` — visitor never returned a cookie
  - Only processed/sent to LLM when `request_count >= 5`
  - If cookie appears later (e.g. on 6th request) → merge into normal session, set `had_primary = 1`

### wp_baskerville_sessions table

```sql
id             BIGINT AUTO_INCREMENT
ip             VARCHAR(45)
baskerville_id VARCHAR(100) NULL      -- NULL = primary session
is_primary     TINYINT(1)             -- 1 = no cookie returned
had_primary    TINYINT(1) DEFAULT 0   -- was primary before cookie arrived
request_count  INT DEFAULT 0
url_sequence   JSON                   -- last 20 URLs: [{url, ts_ms}, ...]
intervals_ms   JSON                   -- computed on DB import from timestamps
avg_score      FLOAT DEFAULT 0
top_factors    JSON                   -- accumulated [{factor, count}, ...]
country_code   VARCHAR(2)
asn            VARCHAR(128)
user_agent     TEXT
started_at     DATETIME
last_seen_at   DATETIME
PRIMARY KEY (id)
UNIQUE KEY session_key (ip, baskerville_id)  -- baskerville_id NULL = primary
KEY last_seen_at (last_seen_at)
KEY is_primary (is_primary)
KEY avg_score (avg_score)
```

### File Buffer → DB Import (Variant 1)

Session data is buffered to file for performance (same pattern as visit stats):

**On each request** → append one JSON line to `sessions-YYYY-MM-DD.log`:
```json
{
  "ip": "1.2.3.4",
  "baskerville_id": "abc123",
  "url": "/about/",
  "ts_ms": 1754567890123,
  "score": 58,
  "top_factor": "webdriver",
  "country_code": "SG",
  "asn": "ALIBABA-US (AS45102)",
  "user_agent": "Mozilla/5.0 ..."
}
```

**Cron every 1 min** → `process_session_log_files()`:
1. Read log lines, group by `(ip, baskerville_id)`
2. Sort each group by `ts_ms`, compute `intervals_ms` as diffs
3. UPSERT into `wp_baskerville_sessions`:
   - Append URLs to `url_sequence` (keep last 20)
   - Append intervals
   - Increment `request_count`
   - Update `avg_score`, `last_seen_at`, `top_factors`
4. Primary session merge: if `baskerville_id` now present but `is_primary` row exists for same IP → merge rows, set `had_primary = 1`

**Session TTL**: 30 minutes of inactivity → session closed.
Cleanup cron runs daily, removes sessions with `last_seen_at < NOW() - 30 MIN` that are already processed.

---

## Two Levels of LLM Analysis

### Level 1 — Cluster / Incident Analysis (async, no latency)

Triggered by traffic or decision spike. Aggregated payload → LLM → incident report + action list. Runs as background cron job, never in the hot path.

### Level 2 — Session-Level Analysis (async, one-visit delay)

For borderline sessions (avg_score 40–70), using data from `wp_baskerville_sessions`.

**Selection criteria for LLM submission:**
- `avg_score BETWEEN 40 AND 70`
- Normal sessions: any `request_count`
- Primary sessions: `request_count >= 5` only (less = not enough signal)
- Not already submitted in last 30 min (debounce per session)

**Grouping strategy — avoid drowning in data:**
Sessions are clustered by `(top_factor, country_code, asn)` before submission.
Top 5 clusters → 1 representative session each → 5 LLM calls per cron cycle max.

**Flow:**
```
Cron every 5 min:
  → Select top 5 borderline session clusters
  → For each: POST /v1/analyze/session → { job_id }
  → Store job_ids in wp_options

Next cron:
  → Poll job results
  → Verdict (block/challenge/allow) stored per (ip, baskerville_id)
  → Applied on next request from that IP via firewall cache
```

**On first visit with borderline score:**
- Show Altcha challenge (buys time while async analysis runs)
- Bots that return get LLM verdict applied immediately from cache

**Session data sent per cluster representative:**
```json
{
  "country": "SG",
  "asn": "ALIBABA-US (AS45102)",
  "user_agent": "Mozilla/5.0 ...",
  "avg_score": 58,
  "request_count": 12,
  "is_primary": false,
  "had_primary": true,
  "url_sequence": [
    { "url": "/", "ts_ms": 0 },
    { "url": "/wp-login.php", "ts_ms": 312 },
    { "url": "/wp-login.php", "ts_ms": 608 }
  ],
  "intervals_ms": [312, 296, 289, 301],
  "interval_cv": 0.02,
  "top_factors": [
    { "factor": "webdriver", "count": 8 },
    { "factor": "http1_protocol", "count": 12 }
  ],
  "cluster_size": 340
}
```

No raw IPs sent. `cluster_size` tells LLM how many sessions this pattern represents.

---

## Natural Language Query Interface

Instead of dashboards and graphs, the admin UI exposes a single text input.
The user types a question in plain language; the plugin aggregates the relevant data and
sends it to the LLM; the result appears as a markdown report inline in the admin panel.

**Examples:**
- "Give me a breakdown of AI companies that crawled my site this week"
- "Were there any interesting incidents last month?"
- "Is ByteDance behaving aggressively compared to last month?"
- "What content are AI crawlers targeting?"

This is not a chatbot — one question, one report. No conversation state.

### Flow

```
Admin UI (text input + submit)
  → AJAX POST to WP REST endpoint
  → build_query_payload(query, timeframe)   ← reads daily rollups
  → POST /v1/query → { job_id }
  → browser polls GET /v1/report/{job_id} every 3 sec
  → result rendered as markdown in admin panel
```

Polling happens in the browser (JavaScript), not via WP Cron — the user sees the result
appear within ~10 seconds without a page reload.

### Why not on-demand from raw data

Snapshots (`wp_baskerville_snapshots`) are retained for only 24 hours.
Querying `wp_baskerville_stats` directly for "last month" is expensive.
Daily rollups solve both problems: cheap reads, arbitrary lookback window.

### wp_baskerville_daily table

One row per day. Written by a nightly cron job (rolls up that day's snapshots before they expire).

```sql
day                DATE         PRIMARY KEY
traffic_total      INT
block_total        INT
challenge_total    INT
unique_ips_avg     INT          -- average across snapshots that day
immature_ratio_avg FLOAT
no_cookie_pct_avg  FLOAT
incident_count     INT
peak_spike_factor  FLOAT        -- highest spike_factor in any incident that day

-- Histograms: summed across all snapshots for the day
countries_json        longtext     -- { "SG": 12400, "US": 890 }
fingerprints_json     longtext
ua_json               longtext
asn_json              longtext
classifications_json  longtext     -- { "human": 45000, "bot": 12000, "bad_bot": 38000, "borderline": 800 }
known_bots_json       longtext     -- { "search_engines": {...}, "ai_training": {...}, "seo_tools": {...} }
ai_traffic_json       longtext     -- { "OpenAI": 1240, "ByteDance": 8900 }
```

Retention: 365 days (configurable). One row = ~2KB → full year = ~700KB.

### Query payload

```json
{
  "license_key": "...",
  "domain": "example.com",
  "question": "Give me a breakdown of AI companies that crawled my site this week",
  "period": "7d",
  "daily_rollups": [
    {
      "day": "2026-08-05",
      "traffic_total": 8420,
      "incident_count": 1,
      "peak_spike_factor": 12.4,
      "ai_traffic": { "OpenAI": 234, "ByteDance": 890 },
      "countries": { "SG": 4200, "US": 890 }
    },
    ...
  ],
  "incidents": [
    { "started_at": "2026-08-07", "spike_type": "traffic", "spike_factor": 12.4,
      "reasoning": "97% traffic from Alibaba Singapore..." }
  ]
}
```

### New backend endpoint

`POST /v1/query` — same async pattern as `/v1/analyze`:
- Accepts `question` + `daily_rollups` + `incidents`
- LLM system prompt: "You are a security analyst. Answer the user's question using site data. Be specific, cite numbers. Format: markdown, 200–400 words."
- Returns `{ job_id }` immediately, result polled via `GET /v1/report/{job_id}`

---

## Watchdog — Daily AI Summary

A short, plain-language summary of what happened on the site in the last 24 hours.
Displayed prominently in the WordPress admin — either as a widget on the main WP Dashboard,
or as a sticky notice at the top of the Baskerville admin page.

**Goal:** the site owner sees at a glance whether anything interesting or unusual happened,
without opening reports or reading graphs.

**Example output:**
> Quiet day overall. ByteDance crawled 3× more than usual — 890 requests vs a 7-day average
> of 290. They targeted mostly /news/* pages. OpenAI was within normal range. No attack
> incidents detected.

> ⚠ Unusual: a traffic spike hit at 14:00 UTC — 1,958 requests in 5 minutes, mostly from
> Singapore (94%). The firewall blocked 847 of them. No repeat since.

### Generation flow

Runs as part of the nightly rollup cron (after daily row is written):

```
1. Read today's wp_baskerville_daily row
2. Read yesterday's row + 7-day average (for comparison)
3. Read any incidents from the last 24h (with their reasoning)
4. POST /v1/watchdog → { job_id }
5. Poll result → save to wp_options('baskerville_watchdog_summary')
6. Also save generated_at timestamp
```

### Watchdog payload (small, cheap)

```json
{
  "license_key": "...",
  "domain": "example.com",
  "today": {
    "traffic_total": 18420,
    "incident_count": 1,
    "peak_spike_factor": 12.4,
    "ai_traffic": { "OpenAI": 234, "ByteDance": 890 },
    "top_countries": { "US": 8400, "SG": 4200 },
    "immature_ratio_avg": 0.14
  },
  "yesterday": {
    "traffic_total": 16200,
    "ai_traffic": { "OpenAI": 230, "ByteDance": 290 },
    "incident_count": 0
  },
  "week_avg": {
    "traffic_total": 15800,
    "ai_traffic": { "OpenAI": 220, "ByteDance": 310 }
  },
  "incidents_today": [
    { "started_at": "14:00 UTC", "spike_type": "traffic", "spike_factor": 12.4,
      "reasoning": "97% from Singapore, Alibaba ASN" }
  ]
}
```

### LLM system prompt for watchdog

> You are a security watchdog for a WordPress site. Write a 2–4 sentence plain-language
> summary of what happened today. Highlight anything unusual compared to yesterday or the
> 7-day average. Mention AI crawlers if their behavior changed significantly.
> Be direct, conversational, no jargon. Start with a one-word status: Quiet / Warning / Alert.

### Storage and display

- Saved to `wp_options('baskerville_watchdog_summary')` — a simple string (markdown, 2–4 sentences)
- Also saved: `baskerville_watchdog_generated_at` (timestamp)
- Displayed in WP admin via `wp_dashboard_setup` hook — a small widget on the main Dashboard
- Also shown as a notice at the top of the Baskerville settings page
- If no summary yet (first day, no license): widget shows "Baskerville AI Watchdog — activate a license to enable daily summaries"
- Refreshed once per day; if LLM call fails, previous summary is kept with a "last updated X ago" note

### Cost

~300 tokens per watchdog call × 365 days = ~$0.02/year per site at GPT-4o-mini pricing. Negligible.

### New backend endpoint

`POST /v1/watchdog` — same async pattern:
- Accepts today/yesterday/week_avg + incidents
- Returns `{ job_id }`, polled via `GET /v1/report/{job_id}`
- Result: `{ summary: "Quiet day. ByteDance crawled 3×..." }`

---

## Daily Rollup

Nightly cron (`baskerville_daily_rollup`, runs at 00:05 UTC):
1. Aggregate all snapshots for yesterday into one `wp_baskerville_daily` row
2. Generate watchdog summary via `/v1/watchdog` → save to `wp_options`
3. Delete snapshots older than 24h

If no snapshots exist for a day (site offline, cron missed) — row is skipped, no gap-filling.

---

## Backend (api.baskerville.ai)

FastAPI on Kubernetes (same cluster as Baskervillehall). LLM provider switchable via `LLM_PROVIDER` env var:
- `openai` (default) — GPT-4o-mini
- `anthropic` — Claude Opus 4.6

### Endpoints

- `POST /v1/analyze` → `{ job_id }` (immediate, LLM runs in background)
- `GET /v1/report/{job_id}` → `{ status: pending|ready|error, actions[], reasoning, report_markdown }`
- `GET /health`

Job TTL: 2 hours. In-memory store (V1), Redis (V2).

---

## LLM Cost Estimate

- Cluster/incident analysis: ~800 tokens per incident → $0.00016 per incident (GPT-4o-mini)
- Session-level analysis: ~400 tokens per borderline session
- Only borderline sessions go to LLM (~5–15% of traffic)
- 1,000 incidents/day + 10,000 sessions/day across all users: ~$1.20/day
- Marginal cost negligible at subscription pricing

---

## Billing

### One API Key, Per-Site Accounting

Single OpenAI/Anthropic key on backend. Token usage logged per license key per day.

### Subscription Tiers

| Plan | Price | Incidents/mo | Sessions/mo |
|---|---|---|---|
| Starter | $9 | 50 | 5,000 |
| Pro | $29 | 500 | 50,000 |
| Agency | $99 | unlimited | unlimited |

### Throttling

- **Cluster analysis** never stops (cheap, high value)
- **Session analysis** pauses at quota limit
- Dashboard notice with usage stats + upgrade prompt

---

## Cross-Site Threat Intelligence (V3)

Aggregated attack data across install base (opt-in):
- Same ASN attacks multiple sites → pre-warn all subscribed sites
- New botnet fingerprint detected on one site → block pushed proactively
- Campaign attribution across targets

---

## User Flow

1. Visit baskerville.ai, subscribe → get license key
2. WordPress admin → Baskerville → Settings → enter license key
3. Done — reports and AI defense activate automatically

---

## Phased Rollout

**V1 — Core (current):**
- License key auth (stub, no billing yet)
- Incident lifecycle: detect → analyze → apply → close
- Actions: block_country, block_asn, block_useragent, raise_threshold
- No-cookie attack mode: auto-detect, Altcha (< 10x spike) or hard 403 (≥ 10x)
- IP overlap with previous incidents (90-day lookback)
- UA analysis via LLM prompt
- Async job system: fire-and-forget POST → job_id, poll every 2 min
- wp_baskerville_incidents + wp_baskerville_reports tables
- Report shown in admin dashboard
- **Session tracking**: wp_baskerville_sessions, file buffer → DB import every 1 min
  - Normal sessions: (ip, baskerville_id)
  - Primary sessions: no cookie, min 5 requests before processing
  - Merge primary → normal when cookie appears, flag had_primary=1
  - 30 min TTL, cap 20 URLs with timestamps, intervals computed on import
- **Level 2 LLM**: borderline sessions (score 40–70), top 5 clusters per cycle
  - Cluster by (top_factor, country_code, asn) → 1 representative per cluster
  - Verdict cached per session, applied on next request

**V2 — Enhanced:**
- Email delivery of incident reports
- Redis job store for persistence across restarts
- Tool calling: backend requests additional SQL from plugin mid-analysis
- Stripe billing integration
- **Daily rollups**: `wp_baskerville_daily` table, nightly cron, 365-day retention
- **Watchdog widget**: 2–4 sentence daily summary on WP Dashboard + Baskerville admin top
  - Generated nightly alongside daily rollup
  - Plain language: "Quiet day" / "Warning" / "Alert" + what changed
  - Highlights AI bot changes, incidents, unusual patterns vs 7-day baseline
  - Stored in `wp_options`, costs ~$0.02/year per site
- **Natural language query interface**: admin text input → `/v1/query` → markdown report in browser
  - Reads daily rollups for arbitrary lookback (week, month, year)
  - Browser-side polling (no WP Cron), result appears in ~10 sec
- **AI Bot Intelligence**: `ai_traffic_json` in snapshots + daily rollups, per-company report
  - Known AI crawler map (OpenAI, Anthropic, Google, ByteDance, Meta, Perplexity, CCBot, ...)
  - Always-on (no spike required), refreshed every snapshot cycle
  - LLM-generated `ai_report`: behavior assessment + per-company recommendations
  - Admin dashboard "AI Traffic" tab with 24h stats and weekly trend

**V3 — Cross-site Intelligence + Monetization:**
- Opt-in aggregated threat sharing across install base
- Pre-warn sites about known attacking ASNs/IPs
- Campaign attribution across targets
- **x402 monetization**: return `402 Payment Required` to identified AI bots instead of blocking
  - Configurable per company: block / allow-free / require-payment
  - Revenue stream for media and CSOs from AI content scraping

**V4 — Self-hosted:**
- Accept any OpenAI-compatible endpoint (Ollama, private LLM)
- No data leaves the server
