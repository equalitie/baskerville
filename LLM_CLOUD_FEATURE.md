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
  ├── Detects spike (traffic or decisions)
  ├── Runs pre-aggregated SQL queries
  ├── Builds payload JSON (~10-15KB)
  │
  └── POST https://api.baskerville.ai/v1/analyze
          { license_key, domain, spike_type, spike_factor,
            timeline, top_asns, top_countries, top_urls,
            ua_distribution, unique_ips, fingerprint_signals,
            ip_overlap, no_cookie_pct }
              │
              └── Baskerville backend (FastAPI)
                    ├── Validates license key
                    ├── Calls OpenAI / Anthropic (switchable via LLM_PROVIDER)
                    └── Returns { job_id }  ← immediately, async

Plugin polls GET /v1/report/{job_id} every 2 min
  ├── status: pending → wait
  └── status: ready → { incident_action[], reasoning, report_markdown }
        ├── Apply actions locally (firewall rules, temporary blocks)
        └── Save to wp_baskerville_reports + wp_baskerville_incidents
```

The LLM never connects to the WordPress database. All SQL runs locally in PHP before the request is sent.

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

## Spike Detection

Two independent triggers (either fires an incident):

**Traffic spike** — current 5-min bucket vs average of previous buckets in last 30 min exceeds 3x.

**Decision spike** — blocks + bad_bot classifications spike 3x vs baseline. Fires earlier than traffic spike — the rule engine already sees the attack before raw volume peaks.

Cooldown: 30 minutes between incidents to avoid re-triggering during active attack.

---

## Payload Sent to API

Aggregated statistics only — no raw IPs, no PII:

```json
{
  "license_key": "...",
  "domain": "example.com",
  "spike_type": "traffic | decisions | both",
  "spike_factor": 163.4,
  "unique_ips": 692,
  "no_cookie_pct": 94.2,

  "timeline": [
    { "bucket": "2026-08-07 14:05", "requests": 12 },
    { "bucket": "2026-08-07 14:10", "requests": 1958 }
  ],

  "top_asns": [
    { "asn": "ALIBABA-US (AS45102)", "attack_pct": 97.2, "normal_pct": 0.1 }
  ],

  "top_countries": [
    { "country": "SG", "attack_pct": 99.0, "normal_pct": 0.2 }
  ],

  "top_urls": [
    { "url": "/wp-login.php", "count": 1240 }
  ],

  "ua_distribution": [
    { "user_agent": "Mozilla/5.0 (compatible; MJ12bot/...)", "count": 890 }
  ],

  "fingerprint_signals": {
    "webdriver_pct": 87.3,
    "no_touch_mobile_pct": 76.1,
    "http1_pct": 92.0,
    "lang_mismatch_pct": 45.2,
    "no_webgl_pct": 68.0,
    "top_factors": [
      { "factor": "webdriver", "count": 1240, "percent": 87.3, "avg_score": 78.2 }
    ]
  },

  "ip_overlap": {
    "previous_incidents": 3,
    "overlap_count": 340,
    "overlap_pct": 49.1,
    "last_seen": "2026-07-15"
  }
}
```

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

**V3 — Cross-site Intelligence:**
- Opt-in aggregated threat sharing across install base
- Pre-warn sites about known attacking ASNs/IPs
- Campaign attribution across targets

**V4 — Self-hosted:**
- Accept any OpenAI-compatible endpoint (Ollama, private LLM)
- No data leaves the server
