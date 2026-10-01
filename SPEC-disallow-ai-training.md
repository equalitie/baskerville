# Spec: AI Bot Access Redesign

**Status:** Draft  
**Priority:** Post-1.0.6  
**Context:** Cloudflare moved to a 3-category model (Search / Training / Agent) on 2026-09-15.
We can't do ML-based classification like they can, but we verify enough companies via rDNS and
published IP ranges to make a meaningful per-company UI. This spec replaces the current
4-mode system (allow_all / block_all / whitelist / blacklist) with a model that maps to how
site owners actually think about AI bots.

---

## Problem

The current 4-mode system is abstract and doesn't help users understand what they're allowing
or blocking. Users think in terms of companies and purposes, not access-control modes.

Additionally:
- No distinction between Training bots (scrape content for model training) and Agent bots
  (act in real-time on behalf of a user) — these are different threat models
- Mixed-use crawlers (Googlebot/Google-Extended) create confusion — blocking "Google" breaks search
- No robots.txt signal for compliant operators who honor it

---

## Verification Coverage

We verify bots from these companies — blocking only applies to verified IPs:

| Company | Method | IP range source | UAs covered |
|---------|--------|-----------------|-------------|
| Google (Search) | rDNS `.googlebot.com` / `.google.com` | — | `Googlebot` |
| Google (AI) | IP ranges JSON | developers.google.com/static/crawling/ipranges/ | `Google-Extended`, `GoogleSpecial`, `GoogleUserTriggered` |
| Microsoft | rDNS `.search.msn.com` | — | `Bingbot` |
| Apple | rDNS + IP ranges JSON | search.developer.apple.com/applebot.json | `Applebot` |
| DuckDuckGo | rDNS + IP ranges JSON | duckduckgo.com/duckassistbot.json | `DuckDuckBot`, `DuckAssistBot` |
| Meta | rDNS `.facebook.com` / `.fbscan.com` + static CIDRs | facebook.com/peering/geofeed | `meta-externalagent`, `meta-externalfetcher` |
| OpenAI | IP ranges JSON | openai.com/gptbot.json, searchbot.json, chatgpt-user.json | `GPTBot`, `OAISearchBot`, `ChatGPT-User` |
| Anthropic | IP ranges JSON | claude.com/crawling/bots.json | `ClaudeBot`, `Claude-SearchBot`, `Claude-User` |
| Amazon | IP ranges JSON | developer.amazon.com/amazonbot/*.json (3 JSONs) | `Amazonbot` (training/search/live) |
| Perplexity | IP ranges JSON | perplexity.ai/perplexitybot.json, perplexity-user.json | `PerplexityBot`, `Perplexity-User` |
| Mistral | IP ranges JSON | mistral.ai/mistralai-index-ips.json, mistralai-user-ips.json | `MistralAI-Index`, `MistralAI-User` |
| Common Crawl | IP ranges JSON | index.commoncrawl.org/ccbot.json | `CCBot` |

**Unverified companies** — UA-only matching, no IP verification. Treated as a single group.

### xAI / Grok — special case

xAI publishes no official IP ranges and no crawler documentation. The UA tokens `xAI-Bot`,
`xAI-SearchBot`, `Grok`, `Grok-DeepSearch` only catch honest declarations — there is no
way to verify them against IP ranges.

In practice, Grok relies primarily on X/Twitter posts, Common Crawl, and Wikipedia rather
than active web crawling, so actual xAI-originated traffic in server logs appears to be
minimal. Webmasters checking their logs typically find nothing identifiable as Grok.

If xAI does crawl directly in the future, **ASN-level blocking** (X/Twitter ASNs) would be
the only reliable mitigation beyond UA matching. Track as future addition.

---

## Bot Categories

Three categories matching Cloudflare's model. "AI Training" replaces Cloudflare's "AI Crawler"
label — more descriptive of actual purpose.

### AI Training — scrape content to develop or refine AI models
| Company | UA | Verified |
|---------|----|----------|
| OpenAI | `GPTBot` | ✓ IP ranges |
| Anthropic | `ClaudeBot`, `anthropic-ai` | ✓ IP ranges |
| Meta | `meta-externalagent`, `meta-webindexer` | ✓ rDNS + CIDRs |
| Google AI | `Google-Extended` | ✓ IP ranges |
| Amazon | `Amazonbot` (training) | ✓ IP ranges |
| Common Crawl | `CCBot` | ✓ IP ranges |
| Bytedance | `Bytespider`, `TikTok Spider` | ✗ |
| Diffbot | `Diffbot` | ✗ |
| xAI | `xAI-Bot`, `Grok`, `Grok-DeepSearch`, `xAI-Web-Crawler` | ✗ (see note) |
| Huawei | `PetalBot` | ✗ |
| Manus | `Manus Bot` | ✗ |
| Novellum | `Novellum AI Crawl` | ✗ |
| ProRata.ai | `ProRataInc` | ✗ |
| Timpi | `Timpibot` | ✗ |

### AI Search — answer user questions using indexed content
| Company | UA | Verified |
|---------|----|----------|
| OpenAI | `OAI-SearchBot` | ✓ IP ranges |
| Anthropic | `Claude-SearchBot` | ✓ IP ranges |
| Perplexity | `PerplexityBot` | ✓ IP ranges |
| Amazon | `Amazonbot` (search) | ✓ IP ranges |
| Mistral | `MistralAI-Index` | ✓ IP ranges |
| Apple | `Applebot` (AI search mode) | ✓ rDNS + IP ranges |
| xAI | `xAI-SearchBot` | ✗ (see note) |

### AI Assistant — act in real-time on behalf of a user
| Company | UA | Verified |
|---------|----|----------|
| OpenAI | `ChatGPT-User` | ✓ IP ranges |
| Anthropic | `Claude-User` | ✓ IP ranges |
| Meta | `meta-externalfetcher` | ✓ rDNS + CIDRs |
| DuckDuckGo | `DuckAssistBot` | ✓ rDNS + IP ranges |
| Amazon | `Amazonbot` (live) | ✓ IP ranges |
| Perplexity | `Perplexity-User` | ✓ IP ranges |
| Mistral | `MistralAI-User` | ✓ IP ranges |
| Anchor | `Anchor Browser` | ✗ |

### Search bots — index content for search engines (never blocked, not in UI)
| Company | UA | Verified |
|---------|----|----------|
| Google | `Googlebot` | ✓ rDNS |
| Microsoft | `Bingbot` | ✓ rDNS |
| DuckDuckGo | `DuckDuckBot` | ✓ rDNS |
| Baidu | `Baiduspider` | ✗ |
| Internet Archive | `archive.org_bot` | ✗ |

Search bots are always allowed — verified ones confirmed safe, blocking breaks search indexing.
They do not appear in the blocking UI.

---

## Proposed UI

Replace the current 4-mode dropdown with per-company toggles grouped by category.

```
[ AI Bot Control ]

AI Training                                           [Block All / Allow All]
──────────────────────────────────────────────────────────────────────────────
☑ OpenAI          GPTBot                        verified ✓
☑ Anthropic       ClaudeBot                     verified ✓
☑ Meta            meta-externalagent            verified ✓
☑ Google AI       Google-Extended               verified ✓
☑ Amazon          Amazonbot                     verified ✓
☑ Common Crawl    CCBot                         verified ✓
☑ Bytedance       Bytespider                    unverified
☑ Diffbot         Diffbot                       unverified
☑ xAI             xAI-Bot, Grok                 unverified ⚠
☑ Huawei          PetalBot                      unverified
...

AI Search                                             [Block All / Allow All]
──────────────────────────────────────────────────────────────────────────────
☑ OpenAI          OAI-SearchBot                 verified ✓
☑ Anthropic       Claude-SearchBot              verified ✓
☑ Perplexity      PerplexityBot                 verified ✓
☑ Amazon          Amazonbot (search)            verified ✓
☑ Mistral         MistralAI-Index               verified ✓
☑ xAI             xAI-SearchBot                 unverified ⚠

AI Assistant                                          [Block All / Allow All]
──────────────────────────────────────────────────────────────────────────────
☑ OpenAI          ChatGPT-User                  verified ✓
☑ Anthropic       Claude-User                   verified ✓
☑ Meta            meta-externalfetcher          verified ✓
☑ DuckDuckGo      DuckAssistBot                 verified ✓
☑ Perplexity      Perplexity-User               verified ✓
☑ Amazon          Amazonbot (live)              verified ✓
☑ Mistral         MistralAI-User                verified ✓

Unknown AI Bots (unverified companies)
──────────────────────────────────────────────────────────────────────────────
● Block  ○ Allow
Bots not in the list above, matched by User-Agent only.
```

- Default: all checkboxes ON (block), Unknown = Block
- "verified ✓" — IP confirmed via rDNS or published IP ranges before blocking
- "unverified" — UA-match only, blocked on UA claim alone

### Removed charts

Two charts currently on the AI Bot Control tab should be removed — redundant given the
per-company toggle table above:

- **AI Bots Hits by Country** — country breakdown belongs in the GeoIP tab, not here
- **Unverified Bot UAs (Spoofers)** — redundant with the "unverified" labels in the table
  and the Unknown AI Bots toggle; adds noise without actionable value

---


## Technical Implementation

### 1. Settings schema

Replace `ai_bot_blocking_mode` / `whitelist_ai_companies` / `blacklist_ai_companies` with:

```php
// baskerville_settings['ai_blocked_companies'] = comma-separated list of company keys
// e.g. 'openai,anthropic,meta,google_ai,amazon,bytedance,ccbot,diffbot,xai'

// baskerville_settings['ai_block_unknown'] = bool (default: true)
```

Company keys map to UA lists in `Baskerville_AI_UA`.

### 2. Firewall logic

```php
// In pre_db_firewall(), replace the 4-mode block with:

$blocked_companies = array_filter(explode(',', $options['ai_blocked_companies'] ?? ''));
$block_unknown     = !isset($options['ai_block_unknown']) || $options['ai_block_unknown'];

if (in_array($cls, ['ai_bot', 'verified_ai_bot', 'ai_bot_unverified'], true)) {
    $company_key = $this->aiua->get_ai_bot_company_key($company); // e.g. 'openai'
    $is_known    = $company_key !== '';

    if ($is_known && in_array($company_key, $blocked_companies, true)) {
        $should_block = true;
        $reason = 'ai-bot-company-blocked';
    } elseif (!$is_known && $block_unknown) {
        $should_block = true;
        $reason = 'ai-bot-unknown-blocked';
    }
}
```

### 3. Migration from 4-mode system

On first load after upgrade, `maybe_upgrade_schema()` converts existing settings:

```php
$old_mode = $options['ai_bot_blocking_mode'] ?? 'allow_all';
if ($old_mode === 'allow_all') {
    $options['ai_blocked_companies'] = '';
    $options['ai_block_unknown']     = false;
} elseif ($old_mode === 'block_all') {
    $options['ai_blocked_companies'] = implode(',', ALL_COMPANY_KEYS);
    $options['ai_block_unknown']     = true;
} elseif ($old_mode === 'blacklist') {
    $options['ai_blocked_companies'] = $options['blacklist_ai_companies'] ?? '';
    $options['ai_block_unknown']     = false;
} elseif ($old_mode === 'whitelist') {
    // invert: block everything NOT in the whitelist
    $allowed  = array_filter(explode(',', $options['whitelist_ai_companies'] ?? ''));
    $options['ai_blocked_companies'] = implode(',', array_diff(ALL_COMPANY_KEYS, $allowed));
    $options['ai_block_unknown']     = true;
}
unset($options['ai_bot_blocking_mode'], $options['whitelist_ai_companies'], $options['blacklist_ai_companies']);
```

---

## Open Questions

1. **Bingbot training UA** — Microsoft ETA 2027. Add to AI Search or AI Training when announced.

2. **OAI-SearchBot default** — block by default or allow? It's a search agent, not training.
   Lean toward: block by default, user can allow.

3. **Applebot in AI Search** — Applebot serves both traditional search and AI search
   (Siri/Spotlight). Block by default or allow? Lean toward: allow (verified, search function).

4. **xAI ASN blocking** — xAI publishes no IP ranges and no crawler docs. UA matching only
   catches honest declarations. In practice xAI traffic in server logs is minimal (they rely
   on Common Crawl and X/Twitter data). If they start active crawling, ASN-level blocking
   would be the only reliable mitigation. Track as future addition.

5. **Amazon three-variant UA** — Amazon publishes separate IP range JSONs for training,
   search, and live/retrieval. Their UA string `Amazonbot` appears the same across all three
   variants in practice. Need to confirm if they use distinct UAs per variant or shared UA.

---

## Changelog entry (when released)

```
= 1.0.7 =
* New: AI Bot Control redesigned — per-company toggles grouped by AI Training / AI Search /
  AI Assistant categories, replacing the abstract 4-mode access system
* New: Verified badge for companies confirmed via rDNS or published IP ranges (OpenAI,
  Anthropic, Meta, Google AI) — no false positives for these
* New: "Unknown AI Bots" global toggle for unverified companies matched by User-Agent only
```
