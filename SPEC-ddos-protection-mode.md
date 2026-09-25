# Spec: DDoS Protection Mode Switch

**Status:** Draft  
**Priority:** Post-1.0.6  
**Context:** Baskerville is being deployed on EQPress which already runs Banjax for DDoS
protection. The team is concerned about duplicate blocking functionality. This spec introduces
a clean separation between DDoS protection (overlaps with Banjax) and bot/access control
(unique to Baskerville), replacing the existing master on/off switch.

---

## Problem

The current "Master Protection" switch turns everything off — including AI Bot Control, GeoIP
blocking, and honeypot — which are unique Baskerville features with no equivalent in Banjax.

On EQPress deployments, operators want to:
- Disable DDoS-style blocking (burst, rate, session score challenges) — Banjax handles this
- Keep bot identity controls active (AI bots, country blocks, honeypot)
- Still collect fingerprint data and see what *would have been* blocked

---

## Two Layers

### Layer 1: Bot & Access Control (always available)
Controls based on **identity** — who the visitor is, not how many requests they're making.

- AI Bot Control (AI Training / AI Search / AI Assistant blocking)
- GeoIP / Country blocking
- Honeypot (identifies and bans AI bots by behavior)
- Fingerprint collection and scoring (always runs)
- Bot classification and logging
- Verified crawler allowlist (Googlebot, Bingbot, etc.)

### Layer 2: DDoS Protection (switchable)
Controls based on **traffic patterns** — rate, burst, session behavior.

- Burst rate limiting (nojs-burst, nonbrowser-ua-burst, fp-burst)
- Primary session scoring → challenge threshold
- CAPTCHA / Gatekeeper challenge for high-score visitors
- `score > threshold → block/challenge` enforcement
- Under Attack mode

**When DDoS Protection is OFF:** fingerprinting and scoring still run, but no
blocks or challenges are issued based on score. Banjax handles rate/burst protection.

---

## Shadow Mode

When DDoS Protection is OFF, the UI shows what *would have* happened:

- Live Feed: high-score visits tagged **[would challenge]** / **[would block]**
- Stats dashboard: counter "X requests would have been challenged today"
- Admin notice: "DDoS Protection is OFF — 47 high-score requests would have been challenged
  in the last 24h. [Enable DDoS Protection]"

This serves two purposes:
1. **Visibility** — operator sees real threat level without active blocking
2. **Onboarding** — new sites run in shadow mode first, verify no false positives,
   then enable DDoS Protection with confidence

---

## UI

Replace the current "Master Protection" toggle with two separate controls:

```
[ General Settings ]

Bot & Access Control                                  [ON / OFF]
AI Bot Control, GeoIP blocking, Honeypot, Fingerprinting.
Turning this off disables all Baskerville protection.

DDoS Protection                                       [ON / OFF]
Burst rate limiting, session scoring, CAPTCHA challenges.
Disable when another system (e.g. Banjax) handles DDoS protection.
When OFF, high-score traffic is logged but not blocked — shown as
"would block" in Live Feed and Stats.
```

Default:
- Bot & Access Control: ON
- DDoS Protection: ON

On EQPress deployments, installer detects Deflect presence via `X-Deflect-Country-Code`
header and automatically sets `ddos_protection_enabled = false`, then shows an admin notice:
"Deflect detected — DDoS Protection has been automatically disabled. Burst rate limiting
and challenge features are handled by Deflect. AI Bot Control, GeoIP, and Honeypot remain
active."

---

## Technical Implementation

### 1. Settings

```php
// Replaces 'master_protection_enabled'
// baskerville_settings['bot_access_control_enabled'] = bool (default: true)
// baskerville_settings['ddos_protection_enabled']    = bool (default: true)
```

### 2. Firewall logic

```php
$bot_control_enabled = !isset($options['bot_access_control_enabled'])
    || $options['bot_access_control_enabled'];
$ddos_enabled = !isset($options['ddos_protection_enabled'])
    || $options['ddos_protection_enabled'];

// Always run: fingerprinting, scoring, classification, logging
$evaluation     = $this->aiua->baskerville_score_fp(...);
$classification = $this->aiua->classify_client(...);

// Bot & Access Control gates (identity-based)
if ($bot_control_enabled) {
    // AI bot blocking
    // GeoIP blocking
    // Honeypot ban enforcement
    // Verified crawler allowlist
}

// DDoS Protection gates (pattern-based)
if ($ddos_enabled) {
    // Burst counters → block
    // Score threshold → challenge
    // Under Attack mode
} else {
    // Shadow mode: log "would_block" / "would_challenge" without acting
    if ($score >= $challenge_threshold) {
        $this->stats->log_shadow_action($ip, 'would_challenge', $score);
    }
}
```

### 3. Shadow mode logging

Add `shadow_action` field to visit stats:
- `null` — normal (DDoS protection on, or score below threshold)
- `'would_challenge'` — score above challenge threshold, DDoS protection off
- `'would_block'` — score above block threshold, DDoS protection off

Live Feed query adds these to results with distinct styling.
Stats dashboard aggregates daily count.

### 4. Migration from master switch

`maybe_upgrade_schema()`:
```php
if (isset($options['master_protection_enabled'])) {
    $options['bot_access_control_enabled'] = $options['master_protection_enabled'];
    $options['ddos_protection_enabled']    = $options['master_protection_enabled'];
    unset($options['master_protection_enabled']);
}
```

---

## Open Questions

1. **Honeypot placement** — honeypot bans by identity (AI bot), but the ban itself is
   blocking behavior. Should honeypot banning be gated on DDoS Protection or Bot & Access
   Control? Lean toward: Bot & Access Control — it's identity-based.

2. **Challenge-mode only** — should there be a third state: "Challenge but don't block"?
   Useful for sites that want Gatekeeper CAPTCHA but not hard blocks. Separate concern,
   out of scope for this spec.

3. **Deflect auto-detection** — detection via `X-Deflect-Country-Code` header is reliable
   on EQPress. Auto-disable is the right behavior (not just a suggestion). The admin notice
   should be dismissible but persistent until dismissed — operator must acknowledge.

---

## Changelog entry (when released)

```
= 1.0.7 =
* New: Separate "DDoS Protection" switch — disable burst/rate/challenge blocking when
  another system (Banjax, Cloudflare) handles DDoS, while keeping AI Bot Control,
  GeoIP, and Honeypot active
* New: Shadow mode — when DDoS Protection is OFF, high-score requests are logged as
  "would challenge / would block" in Live Feed and Stats dashboard
* Change: "Master Protection" switch replaced by Bot & Access Control + DDoS Protection
  switches; existing settings migrated automatically
```
