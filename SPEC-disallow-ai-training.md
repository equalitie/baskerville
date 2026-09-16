# Spec: Disallow AI Training

**Status:** Draft  
**Priority:** Post-1.0.6  
**Context:** Cloudflare announced "Disallow AI Training" on 2026-09-15 — a setting that lets site owners signal no-training preference via robots.txt while staying indexed for search. Apple, Google, and Microsoft committed to honoring it. We already block training crawlers; this adds the robots.txt signal layer and surfacing in the UI.

---

## Problem

Site owners who use Baskerville's AI bot blocking today face the same tradeoff Cloudflare identified:

- Blocking `Googlebot` stops both search indexing AND training. Most owners don't want that.
- NOT blocking `Googlebot` means accepting training. Many owners don't want that either.
- Mixed-use crawlers (Googlebot, Bingbot, Applebot) serve both purposes from the same IP ranges and UA strings. You can't distinguish them at the network level.

The solution: Google, Apple, and Microsoft publish **separate training-specific user-agents** (`Google-Extended`, `Applebot-Extended`) that they've committed to honor in robots.txt. Block those → training stops. Main crawler keeps going → search continues.

For training-only crawlers (OpenAI GPTBot, Anthropic, Meta, Amazon) the situation is simpler — blocking them has zero search impact.

---

## Proposed Solution

Two complementary layers:

1. **robots.txt signal** — `Disallow: /` for training-specific UAs, written once, honored by compliant operators without needing active blocking
2. **Active blocking** — already exists in AI Bot Control; needs to be linked to the new UI concept so the user understands the full picture

---

## Crawler Classification

### Mixed-use crawlers — search + training from same bot

| Operator | Search UA | Training UA | robots.txt key |
|----------|-----------|-------------|----------------|
| Google   | `Googlebot` | `Google-Extended` | `Google-Extended` |
| Apple    | `Applebot` | `Applebot-Extended` | `Applebot-Extended` |
| Microsoft | `Bingbot` | (in progress, ETA early 2027) | not yet |

For these: disallow the `*-Extended` UA in robots.txt, leave the main UA alone.

### Training-only crawlers — no search function

| Operator | UA | Block impact on search |
|----------|----|------------------------|
| OpenAI   | `GPTBot` | none |
| Anthropic | `anthropic-ai`, `ClaudeBot` | none |
| Meta | `meta-externalagent` | none |
| Amazon | `Amazonbot` | none |
| Bytedance | `Bytespider` | none |
| Diffbot | `Diffbot` | none |
| Common Crawl | `CCBot` | none |

For these: disallow in robots.txt AND block by IP (already have IP ranges in `Baskerville_AI_UA`).

---

## UI Changes

### Where does this live?

**Option A:** New top-level toggle in AI Bot Control tab — "Disallow AI Training"
- Sits above the per-provider table
- One click covers all training UAs
- Per-provider overrides still possible below

**Option B:** New dedicated tab "AI Training"
- Cleaner separation from "AI Bot Access" (which is about access control, not training preference)
- More room to explain the nuance (robots.txt vs blocking)
- Easier to add AI Summary controls later (Cloudflare's next step)

**Recommendation: Option B** — separate tab. The audience for "I want to block scrapers" vs "I want to control AI training" is subtly different. Option B also leaves room for the summary/snippet controls that will matter next.

### Tab: "AI Training"

```
[ AI Training ]

Disallow AI Training                                    [ON/OFF toggle]

When ON, Baskerville adds Disallow directives to your robots.txt for
training-specific crawlers. Compliant operators (Google, Apple) will stop
using your content for model training while continuing to index you for search.
Non-compliant crawlers are blocked regardless.

───────────────────────────────────────────────────────────────────────
robots.txt signal            Active blocking
───────────────────────────────────────────────────────────────────────
Google-Extended      ✓ Disallow    —
Applebot-Extended    ✓ Disallow    —
Bingbot              (pending — Microsoft ETA 2027)
GPTBot               ✓ Disallow    ✓ Blocked
anthropic-ai         ✓ Disallow    ✓ Blocked
ClaudeBot            ✓ Disallow    ✓ Blocked
meta-externalagent   ✓ Disallow    ✓ Blocked
Amazonbot            ✓ Disallow    ✓ Blocked
Bytespider           ✓ Disallow    ✓ Blocked
CCBot                ✓ Disallow    ✓ Blocked
───────────────────────────────────────────────────────────────────────

Note: Active blocking follows your AI Bot Control settings. Training
crawlers that ignore robots.txt are blocked by IP range verification.
```

---

## Technical Implementation

### 1. Setting

```php
// baskerville_settings['disallow_ai_training'] = bool (default: false)
```

In `sanitize_settings()`:
```php
$sanitized['disallow_ai_training'] = isset($input['disallow_ai_training'])
    ? (bool) $input['disallow_ai_training']
    : (isset($existing['disallow_ai_training']) ? $existing['disallow_ai_training'] : false);
```

### 2. robots.txt — write a physical file (primary approach)

When the setting is enabled, Baskerville writes a physical `robots.txt` to the webroot using
`WP_Filesystem`. This is better than the WordPress `robots_txt` filter because:

- nginx/Apache serves the file directly — no PHP overhead per request
- Works correctly behind Deflect and other CDNs that cache static files
- No dependency on whether the request reaches WordPress

**Write on settings save** (hook on `update_option`):

```php
add_action('update_option_baskerville_settings', function($old, $new) {
    $manager = new Baskerville_Robots_Manager();
    if (!empty($new['disallow_ai_training'])) {
        $manager->write_robots_txt();
    } else {
        $manager->remove_baskerville_block();
    }
}, 10, 2);
```

**`Baskerville_Robots_Manager` class** (new file `includes/class-baskerville-robots.php`):

```php
class Baskerville_Robots_Manager {

    const MARKER_BEGIN = '# BEGIN Baskerville AI Training';
    const MARKER_END   = '# END Baskerville AI Training';

    private static function training_uas(): array {
        return [
            // Mixed-use: training-specific sub-agents (search UA unaffected)
            'Google-Extended',
            'Applebot-Extended',
            // Training-only (no search impact)
            'GPTBot',
            'anthropic-ai',
            'ClaudeBot',
            'meta-externalagent',
            'Amazonbot',
            'Bytespider',
            'Diffbot',
            'CCBot',
            'omgili',
            'Omgilibot',
            'xAI-Bot',
            'JinaBot',
            'DeepSeekBot',
        ];
    }

    private function build_block(): string {
        $lines = [ self::MARKER_BEGIN ];
        foreach (self::training_uas() as $ua) {
            $lines[] = "User-agent: {$ua}";
        }
        $lines[] = 'Disallow: /';
        $lines[] = '';
        $lines[] = self::MARKER_END;
        return implode("\n", $lines) . "\n";
    }

    public function write_robots_txt(): bool {
        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        $path    = ABSPATH . 'robots.txt';
        $current = $wp_filesystem->exists($path) ? $wp_filesystem->get_contents($path) : '';

        // Remove any existing Baskerville block, then append fresh one
        $stripped = $this->strip_block($current);
        $updated  = rtrim($stripped) . "\n\n" . $this->build_block();

        return $wp_filesystem->put_contents($path, $updated, FS_CHMOD_FILE);
    }

    public function remove_baskerville_block(): bool {
        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        $path = ABSPATH . 'robots.txt';
        if (!$wp_filesystem->exists($path)) return true;

        $current = $wp_filesystem->get_contents($path);
        $stripped = $this->strip_block($current);

        // If nothing left but whitespace, delete the file entirely
        if (trim($stripped) === '') {
            return $wp_filesystem->delete($path);
        }
        return $wp_filesystem->put_contents($path, $stripped, FS_CHMOD_FILE);
    }

    private function strip_block(string $content): string {
        $pattern = '/' . preg_quote(self::MARKER_BEGIN, '/') . '.*?' . preg_quote(self::MARKER_END, '/') . '\n?/s';
        return preg_replace($pattern, '', $content);
    }

    public function can_write(): bool {
        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        $path = ABSPATH . 'robots.txt';
        // Can write if file doesn't exist yet (directory writable) or file is writable
        return $wp_filesystem->is_writable(ABSPATH) || $wp_filesystem->is_writable($path);
    }
}
```

**On plugin deactivation** — remove the Baskerville block from robots.txt (or delete the file if
it only contained our block).

### 3. Fallback: `robots_txt` WordPress filter

If `WP_Filesystem` cannot write to ABSPATH (hardened server, incorrect permissions), fall back to
the WordPress dynamic filter. Show an admin notice explaining the limitation.

```php
// In write_robots_txt() — if put_contents() fails:
// fall back to filter, set transient 'baskerville_robots_write_failed'

add_filter('robots_txt', function($output, $public) {
    if (!$public) return $output;
    $options = get_option('baskerville_settings', []);
    if (empty($options['disallow_ai_training'])) return $output;
    // Only used as fallback when physical file write failed
    if (!get_transient('baskerville_robots_write_failed')) return $output;

    $output .= "\n" . (new Baskerville_Robots_Manager())->build_block_string();
    return $output;
}, 10, 2);
```

**Fallback limitation:** WordPress only calls `robots_txt` filter when `blog_public = 1` and there
is no physical `robots.txt` at the webroot. On cached Deflect/nginx sites, the dynamically
generated robots.txt may itself be cached, so the filter runs only on cache miss. For production
deployments behind a CDN, the physical file approach is strongly preferred.

### 4. AI Bot Control integration

The AI Bot Control per-provider table already handles blocking for training-only crawlers. The new tab needs to:
- Read the current block state for each training crawler from the existing AI bot settings
- Show it as "Active blocking: ✓ / ✗" in the table (read-only in this tab)
- Link to AI Bot Control tab for changes

No duplication of settings. The AI Training tab is a **view + robots.txt toggle**, not a second blocking control.

### 5. New user-agents to add to `Baskerville_AI_UA`

Check which of these are missing from `$this->known_ai_bots` in `class-baskerville-ai-ua.php`:
- `Google-Extended` (training variant of Googlebot — should be handled separately from Googlebot)
- `Applebot-Extended` (training variant of Applebot)
- `OAI-SearchBot` (OpenAI's search agent, separate from GPTBot)
- `DataForSeoBot`
- `ImagesiftBot`

---

## Edge Cases

### What if user blocks Googlebot entirely in AI Bot Control?
`Disallow AI Training` adds a disallow for `Google-Extended`. The user's block on `Googlebot` is a separate, stronger action that's their explicit choice. Don't override it, don't warn about it — they know what they're doing.

### What if user enables "Disallow AI Training" but NOT blocking?
That's a valid choice. Some users prefer the soft signal (robots.txt) without hard blocking. Especially for Google-Extended and Applebot-Extended where the operator has committed to honoring it. The UI should make it clear this is the distinction.

### What if filesystem write fails?
Fall back to `robots_txt` WordPress filter (see §3 above). Show admin notice:
"Could not write robots.txt — using WordPress filter as fallback. This may not work correctly
behind a CDN cache. Check file permissions on ABSPATH."

### What if a physical robots.txt already exists with custom content?
`strip_block()` + re-append preserves existing content. Only the `# BEGIN/END Baskerville` block
is replaced. Manual entries above/below our block are untouched.

### What about the `X-Robots-Tag` header?
robots.txt is per-domain. `X-Robots-Tag: noai, noimageai` can be per-page. Future addition —
see AI Summaries section below. Not in scope for this spec.

### What if `blog_public` = 0 (Search engine visibility OFF)?
The physical file approach works regardless of `blog_public`. However, if a site is hiding from
search engines, writing training disallows is moot — add a notice: "Your site has Search Engine
Visibility disabled. Disallow AI Training has no effect while search indexing is off."

---

## AI Summary Controls (Future — not in scope now)

Cloudflare's stated next step: let site owners control **how much** content appears in AI summaries, not just yes/no. This will involve:
- `X-Robots-Tag: nosnippet` / `max-snippet` per page
- Possibly new directives as `ai-prefs` IETF standard matures
- Per-page controls (not just domain-level)

Baskerville could add this as a second section in the AI Training tab. Placeholder for now.

---

## Open Questions

1. **Should blocking follow robots.txt automatically?** If user enables "Disallow AI Training", should we also auto-enable blocking for training-only crawlers (GPTBot, etc.)? Or keep them decoupled?
   - Argument for auto-block: robots.txt alone is not enforcement; completes the intent
   - Argument against: user may want signal-only; AI Bot Control is the explicit blocking UI
   - **Lean toward:** show a notice "For training-only crawlers that may ignore robots.txt, enable blocking in AI Bot Control" — let user decide

2. **Bingbot:** Microsoft committed to honoring a robots.txt directive by early 2027. We don't know the UA yet. Do we add a placeholder entry now or wait until it's confirmed?
   - **Lean toward:** wait; wrong UA in robots.txt is noise

3. **OAI-SearchBot:** OpenAI's new search agent is separate from GPTBot and may be legitimate (search, not training). Should it be in the disallow list?
   - **Lean toward:** exclude from AI Training disallow; it's in a different category
   - Track separately in AI Bot Control

4. **Tab name:** "AI Training" vs "Training Controls" vs "Content Use"?

---

## Changelog entry (when released)

```
= 1.0.7 =
* New: Disallow AI Training — one-click setting writes Disallow directives to robots.txt
  for Google-Extended, Applebot-Extended, GPTBot, Anthropic, Meta, Amazon, xAI, Jina,
  and other training crawlers; keeps search indexing (Googlebot, Bingbot, Applebot) intact
* New: AI Training tab in Baskerville settings with per-crawler status table showing
  robots.txt signal and active blocking status side by side
* New: Physical robots.txt written via WP_Filesystem for CDN/cache compatibility;
  falls back to WordPress robots_txt filter with admin notice if file write fails
* New: Baskerville block cleanly removed from robots.txt on plugin deactivation
```
