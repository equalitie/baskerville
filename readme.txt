=== Baskerville AI Security ===
Contributors: equalitie, burdianov, mazhurin
Tags: security, captcha, spam protection, firewall, anti-bot
Requires at least: 6.2
Tested up to: 7.0
Stable tag: 1.0.5
Requires PHP: 7.4
License: GPL v3

Advanced WordPress security plugin with AI bot detection, GeoIP access control, CAPTCHA challenge, and optional AI cloud analysis.

== Description ==

Baskerville is a comprehensive WordPress security plugin that protects your site from malicious bots, AI crawlers, and unwanted traffic using multiple detection methods.

**Key Features:**

* **AI Bot Detection** - Browser fingerprint scoring (Canvas, WebGL, Audio) assigns every visitor a risk score 0–100
* **AI Spoofer Detection** - Catches bots faking legitimate AI crawler identities (GPTBot, ClaudeBot, etc.) by verifying IP ranges against published ASN data
* **GeoIP Access Control** - Block or allow traffic by country, built-in GeoIP with no external API required
* **CAPTCHA Challenge** - Altcha (built-in, no account needed) or Cloudflare Turnstile (optional)
* **Per-Provider AI Bot Rules** - Allow, challenge, or block by AI company (OpenAI, Meta, Google, and others)
* **Honeypot Detection** - Hidden links to catch automated crawlers
* **Live Traffic Feed** - Every request, score, classification, and decision in real time
* **High-Risk Page Protection** - Login, registration, and comment pages hardened automatically
* **Under Attack Mode** - Emergency mode to challenge all visitors
* **IP Whitelist** - Trusted IPs always bypass all enforcement
* **Near-Zero Latency** - Firewall runs from local cache (~1ms with page cache active), no outbound calls on request path
* **AI Cloud Analysis** (optional, paid) - Nightly watchdog report and natural language query interface powered by LLM

**Bot Score System:**

* 0-39: Likely human (allowed)
* 40-70: Borderline (optional Turnstile challenge)
* 71-100: Likely bot (blocked)

**Performance:**

* Minimal overhead (~1ms with page cache, ~30-50ms without)
* APCu + file-based caching for GeoIP lookups
* Compatible with all major caching plugins

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/baskerville/` or install via WordPress admin
2. Activate the plugin through the 'Plugins' menu
3. Go to Settings > Baskerville to configure
4. Install MaxMind GeoLite2 database for GeoIP features (one-click installer in Settings)
5. (Optional) Configure Cloudflare Turnstile keys for CAPTCHA challenges

== Frequently Asked Questions ==

= How do I set up GeoIP blocking? =

Go to Settings > Baskerville > GeoIP, install the MaxMind database, then configure your country whitelist or blacklist.

= How does Turnstile work? =

Visitors with borderline bot scores (default 40-70) are shown a Cloudflare Turnstile challenge. If they pass, they're allowed through. This catches bots while minimizing friction for real users.

= What is Under Attack Mode? =

Emergency mode that shows Turnstile challenge to ALL visitors. Use this when your site is under active attack.

= Will this slow down my site? =

With page caching enabled, overhead is near zero. Without caching, expect ~30-50ms overhead per request.

== External Services ==

This plugin connects to the following third-party services:

= Cloudflare Turnstile =

When Turnstile is enabled, the plugin loads JavaScript from Cloudflare's servers to display CAPTCHA challenges:

* Service URL: https://challenges.cloudflare.com/turnstile/v0/api.js
* Verification API: https://challenges.cloudflare.com/turnstile/v0/siteverify
* Data sent: Turnstile token, visitor IP address
* Purpose: Human verification to prevent bot access
* Privacy Policy: https://www.cloudflare.com/privacypolicy/
* Terms of Service: https://www.cloudflare.com/website-terms/

Turnstile is only loaded when you enable it in plugin settings and provide your Cloudflare API keys.

= MaxMind GeoIP Database =

When you use the one-click GeoIP database installer, the plugin downloads the GeoLite2-Country database from MaxMind:

* Database download URL: https://download.maxmind.com/
* Data sent: Your MaxMind license key (required for database download)
* Purpose: Determine visitor country for geo-blocking features
* Privacy Policy: https://www.maxmind.com/en/privacy-policy
* Terms of Service: https://www.maxmind.com/en/geolite2/eula

The installer also downloads the MaxMind PHP libraries from GitHub:

* GeoIP2 PHP API: https://github.com/maxmind/GeoIP2-php/archive/refs/tags/v2.13.0.zip
* MaxMind DB Reader: https://github.com/maxmind/MaxMind-DB-Reader-php/archive/refs/tags/v1.11.1.zip
* These are open-source libraries used to read the local GeoIP database. No visitor data is sent to GitHub.
* GitHub Terms of Service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
* GitHub Privacy Statement: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement

The database is stored locally on your server. No visitor data is sent to MaxMind during lookups.

== Privacy ==

= Data Collected =

This plugin collects and stores the following visitor data locally in your WordPress database:

* IP addresses
* Browser fingerprints (Canvas, WebGL, Audio hashes)
* User agent strings
* Country codes (derived from IP)
* Bot scores and classifications
* Timestamps of visits

= Data Retention =

Statistics are automatically deleted after the retention period you configure (default: 14 days). You can adjust this in Settings > Baskerville > Settings.

= GDPR Compliance =

* All data is stored locally on your server
* No visitor data is shared with third parties (except Cloudflare when Turnstile verification occurs)
* Data retention is configurable
* Consider adding disclosure to your site's privacy policy

== Changelog ==
= 1.0.5 =
* AI Cloud integration: nightly AI Watchdog report in WordPress dashboard
* AI query interface: ask questions about your traffic in plain English
* Cloud action enforcement: LLM agent can now block by country and user agent automatically
* Token usage tracking: see monthly AI token consumption in admin panel
* Quick question chips in AI panel for one-click queries
* Fix: wpsec_log() was undefined causing silent PHP fatal error in WP Cron, preventing nightly watchdog from running
* Fix: double watchdog job submission on first run after midnight

= 1.0.4 =
* Altcha PoW challenge support — self-hosted, privacy-friendly, works out of the box
* Altcha widget on login, registration and comment forms
* Login form protection stats in Analytics dashboard
* AI crawlers IP verification via published IP ranges and reverse DNS
* AI spoofers detection — crawlers pretending to be legitimate AI bots with mismatched IP
* Expanded AI company coverage
* Fix: Meta crawlers (meta-externalagent) incorrectly flagged as spoofers on IPs without PTR records
* Fix: Master switch OFF now correctly disables all blocking including honeypot and form challenges

= 1.0.3 =
* Deflect GEO IP support
* JS burst counter fix (static files excluded)

= 1.0.2 =
* Replaced hardcoded Ajax/REST paths with wp_doing_ajax(), REST_REQUEST and rest_get_url_prefix().
* Replaced direct require_once of class-pclzip.php with WordPress unzip_file() API.
* Replaced WP_CONTENT_DIR usage with wp_upload_dir() for GeoIP database paths.
* Changed REST /fp permission_callback to __return_true (intentionally public endpoint).
* Made nonce validation mandatory in REST fingerprint handler (fail-early on missing nonce).
* Added nonce and current_user_can('manage_options') checks to debug widget toggle.
* Removed DONOTCACHEPAGE global constant definition.
* Removed unsanitized $_COOKIE processing from debug headers; now checks only specific plugin cookies.
* Documented MaxMind GitHub library downloads in readme External Services section.
* Removed external URL from test User-Agent strings.

= 1.0.1 =
* Added support for the Deflect GeoIP database.
* Made all hardcoded text fully translatable.
* Renamed the plugin to Baskerville AI Security.
* Moved all inline scripts and styles to proper wp_enqueue_script() / wp_enqueue_style() usage.
* Updated Chart.js to v4.5.1.

= 1.0.0 =
Initial release.