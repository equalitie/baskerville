=== Baskerville AI Security ===
Contributors: equalitie
Tags: security, captcha, spam protection, firewall, anti-bot
Requires at least: 6.2
Tested up to: 6.9
Stable tag: 1.0.2
Requires PHP: 7.4
License: GPL v3

Advanced WordPress security plugin with AI bot detection, GeoIP access control, and Cloudflare Turnstile integration.

== Description ==

Baskerville is a comprehensive WordPress security plugin that protects your site from malicious bots, AI crawlers, and unwanted traffic using multiple detection methods.

**Key Features:**

* **AI Bot Detection** - Intelligent classification of bots vs. humans with configurable score thresholds
* **GeoIP Access Control** - Block or allow traffic by country (whitelist/blacklist modes)
* **Cloudflare Turnstile** - CAPTCHA challenge for borderline bot scores with precision analytics
* **Browser Fingerprinting** - Advanced client-side fingerprinting (Canvas, WebGL, Audio)
* **Honeypot Detection** - Hidden links to catch AI crawlers
* **Real-Time Analytics** - Live feed, traffic statistics, and Turnstile precision metrics
* **Under Attack Mode** - Emergency mode to challenge all visitors during attacks
* **IP Whitelist** - Bypass firewall for trusted IPs
* **Form Protection** - Protect login, registration, and comment forms with Turnstile

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