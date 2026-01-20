=== Baskerville ===
Contributors: equalitie
Tags: security, firewall, bot detection, geoip, turnstile, captcha, anti-bot, spam protection
Requires at least: 6.2
Tested up to: 6.9
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPL v3

Advanced WordPress security plugin with AI-powered bot detection, GeoIP access control, and Cloudflare Turnstile integration.

== Description ==

Baskerville is a comprehensive WordPress security plugin that protects your site from malicious bots, AI crawlers, and unwanted traffic using multiple detection methods.

**Key Features:**

* **AI-Powered Bot Detection** - Intelligent classification of bots vs. humans with configurable score thresholds
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

== Changelog ==

= 1.0.0 =
* Initial release
* AI-powered bot detection and classification
* GeoIP-based access control (whitelist/blacklist)
* Cloudflare Turnstile integration with precision analytics
* Browser fingerprinting (Canvas, WebGL, Audio)
* Honeypot detection for AI crawlers
* Real-time traffic analytics and live feed
* Under Attack Mode
* IP whitelist
* Form protection (login, registration, comments)
* Configurable instant ban threshold
* Ban all detected bots option