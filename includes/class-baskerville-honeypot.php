<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Honeypot {

    /** @var Baskerville_Core */
    private $core;

    /** @var Baskerville_Stats */
    private $stats;

    /** @var Baskerville_AI_UA */
    private $aiua;

    public function __construct(Baskerville_Core $core, Baskerville_Stats $stats, Baskerville_AI_UA $aiua) {
        $this->core  = $core;
        $this->stats = $stats;
        $this->aiua  = $aiua;
    }

    /**
     * Initialize honeypot functionality
     */
    public function init() {
        // Add virtual page route
        add_action('init', [$this, 'register_honeypot_route']);

        // Whitelist query var
        add_filter('query_vars', [$this, 'add_query_vars']);

        // Inject hidden link into footer
        add_action('wp_footer', [$this, 'inject_hidden_link'], 999);

        // Handle honeypot page visit
        add_action('template_redirect', [$this, 'handle_honeypot_visit'], -1000);
    }

    /**
     * Add query var to WordPress whitelist
     */
    public function add_query_vars($vars) {
        $vars[] = 'baskerville_honeypot';
        return $vars;
    }

    /**
     * Register virtual honeypot page route
     */
    public function register_honeypot_route() {
        add_rewrite_rule(
            '^ai-training-data/?$',
            'index.php?baskerville_honeypot=1',
            'top'
        );
    }

    /**
     * Handle honeypot page visit - mark IP as AI bot immediately
     */
    public function handle_honeypot_visit() {
        if (!get_query_var('baskerville_honeypot')) {
            return;
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        if (!$ip) {
            return;
        }

        // error_log("Baskerville Honeypot: Visit detected from IP $ip");

        // Skip whitelisted IPs
        if ($this->core->is_whitelisted_ip($ip)) {
            // error_log("Baskerville Honeypot: IP $ip is whitelisted, skipping ban");
            $this->render_honeypot_page();
            exit;
        }

        $ua = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $headers = [
            'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
            'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
            'user_agent'      => $ua,
            'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
            'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
        ];

        // Evaluate and classify
        $evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
        $classification = [
            'classification' => 'ai_bot',
            'reason'         => 'Honeypot triggered: accessed hidden link',
            'risk_score'     => 100,
            'details'        => [
                'honeypot'   => true,
                'page'       => 'ai-training-data',
                'user_agent' => substr($ua, 0, 200)
            ]
        ];

        // Force high score for honeypot triggers
        $evaluation['score'] = 100;
        $evaluation['reasons'][] = 'honeypot-triggered';

        // Get ban settings to determine block_reason
        $options = get_option('baskerville_settings', array());
        $ban_enabled = isset($options['ban_bots_403']) ? (bool)$options['ban_bots_403'] : true;
        $honeypot_ban_enabled = isset($options['honeypot_ban']) ? (bool)$options['honeypot_ban'] : true;
        $block_reason = ($ban_enabled && $honeypot_ban_enabled) ? 'honeypot-triggered' : null;

        // Log as AI bot
        $cookie_id = $this->core->get_cookie_id();
        $result = $this->stats->save_visit_stats(
            $ip,
            $cookie_id ?? '',
            $evaluation,
            $classification,
            $ua,
            'honeypot',
            null,
            $block_reason
        );

        // error_log("Baskerville Honeypot: Saved to DB for IP $ip, result: " . ($result ? 'SUCCESS' : 'FAILED'));

        // Mark IP with long-term cache flag (24 hours)
        $this->core->fc_set("honeypot_caught:{$ip}", 1, 86400);

        // Log to error log for monitoring
        // error_log(sprintf(
        //     'Baskerville Honeypot: AI bot detected from IP %s | UA: %s',
        //     $ip,
        //     substr($ua, 0, 100)
        // ));

        // Ban if enabled (default: 24 hours)
        if ($ban_enabled && $honeypot_ban_enabled) {
            $ban_ttl = (int)get_option('baskerville_honeypot_ban_ttl', 86400); // 24 hours default
            $this->core->fc_set("ban:{$ip}", [
                'reason' => 'honeypot',
                'score'  => 100,
                'cls'    => 'ai_bot',
                'until'  => time() + $ban_ttl,
            ], $ban_ttl);

            // error_log("Baskerville Honeypot: BANNED IP $ip for {$ban_ttl} seconds (honeypot-triggered)");

            // Send 403 response
            status_header(403);
            nocache_headers();
            echo "<!DOCTYPE html>\n<html>\n<head>\n<title>403 Forbidden</title>\n</head>\n<body>\n";
            echo "<h1>403 Forbidden</h1>\n";
            echo "<p>Access denied. Automated bot detected.</p>\n";
            echo "</body>\n</html>";
            exit;
        } else {
            // error_log("Baskerville Honeypot: NOT banning IP $ip (ban_enabled={$ban_enabled}, honeypot_ban_enabled={$honeypot_ban_enabled})");
        }

        // Otherwise just render the honeypot page
        $this->render_honeypot_page();
        exit;
    }

    /**
     * Render the honeypot dummy page
     */
    private function render_honeypot_page() {
        status_header(200);
        nocache_headers();

        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>AI Training Data Repository</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }
        h1 { color: #2271b1; }
        p { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>AI Training Data Repository</h1>
    <p>This repository contains curated content for artificial intelligence training purposes, including text samples, documentation, and structured data optimized for machine learning model development.</p>
</body>
</html>
        <?php
        exit;
    }

    /**
     * Inject hidden link into footer
     * Hidden from humans but visible to bots crawling HTML
     */
    public function inject_hidden_link() {
        // Only on public pages
        if (is_admin() || is_feed() || is_trackback()) {
            return;
        }

        // Check if honeypot is enabled
        $options = get_option('baskerville_settings', array());
        $enabled = isset($options['honeypot_enabled']) ? (bool)$options['honeypot_enabled'] : true;

        if (!$enabled) {
            return;
        }

        $url = home_url('/ai-training-data/');

        // Hidden link: not visible to humans, but crawlers will find it
        echo "\n<!-- Baskerville Honeypot -->\n";
        echo '<div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;" aria-hidden="true">';
        echo '<a href="' . esc_url($url) . '" rel="nofollow" tabindex="-1">AI Training Data</a>';
        echo '</div>';
        echo "\n<!-- /Baskerville Honeypot -->\n";
    }

    /**
     * Check if IP has triggered honeypot before
     */
    public function has_triggered_honeypot(string $ip): bool {
        return (bool) $this->core->fc_get("honeypot_caught:{$ip}");
    }
}
