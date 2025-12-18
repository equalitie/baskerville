<?php

class Baskerville_REST {
    private Baskerville_Core $core;
    private Baskerville_AI_UA $aiua;
    private Baskerville_Stats $stats;

    public function __construct(
        Baskerville_Core $core,
        Baskerville_Stats $stats,
        Baskerville_AI_UA $aiua
    ) {
        $this->core  = $core;
        $this->stats = $stats;
        $this->aiua  = $aiua;
    }

    public function register_routes() {
        // error_log('Baskerville: registering REST routes');

        register_rest_route('baskerville/v1', '/fp', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'handle_fp'],
            'permission_callback' => function () { return true; }, // public endpoint; nonce checked inside
        ]);
    }

    /**
     * Check API rate limiting
     * Returns WP_REST_Response with 429 if rate limit exceeded, null otherwise
     */
    private function check_api_rate_limit() {
        $options = get_option('baskerville_settings', array());
        $rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;

        if (!$rate_limit_enabled) {
            return null; // Rate limiting disabled
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));

        // Check if IP is whitelisted
        if ($this->core->is_whitelisted_ip($ip)) {
            return null; // Whitelisted IPs bypass rate limiting
        }

        $max_requests = isset($options['api_rate_limit_requests']) ? (int)$options['api_rate_limit_requests'] : 100;
        $window_sec = isset($options['api_rate_limit_window']) ? (int)$options['api_rate_limit_window'] : 60;

        $key = "api_ratelimit:{$ip}";
        $count = $this->core->fc_inc_in_window($key, $window_sec);

        if ($count > $max_requests) {
            return new WP_REST_Response([
                'error' => 'rate_limit_exceeded',
                /* translators: %1$d is the maximum number of requests, %2$d is the time window in seconds */
                'message' => sprintf(esc_html__('Rate limit exceeded. Maximum %1$d requests per %2$d seconds.', 'baskerville'), $max_requests, $window_sec),
                'retry_after' => $window_sec
            ], 429);
        }

        return null;
    }

    /**
     * Handle fingerprint submission via REST API.
     *
     * Direct database queries are required for real-time fingerprint processing.
     * Caching is not applicable as fingerprints must be stored immediately.
     *
     * @param WP_REST_Request $request REST request object.
     * @return WP_REST_Response REST response.
     *
     * @phpcs:disable WordPress.DB.DirectDatabaseQuery
     */
    public function handle_fp( WP_REST_Request $request ) {
        // Check rate limit
        $rate_limit_response = $this->check_api_rate_limit();
        if ($rate_limit_response) {
            return $rate_limit_response;
        }
        $nonce = $request->get_header('x-wp-nonce');
        if ($nonce && !wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_REST_Response(['error' => 'invalid_nonce'], 403);
        }

        $body = $request->get_json_params();
        if (empty($body)) {
            return new WP_REST_Response(['error' => 'empty_payload'], 400);
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        $headers = [
            'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
            'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
            'user_agent'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
            'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
        ];
        $cookie_id = $this->core->get_cookie_id();

        // calculate
        try {
            $evaluation     = $this->aiua->baskerville_score_fp($body, ['headers' => $headers]);
            $classification = $this->aiua->classify_client($body, ['headers' => $headers]);
        } catch (Exception $e) {
            // error_log('Baskerville evaluation error: ' . $e->getMessage());
            $evaluation = ['score' => 0, 'action' => 'error', 'reasons' => ['evaluation_error'], 'top_factors' => []];
            $classification = ['classification' => 'unknown', 'reason' => esc_html__('Classification error', 'baskerville'), 'risk_score' => 0];
        }

        // fp cookie (HttpOnly, signed)
        $ua      = $headers['user_agent'] ?? '';
        $ua_hash = sha1((string)$ua);
        $ttl_sec = 6 * 60 * 60;

        // ! IMPORTANT: assumes that core provides public methods:
        // cookie_secret(), ip_key(), b64u_enc(). If they are private — create public equivalents.
        $payload_fp = [
            'v'     => 1,
            'ts'    => time(),
            'ttl'   => $ttl_sec,
            'ipk'   => $this->core->ip_key($ip),
            'ua'    => substr($ua_hash, 0, 16),
            'bid'   => substr($cookie_id ?: '', 0, 16),
            'score' => (int)($evaluation['score'] ?? 0),
            'top'   => array_map(function ($x) {
                return [
                    'key'   => (string)($x['key']   ?? ''),
                    'delta' => (int)   ($x['delta'] ?? 0),
                    'why'   => (string)($x['why']   ?? ''),
                ];
            }, array_slice($evaluation['top_factors'] ?? [], 0, 6)),
        ];
        $raw = wp_json_encode($payload_fp, JSON_UNESCAPED_SLASHES);
        $sig = hash_hmac('sha256', $raw, $this->core->cookie_secret());
        $val = $this->core->b64u_enc($raw) . '.' . $sig;

        setcookie('baskerville_fp', $val, [
            'expires'  => time() + $ttl_sec,
            'path'     => '/',
            'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        // mark fp seen
        if ($ip)        { $this->core->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180)); }
        if ($cookie_id) { $this->core->fc_set("fp_seen_cookie:{$cookie_id}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180)); }
        $this->core->fc_delete("nojs_cnt:{$ip}");

        $fp_hash   = isset($body['fingerprintHash']) ? substr((string)$body['fingerprintHash'], 0, 64) : null;
        $visit_key = isset($body['visitKey']) ? preg_replace('~[^a-f0-9]~i', '', (string)$body['visitKey']) : '';

        if ($visit_key) {
            $this->stats->update_visit_stats_by_key($visit_key, $evaluation, $classification, $fp_hash);
            return new WP_REST_Response([
                'ok'             => true,
                'score'          => (int)($evaluation['score'] ?? 0),
                'action'         => $evaluation['action'] ?? 'allow',
                'why'            => $evaluation['reasons'] ?? [],
                'classification' => $classification,
            ], 200);
        }

        // fallback: attach to last page hit without FP
        global $wpdb;
        $table = esc_sql( $wpdb->prefix . 'baskerville_stats' );
        $wpdb->query("SET time_zone = '+00:00'");

        $attach_window_sec = (int) get_option('baskerville_fp_attach_window_sec', 180);
        $row_id = null;
        if ($ip && $cookie_id) {
            $row_id = $wpdb->get_var(
                $wpdb->prepare(
                      "SELECT id FROM %i
                        WHERE ip=%s AND baskerville_id=%s AND event_type='page' AND had_fp=0
                          AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)
                        ORDER BY timestamp_utc DESC LIMIT 1",
                      $table,
                      $ip,
                      $cookie_id,
                      $attach_window_sec
                  )
            );
        }

        [$top_json, $top_name] = $this->stats->extract_top_factors($evaluation, $this->core->read_fp_cookie());
        $score = (int)($evaluation['score'] ?? 0);
        $cls   = (string)($classification['classification'] ?? 'unknown');
        $why   = implode('; ', $evaluation['reasons'] ?? []);
        $cls_r = (string)($classification['reason'] ?? '');

        if ($row_id) {
            $wpdb->update(
                $table,
                [
                    'score'                 => $score,
                    'classification'        => $cls,
                    'evaluation_json'       => wp_json_encode($evaluation),
                    'score_reasons'         => $why,
                    'classification_reason' => $cls_r,
                    'had_fp'                => 1,
                    'fp_received_at'        => current_time('mysql', true),
                    'fingerprint_hash'      => $fp_hash,
                    'top_factor_json'       => $top_json,
                    'top_factor'            => $top_name,
                ],
                ['id' => (int)$row_id],
                ['%d','%s','%s','%s','%s','%d','%s','%s','%s','%s'],
                ['%d']
            );
        } else {
            $visit_key_new = hash('sha256', ($ip ?: '') . '|' . ($cookie_id ?: '') . '|' . microtime(true) . '|' . wp_generate_uuid4());
            $wpdb->insert(
                $table,
                [
                    'visit_key'             => $visit_key_new,
                    'ip'                    => $ip ?: '',
                    'baskerville_id'        => $cookie_id ?: '',
                    'timestamp_utc'         => current_time('mysql', true),
                    'score'                 => $score,
                    'classification'        => $cls,
                    'user_agent'            => $headers['user_agent'] ?? '',
                    'evaluation_json'       => wp_json_encode($evaluation),
                    'score_reasons'         => $why,
                    'classification_reason' => $cls_r,
                    'event_type'            => 'page',
                    'had_fp'                => 1,
                    'fp_received_at'        => current_time('mysql', true),
                    'fingerprint_hash'      => $fp_hash,
                    'top_factor_json'       => $top_json,
                    'top_factor'            => $top_name,
                ],
                ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%d','%s','%s','%s']
            );
        }

        return new WP_REST_Response([
            'ok'             => true,
            'score'          => $score,
            'action'         => $evaluation['action'] ?? 'allow',
            'why'            => $evaluation['reasons'] ?? [],
            'classification' => $classification,
        ], 200);
    }
    // @phpcs:enable WordPress.DB.DirectDatabaseQuery
}
