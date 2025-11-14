<?php

class Baskerville_Firewall
{
    /** @var Baskerville_Core */
    private $core;

    /** @var Baskerville_Stats */
    private $stats;

    /** @var Baskerville_AI_UA */
    private $aiua;

    public function __construct(Baskerville_Core $core, Baskerville_Stats $stats, Baskerville_AI_UA $aiua) {
        $this->core = $core;
        $this->stats = $stats;
        $this->aiua = $aiua;
    }

    /* ===== Ban cache (no DB) ===== */
    private function get_ban(string $ip): ?array {
        $v = $this->core->fc_get("ban:{$ip}");
        return is_array($v) ? $v : null;
    }

    private function set_ban(string $ip, string $reason, int $ttl, array $meta = []): void {
        $payload = array_merge(['reason' => $reason, 'until' => time() + $ttl], $meta);
        $this->core->fc_set("ban:{$ip}", $payload, $ttl);
    }

    /* ===== One-shot DB logging gate for blocks ===== */
    private function blocklog_once(string $ip, string $reason, array $evaluation, array $classification, string $ua, int $gate_ttl = 600): void {
        $sig = md5($reason);
        $k   = "blocklog:{$ip}:{$sig}";
        if ($this->core->fc_get($k)) return; // already logged recently
        $this->core->fc_set($k, 1, $gate_ttl);
        $this->insert_block_row($ip, $evaluation, $classification, $ua, $reason);
    }

    private function insert_block_row(string $ip, array $evaluation, array $classification, string $ua, string $reason): void {
        global $wpdb;
        $table     = $wpdb->prefix . 'baskerville_stats';
        $cookie_id = $this->core->get_cookie_id() ?: '';
        $visit_key = $this->stats->make_visit_key($ip, $cookie_id);

        // Get country code for GeoIP analytics
        $country_code = $this->core->get_country_by_ip($ip);

        $ok = $wpdb->insert(
            $table,
            [
                'visit_key'             => $visit_key,
                'ip'                    => $ip,
                'country_code'          => $country_code,
                'baskerville_id'        => $cookie_id,
                'timestamp_utc'         => current_time('mysql', true),
                'score'                 => (int)($evaluation['score'] ?? 0),
                'classification'        => (string)($classification['classification'] ?? 'unknown'),
                'user_agent'            => $ua,
                'evaluation_json'       => wp_json_encode($evaluation),
                'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
                'classification_reason' => (string)($classification['reason'] ?? ''),
                'block_reason'          => mb_substr($reason, 0, 120),
                'event_type'            => 'block',
                'had_fp'                => 0,
            ],
            ['%s','%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%d']
        );

        if ($ok === false) {
            error_log('Baskerville: insert_block_row failed - ' . $wpdb->last_error);
        }
    }

    /* ===== send 403 and stop ===== */
    private function send_403_and_exit(array $meta): void {
        // Check if 403 bans are enabled in settings (default: true)
        $options = get_option('baskerville_settings', array());
        $ban_enabled = !isset($options['ban_bots_403']) || $options['ban_bots_403'];

        if (!$ban_enabled) {
            // If bans are disabled, just return and allow the request to continue
            return;
        }

        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            if (!empty($meta['reason'])) header('X-Baskerville-Reason: ' . $meta['reason']);
            if (isset($meta['score']))   header('X-Baskerville-Score: ' . (int)$meta['score']);
            if (!empty($meta['cls']))    header('X-Baskerville-Class: ' . $meta['cls']);
            if (!empty($meta['until'])) {
                $until = (int)$meta['until'];
                header('X-Baskerville-Until: ' . gmdate('c', $until));
                $retry = max(1, $until - time());
                header('Retry-After: ' . $retry);
            }
        }
        echo "Forbidden\n";
        exit;
    }

    /* ===== send 403 for GeoIP blocking - always blocks regardless of ban_bots_403 setting ===== */
    private function send_403_geo_and_exit(array $meta): void {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            if (!empty($meta['reason'])) header('X-Baskerville-Reason: ' . $meta['reason']);
            if (isset($meta['score']))   header('X-Baskerville-Score: ' . (int)$meta['score']);
            if (!empty($meta['cls']))    header('X-Baskerville-Class: ' . $meta['cls']);
            if (!empty($meta['until'])) {
                $until = (int)$meta['until'];
                header('X-Baskerville-Until: ' . gmdate('c', $until));
                $retry = max(1, $until - time());
                header('Retry-After: ' . $retry);
            }
        }
        echo "Forbidden - Access from this country is restricted\n";
        exit;
    }

    public function pre_db_firewall(): void {
        // публичная HTML-страница?
        if (!$this->core->is_public_html_request()) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($ip === '') return;

        // белый список IP — пропускаем
        if ($this->core->is_whitelisted_ip($ip)) return;

        // GeoIP country ban check
        $options = get_option('baskerville_settings', array());
        $mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';

        // Only process GeoIP checks if not in "allow_all" mode
        if ($mode !== 'allow_all') {
            $country = $this->core->get_country_by_ip($ip);
            if ($country) {
                $should_block = false;
                $reason_prefix = '';
                $country_list_str = '';

                if ($mode === 'whitelist') {
                    // Whitelist mode: block if country is NOT in the list
                    $country_list_str = isset($options['whitelist_countries']) ? $options['whitelist_countries'] : '';
                    if (!empty($country_list_str)) {
                        $whitelist_countries = array_map('trim', array_map('strtoupper', explode(',', $country_list_str)));
                        $should_block = !in_array($country, $whitelist_countries, true);
                        $reason_prefix = 'geo-whitelist-blocked';
                    }
                } elseif ($mode === 'blacklist') {
                    // Blacklist mode: block if country IS in the list
                    $country_list_str = isset($options['blacklist_countries']) ? $options['blacklist_countries'] : '';
                    if (!empty($country_list_str)) {
                        $blacklist_countries = array_map('trim', array_map('strtoupper', explode(',', $country_list_str)));
                        $should_block = in_array($country, $blacklist_countries, true);
                        $reason_prefix = 'geo-blacklist-blocked';
                    }
                }

                if ($should_block) {
                    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                    $headers = [
                        'accept'          => $_SERVER['HTTP_ACCEPT'] ?? null,
                        'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
                        'user_agent'      => $ua,
                        'sec_ch_ua'       => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
                    ];

                    $evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
                    $classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
                    $reason = "{$reason_prefix}:{$country}";
                    $ttl = (int) get_option('baskerville_ban_ttl_sec', 600);

                    $this->set_ban($ip, $reason, $ttl, [
                        'score' => (int)($evaluation['score'] ?? 0),
                        'cls'   => 'geo-banned',
                    ]);
                    $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);

                    // Use dedicated GeoIP blocking function - always blocks regardless of ban_bots_403 setting
                    $this->send_403_geo_and_exit([
                        'reason' => $reason,
                        'score'  => $evaluation['score'] ?? null,
                        'cls'    => 'geo-banned',
                        'until'  => time() + $ttl,
                    ]);
                }
            }
        }

        // Если есть корректная FP-кука — подавим no-JS триггеры
        $fp_cookie = $this->core->read_fp_cookie();
        if ($fp_cookie) {
            $this->core->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180));
        }

        // Заголовки для серверной эвристики
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $headers = [
            'accept'          => $_SERVER['HTTP_ACCEPT'] ?? null,
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'user_agent'      => $ua,
            'sec_ch_ua'       => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        ];

        // 0) Уже забанен?
        if ($ban = $this->get_ban($ip)) {
            // если это верифицированный краулер — снимем бан
            if (($ban['cls'] ?? '') === 'verified_bot') {
                $this->core->fc_delete("ban:{$ip}");
            } else {
                $evaluation = ['score' => (int)($ban['score'] ?? 0), 'reasons' => ['cached-ban']];
                $classification = [
                    'classification' => (string)($ban['cls'] ?? 'bot'),
                    'reason'         => (string)($ban['reason'] ?? 'cached-ban'),
                ];
                $this->blocklog_once(
                    $ip,
                    (string)($ban['reason'] ?? 'cached-ban'),
                    $evaluation,
                    $classification,
                    $ua,
                    600
                );
                $this->send_403_and_exit($ban);
            }
        }

        // Помощники
        $looks_like_browser = $this->aiua->looks_like_browser_ua($ua);
        $vc                 = $this->aiua->verify_crawler_ip($ip, $ua);
        $verified_crawler   = ($vc['claimed'] && $vc['verified']);

        // 1) no-JS burst: считаем только страницы, для которых мы не видели FP «вскоре»
        $fp_seen_recent = (bool) $this->core->fc_get("fp_seen_ip:{$ip}");
        if (!$fp_seen_recent) {
            $window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
            $threshold  = (int) get_option('baskerville_nojs_threshold', 20);
            $cnt        = $this->core->fc_inc_in_window("nojs_cnt:{$ip}", $window_sec);

            if ($cnt > $threshold && !$verified_crawler) {
                // Оценка по серверным заголовкам (без JS)
                $evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
                $classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);

                $reason = "nojs-burst>{$threshold}/{$window_sec}s";
                $ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

                $this->set_ban($ip, $reason, $ttl, [
                    'score' => (int)($evaluation['score'] ?? 0),
                    'cls'   => (string)($classification['classification'] ?? 'unknown'),
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit([
                    'reason' => $reason,
                    'score'  => $evaluation['score'] ?? null,
                    'cls'    => $classification['classification'] ?? null,
                    'until'  => time() + $ttl,
                ]);
            }
        }

        // 2) Небраузерный UA (и не «хороший» краулер): быстрый блок по бурсту
        $ua_l = strtolower($ua);
        $nonbrowser_signatures = [
            'curl','wget','python-requests','go-http-client','httpie','libcurl',
            'java','okhttp','node-fetch','axios','aiohttp','urllib','postmanruntime',
            'insomnia','restsharp','powershell','httpclient','http.rb','ruby','perl',
            'traefik','kube-probe','healthcheck','pingdom','datadog','sumologic'
        ];
        $is_nonbrowser = false;
        foreach ($nonbrowser_signatures as $sig) {
            if (strpos($ua_l, $sig) !== false) { $is_nonbrowser = true; break; }
        }

        if ($is_nonbrowser && !$verified_crawler) {
            $window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
            $threshold  = (int) get_option('baskerville_nocookie_threshold', 10);

            // «есть валидная кука на входе?» — пользуемся публичным методом ядра
            $no_cookie  = !$this->core->arrival_has_valid_cookie();
            $key        = $no_cookie ? "nbua_nocookie_cnt:{$ip}" : "nbua_cnt:{$ip}";
            $cnt        = $this->core->fc_inc_in_window($key, $window_sec);

            if ($no_cookie && $cnt > $threshold) {
                $evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
                $classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
                $reason         = "nonbrowser-ua-burst>{$threshold}/{$window_sec}s";
                $ttl            = (int) get_option('baskerville_ban_ttl_sec', 600);

                $this->set_ban($ip, $reason, $ttl, [
                    'score' => (int)($evaluation['score'] ?? 0),
                    'cls'   => (string)($classification['classification'] ?? 'bot'),
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit([
                    'reason' => $reason,
                    'score'  => $evaluation['score'] ?? null,
                    'cls'    => $classification['classification'] ?? null,
                    'until'  => time() + $ttl,
                ]);
            }
            // пока порог не превышен — пропускаем дальше
        }

        // 3) Высокий риск по серверным заголовкам + не похоже на браузер
        $evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
        $classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
        $risk           = (int)($evaluation['score'] ?? 0);

        if (($classification['classification'] ?? '') === 'bad_bot' && !$verified_crawler) {
            $window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
            $threshold  = (int) get_option('baskerville_nocookie_threshold', 10);
            $cnt        = $this->core->fc_inc_in_window("badbot_cnt:{$ip}", $window_sec);

            if ($cnt > $threshold) {
                $reason = 'classified-bad-bot-burst';
                $ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

                $this->set_ban($ip, $reason, $ttl, [
                    'score' => $risk,
                    'cls'   => (string)($classification['classification'] ?? 'bot'),
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit([
                    'reason' => $reason,
                    'score'  => $risk,
                    'cls'    => $classification['classification'] ?? null,
                    'until'  => time() + $ttl,
                ]);
            }
        } elseif ($risk >= 85 && !$looks_like_browser && !$verified_crawler) {
            // очень подозрительно — можно сразу
            $reason = 'high-risk-nonbrowser';
            $ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

            $this->set_ban($ip, $reason, $ttl, [
                'score' => $risk,
                'cls'   => (string)($classification['classification'] ?? 'bot'),
            ]);
            $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
            $this->send_403_and_exit([
                'reason' => $reason,
                'score'  => $risk,
                'cls'    => $classification['classification'] ?? null,
                'until'  => time() + $ttl,
            ]);
        }

        // 4) (опционально) здесь можно добавить дополнительные политики (например, nocookie-burst для «похожих на браузер»)
    }
}
