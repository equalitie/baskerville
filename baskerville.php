<?php
/**
 * Plugin Name: Baskerville
 * Plugin URI: https://equalitie.org/
 * Description: A WordPress plugin by Equalitie.
 * Version: 1.0.0
 * Author: Equalitie
 * Author URI: https://equalitie.org/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: baskerville
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.4
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('BASKERVILLE_VERSION', '1.0.0');
define('BASKERVILLE_PLUGIN_URL', plugin_dir_url(__FILE__));
define('BASKERVILLE_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('BASKERVILLE_DEBUG', defined('WP_DEBUG') && WP_DEBUG);
define('BASKERVILLE_DEFAULT_RETENTION_DAYS', 14);

class Baskerville {

    private $core;
    private $admin;
    private $had_cookie_on_arrival = false;
    private $current_visit_key = null;

    public function __construct() {
        add_action('init', array($this, 'init'));
        add_action('plugins_loaded', array($this, 'load_classes'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('baskerville_cleanup_stats', array($this, 'cleanup_old_stats'));
        add_action('send_headers', [$this, 'ensure_baskerville_cookie'], 0);

        add_action('template_redirect', [$this, 'pre_db_firewall'], -1);

        add_action('template_redirect', [$this, 'log_page_visit'], 0);
        add_action('init', [$this, 'handle_widget_toggle'], 0);
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    private function read_fp_cookie(): ?array {
        $raw = $_COOKIE['baskerville_fp'] ?? '';
        if (!$raw) return null;
        $p = explode('.', $raw, 2);
        if (count($p) !== 2) return null;
        [$b64, $sig] = $p;
        $json = $this->b64u_dec($b64);
        if (!hash_equals(hash_hmac('sha256', $json, $this->cookie_secret()), $sig)) return null;
        $data = json_decode($json, true);
        if (!is_array($data)) return null;

        // TTL
        $ts  = (int)($data['ts']  ?? 0);
        $ttl = (int)($data['ttl'] ?? 0);
        if (!$ts || !$ttl || (time() - $ts) > $ttl) return null;

        // Привязка к ip_key и UA-hash
        $ipk_now = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
        $ua_hash = sha1((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        if (($data['ipk'] ?? '') !== $ipk_now) return null;
        if (($data['ua']  ?? '') !== substr($ua_hash, 0, 16)) return null;

        return $data;
    }

    /* ==== helpers: base64url & ip-key ==== */
    private function b64u_enc(string $s): string {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }
    private function b64u_dec(string $s): string {
        $s = strtr($s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) $s .= str_repeat('=', 4 - $pad);
        return base64_decode($s);
    }

    /** IPv4 -> первые 3 октета; IPv6 -> первые 4 хекстета */
    private function ip_key(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $p = explode('.', $ip);
            return implode('.', array_slice($p, 0, 3)); // /24
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip = strtolower($ip);
            $h = explode(':', $ip);
            // нормализация :: не критична — берем первые сегменты как есть
            return implode(':', array_slice($h, 0, 4)); // /64
        }
        return 'unknown';
    }


    /* ===== Fast cache: APCu + file fallback ===== */

    private function fc_has_apcu(): bool {
        return function_exists('apcu_store') && (function_exists('apcu_enabled') ? apcu_enabled() : true);
    }
    private function fc_key(string $key): string {
        return 'baskerville:' . preg_replace('~[^a-z0-9:_-]~i','_', $key);
    }
    private function fc_dir(): string {
        $dir = WP_CONTENT_DIR . '/cache/baskerville';
        if (!is_dir($dir)) @wp_mkdir_p($dir);
        return $dir;
    }
    private function fc_path(string $key): string {
        return $this->fc_dir() . '/' . sha1($key) . '.cache';
    }
    /** set arbitrary value with TTL */
    private function fc_set(string $key, $value, int $ttl): bool {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) {
            return apcu_store($k, $value, $ttl);
        }
        $data = ['v'=>$value,'e'=>time()+$ttl];
        return (bool) @file_put_contents($this->fc_path($k), serialize($data), LOCK_EX);
    }
    /** get arbitrary value or null */
    private function fc_get(string $key) {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) {
            $ok = false; $v = apcu_fetch($k, $ok);
            return $ok ? $v : null;
        }
        $p = $this->fc_path($k);
        if (!is_file($p)) return null;
        $raw = @file_get_contents($p);
        if ($raw === false) return null;
        $data = @unserialize($raw);
        if (!is_array($data) || ($data['e'] ?? 0) < time()) { @unlink($p); return null; }
        return $data['v'] ?? null;
    }
    /** increment counter in fixed window; returns current value */
    private function fc_inc_in_window(string $key, int $window_sec): int {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) {
            // create-or-increment with window TTL
            if (!apcu_exists($k)) {
                apcu_add($k, 1, $window_sec);
                return 1;
            }
            return (int) apcu_inc($k);
        }
        // file fallback
        $p  = $this->fc_path($k);
        $now= time();
        $cnt= 0; $exp = $now + $window_sec;
        if (is_file($p)) {
            $raw = @file_get_contents($p);
            $data= @unserialize($raw);
            if (is_array($data) && ($data['e'] ?? 0) > $now) {
                $cnt = (int)($data['v'] ?? 0);
                $exp = (int)$data['e'];
            }
        }
        $cnt++;
        @file_put_contents($p, serialize(['v'=>$cnt, 'e'=>$exp]), LOCK_EX);
        return $cnt;
    }
    private function fc_delete(string $key): void {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) { apcu_delete($k); return; }
        @unlink($this->fc_path($k));
    }

    /* ===== Ban cache (no DB) ===== */
    private function get_ban(string $ip): ?array {
        return $this->fc_get("ban:{$ip}") ?: null;
    }
    private function set_ban(string $ip, string $reason, int $ttl, array $meta=[]): void {
        $payload = array_merge(['reason'=>$reason,'until'=>time()+$ttl], $meta);
        $this->fc_set("ban:{$ip}", $payload, $ttl);
    }

    /* ===== One-shot DB logging gate for blocks ===== */
    private function blocklog_once(string $ip, string $reason, array $evaluation, array $classification, string $ua, int $gate_ttl=600): void {
        $sig = md5($reason);
        $k   = "blocklog:{$ip}:{$sig}";
        if ($this->fc_get($k)) return; // already logged recently
        $this->fc_set($k, 1, $gate_ttl);
        $this->insert_block_row($ip, $evaluation, $classification, $ua, $reason);
    }

    private function insert_block_row(string $ip, array $evaluation, array $classification, string $ua, string $reason): void {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';
        $cookie_id = $this->get_cookie_id() ?: '';
        $visit_key = $this->make_visit_key($ip, $cookie_id);
        $ok = $wpdb->insert(
            $table,
            [
                'visit_key'             => $visit_key,
                'ip'                    => $ip,
                'baskerville_id'        => $cookie_id,
                'timestamp_utc'         => current_time('mysql', true),
                'score'                 => (int)($evaluation['score'] ?? 0),
                'classification'        => (string)($classification['classification'] ?? 'unknown'),
                'user_agent'            => $ua,
                'evaluation_json'       => json_encode($evaluation),
                'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
                'classification_reason' => (string)($classification['reason'] ?? ''),
                'block_reason'          => mb_substr($reason, 0, 120),
                'event_type'            => 'block',
                'had_fp'                => 0,
            ],
            ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%d']
        );
        if ($ok === false) {
            error_log('Baskerville: insert_block_row failed - '.$wpdb->last_error);
        }
    }

    /* ===== send 403 and stop ===== */
    private function send_403_and_exit(array $meta): void {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            if (!empty($meta['reason'])) header('X-Baskerville-Reason: '.$meta['reason']);
            if (isset($meta['score']))   header('X-Baskerville-Score: '.(int)$meta['score']);
            if (!empty($meta['cls']))    header('X-Baskerville-Class: '.$meta['cls']);
           if (!empty($meta['until'])) {
               $until = (int)$meta['until'];
               header('X-Baskerville-Until: '.gmdate('c', $until));
               $retry = max(1, $until - time());
               header('Retry-After: '.$retry);
           }
        }
        echo "Forbidden\n";
        exit;
    }




    // ---- ARRIVAL COOKIE CHECK (по «сырому» заголовку) ----
        private function arrival_has_valid_cookie(): bool {
            $hdr = $_SERVER['HTTP_COOKIE'] ?? '';
            if ($hdr === '' || strpos($hdr, 'baskerville_id=') === false) return false;
            if (!preg_match('~(?:^|;\s*)baskerville_id=([^;]+)~i', $hdr, $m)) return false;
            $raw = urldecode($m[1]);
            $parts = explode('.', $raw);

            // новый формат: token.ts.ipk.sig
            if (count($parts) === 4) {
                [$token, $ts, $ipk, $sig] = $parts;
                if (!ctype_xdigit($token) || !ctype_digit($ts)) return false;
                $cur_ipk = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
                // подпись должна валидироваться на ТЕКУЩЕМ ip_key — как в get_cookie_id()
                $calc = $this->sign_cookie($token, (int)$ts, $cur_ipk);
                if (!hash_equals($calc, $sig)) return false;
                if ((int)$ts < time() - 60*60*24*90) return false;
                return true;
            }

            // legacy 3-part: token.ts.sig (оставляем для обратной совместимости)
            if (count($parts) === 3) {
                [$token, $ts, $sig] = $parts;
                if (!ctype_xdigit($token) || !ctype_digit($ts)) return false;
                $calc = hash_hmac('sha256', $token . '.' . (int)$ts, $this->cookie_secret());
                if (!hash_equals($calc, $sig)) return false;
                if ((int)$ts < time() - 60*60*24*90) return false;
                return true;
            }

            return false;
        }

    // ---- Признак «это публичная HTML-страница» (как в log_page_visit) ----
    private function is_public_html_request(): bool {
        if (is_admin()) return false;
        if (defined('REST_REQUEST') && REST_REQUEST) return false;
        if (wp_doing_ajax()) return false;
        if (is_feed() || is_trackback()) return false;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/wp-json/') === 0) return false;
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        if ($accept && !preg_match('~text/html|application/xhtml\+xml|\*/\*~i', $accept)) return false;
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if (!in_array($method, ['GET','HEAD'], true)) return false;
        return true;
    }

    private function is_whitelisted_ip(string $ip): bool {
        $raw = (string) get_option('baskerville_ip_whitelist', '');
        if ($raw === '') return false;
        foreach (preg_split('~[\s,]+~', $raw) as $w) {
            if ($w !== '' && $w === $ip) return true;
        }
        return false;
    }

    private function verify_crawler_ip(string $ip, string $ua): array {
        $ua = strtolower($ua);
        $expect = null;

        if (strpos($ua,'googlebot') !== false)     $expect = ['.googlebot.com','.google.com'];
        elseif (strpos($ua,'bingbot') !== false)   $expect = ['.search.msn.com'];
        elseif (strpos($ua,'applebot') !== false)  $expect = ['.applebot.apple.com'];
        elseif (strpos($ua,'duckduckbot') !== false) $expect = ['.duckduckgo.com'];
        else return ['claimed'=>false,'verified'=>false,'host'=>null];

        // APCu/file cache key
        $ck = 'rdns:'.$ip;
        $cached = $this->fc_get($ck);
        if (is_array($cached)) return $cached;

        $host = gethostbyaddr($ip);
        $ok = false;
        if ($host && $host !== $ip) {
            $suffix_ok = false;
            foreach ($expect as $suf) {
                if (substr($host, -strlen($suf)) === $suf) { $suffix_ok = true; break; }
            }
            if ($suffix_ok) {
                // forward confirm
                $ips = [];
                foreach (['A','AAAA'] as $t) {
                    $r = dns_get_record($host, constant('DNS_'.$t));
                    if (is_array($r)) foreach ($r as $rec) {
                        $ips[] = $rec['ip'] ?? $rec['ipv6'] ?? null;
                    }
                }
                $ips = array_filter($ips);
                $ok  = in_array($ip, $ips, true);
            }
        }

        $res = ['claimed'=>true,'verified'=>$ok,'host'=>$host ?: null];
        // cache 6h on pass, 1h on fail to recheck occasionally
        $this->fc_set($ck, $res, $ok ? 6*3600 : 3600);
        return $res;
    }

    public function get_top_factor_histogram($hours = 24, $min_score = 30) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours     = max(1, min(720, (int)$hours));
        $min_score = max(0, min(100, (int)$min_score));
        $cutoff    = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        // работаем в UTC
        $wpdb->query("SET time_zone = '+00:00'");

        // только события с had_fp=1, где реально считали скор и сохранили top_factor
        $sql = "
          SELECT
            top_factor AS factor,
            COUNT(*)   AS cnt,
            AVG(score) AS avg_score
          FROM $table
          WHERE event_type IN ('page','fp')
            AND timestamp_utc >= %s
            AND had_fp = 1
            AND score > %d
            AND top_factor IS NOT NULL
            AND top_factor <> ''
          GROUP BY top_factor
          ORDER BY cnt DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff, $min_score), ARRAY_A) ?: [];

        $total = 0;
        foreach ($rows as $r) { $total += (int)$r['cnt']; }

        $items = array_map(function($r) use ($total) {
            $cnt = (int)$r['cnt'];
            return [
                'factor'     => (string)$r['factor'],
                'count'      => $cnt,
                'percent'    => $total ? round($cnt * 100 / $total, 1) : 0.0,
                'avg_score'  => round((float)$r['avg_score'], 1),
            ];
        }, $rows);

        return [
            'hours'      => $hours,
            'min_score'  => $min_score,
            'total'      => $total,
            'items'      => $items,
        ];
    }


    public function get_block_reasons_breakdown($hours = 24, $limit = 10) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql_total = "SELECT COUNT(*) FROM $table WHERE event_type='block' AND timestamp_utc >= %s";
        $total = (int)$wpdb->get_var($wpdb->prepare($sql_total, $cutoff));

        $sql = "
          SELECT COALESCE(NULLIF(block_reason,''),'unspecified') AS reason, COUNT(*) AS cnt
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
          GROUP BY reason
          ORDER BY cnt DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        // top-N + 'Other'
        $items = [];
        $acc = 0; $n = 0;
        foreach ($rows as $r) {
            $n++;
            if ($n <= $limit) {
                $c = (int)$r['cnt'];
                $acc += $c;
                $items[] = [
                    'reason'  => $r['reason'],
                    'count'   => $c,
                    'percent' => $total ? round($c * 100 / $total, 1) : 0.0,
                ];
            }
        }
        if ($total > $acc) {
            $rest = $total - $acc;
            $items[] = [
                'reason'  => 'other',
                'count'   => $rest,
                'percent' => $total ? round($rest * 100 / $total, 1) : 0.0,
            ];
        }

        return ['total' => $total, 'items' => $items];
    }


    public function pre_db_firewall(): void {
        if (!$this->is_public_html_request()) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$ip) return;

        if ($this->is_whitelisted_ip($ip)) return; // <- не фильтруем белый список

        $fp_cookie = $this->read_fp_cookie();
        if ($fp_cookie) {
            // подавляем ложные no-JS триггеры
            $this->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180));
        }

         // Считаем UA/headers СРАЗУ — нужно даже если бан уже в кэше
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $headers = [
            'accept'          => $_SERVER['HTTP_ACCEPT'] ?? null,
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'user_agent'      => $ua,
            'sec_ch_ua'       => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        ];

        // 0) Уже забанен? — отдадим 403 и разово прологируем (если ещё не логировали в этот gate)
        if ($ban = $this->get_ban($ip)) {
            // Если бан по ошибке поставлен verified-краулеру — снимаем и пропускаем
            if (($ban['cls'] ?? '') === 'verified_bot') {
                $this->fc_delete("ban:{$ip}");
            } else {
                $evaluation = ['score' => (int)($ban['score'] ?? 0), 'reasons' => ['cached-ban']];
                $classification = [
                    'classification' => (string)($ban['cls'] ?? 'bot'),
                    'reason' => (string)($ban['reason'] ?? 'cached-ban'),
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


        // Сбор контекста для правил
        $client_cookie_header = $_SERVER['HTTP_COOKIE'] ?? '';
//         $has_valid_cookie = (strpos($client_cookie_header, 'baskerville_id=') !== false) && ($this->get_cookie_id() !== null);

        // Помощники
        $looks_like_browser = $this->looks_like_browser_ua($ua);
        $vc = $this->verify_crawler_ip($ip, $ua);
        $verified_crawler = ($vc['claimed'] && $vc['verified']);

        // 1) no-JS burst: считаем только страницы, для которых мы не видели FP "вскоре".
        //    handle_fp() будет ставить метку fp_seen_ip:$ip на 180 сек.
        $fp_seen_recent = (bool) $this->fc_get("fp_seen_ip:{$ip}");
        if (!$fp_seen_recent) {
            $window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
            $threshold  = (int) get_option('baskerville_nojs_threshold', 20);
            $cnt = $this->fc_inc_in_window("nojs_cnt:{$ip}", $window_sec);
            if ($cnt > $threshold && !$verified_crawler) {
                // Вычислим оценку/классификацию по серверным заголовкам (без JS)
                $evaluation     = $this->baskerville_score_fp(['fingerprint'=>[]], ['headers'=>$headers]);
                $classification = $this->classify_client(['fingerprint'=>[]], ['headers'=>$headers]);

                $reason = "nojs-burst>{$threshold}/{$window_sec}s";
                // Сохраняем бан в кэше и разово логируем в БД (event_type=block)
                $this->set_ban($ip, $reason, (int)get_option('baskerville_ban_ttl_sec', 600), [
                    'score' => (int)($evaluation['score'] ?? 0),
                    'cls'   => (string)($classification['classification'] ?? 'unknown')
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit(['reason'=>$reason,'score'=>$evaluation['score']??null,'cls'=>$classification['classification']??null]);
            }
        }

        // 2) Небраузерный UA (и не «хороший» краулер): агрессивный быстрый блок
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
            // если клиент без нашей валидной куки — считаем в отдельный бакет
            $no_cookie  = !$this->arrival_has_valid_cookie();
            $key        = $no_cookie ? "nbua_nocookie_cnt:{$ip}" : "nbua_cnt:{$ip}";
            $cnt        = $this->fc_inc_in_window($key, $window_sec);
            if ($no_cookie && $cnt > $threshold) {
                $evaluation     = $this->baskerville_score_fp(['fingerprint'=>[]], ['headers'=>$headers]);
                $classification = $this->classify_client(['fingerprint'=>[]], ['headers'=>$headers]);
                $reason = "nonbrowser-ua-burst>{$threshold}/{$window_sec}s";
                $ttl    = (int)get_option('baskerville_ban_ttl_sec', 600);
                $this->set_ban($ip, $reason, $ttl, [
                    'score' => (int)($evaluation['score'] ?? 0),
                    'cls'   => (string)($classification['classification'] ?? 'bot')
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit(['reason'=>$reason,'score'=>$evaluation['score']??null,'cls'=>$classification['classification']??null,'until'=>time()+$ttl]);
            }
            // пока порог не превышен — пропускаем дальше
       }

        // 3) Высокий риск по серверным заголовкам + не похоже на браузер
        $evaluation     = $this->baskerville_score_fp(['fingerprint'=>[]], ['headers'=>$headers]);
        $classification = $this->classify_client(['fingerprint'=>[]], ['headers'=>$headers]);
        $risk = (int)($evaluation['score'] ?? 0);
        if (($classification['classification'] ?? '') === 'bad_bot' && !$verified_crawler) {
            $window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
            $threshold  = (int) get_option('baskerville_nocookie_threshold', 10);
            $cnt = $this->fc_inc_in_window("badbot_cnt:{$ip}", $window_sec);
            if ($cnt > $threshold) {
                $reason = 'classified-bad-bot-burst';
                $ttl    = (int)get_option('baskerville_ban_ttl_sec', 600);
                $this->set_ban($ip, $reason, $ttl, [
                    'score' => $risk,
                    'cls'   => (string)($classification['classification'] ?? 'bot')
                ]);
                $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
                $this->send_403_and_exit(['reason'=>$reason,'score'=>$risk,'cls'=>$classification['classification']??null,'until'=>time()+$ttl]);
            }
        } elseif ($risk >= 85 && !$looks_like_browser && !$verified_crawler) {
            // действительно очень подозрительно — можно сразу
            $reason = 'high-risk-nonbrowser';
            $this->set_ban($ip, $reason, (int)get_option('baskerville_ban_ttl_sec', 600), [
                'score' => $risk,
                'cls'   => (string)($classification['classification'] ?? 'bot')
            ]);
            $this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
            $this->send_403_and_exit(['reason'=>$reason,'score'=>$risk,'cls'=>$classification['classification']??null]);
        }

        // 4) (опционально) nocookie-burst уже есть у тебя; если он реализован раньше — оставь его
        //    Если захочешь, его можно переиспользовать здесь по тому же шаблону с fc_inc_in_window(...)
    }

    public function get_block_timeseries_data($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        // гарантируем UTC
        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            FROM_UNIXTIME(
              FLOOR(UNIX_TIMESTAMP(CONVERT_TZ(timestamp_utc,'+00:00','+00:00'))/900)*900
            ) AS time_slot,
            COUNT(*) AS total_blocks,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_blocks,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_blocks,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_blocks,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_blocks,
            SUM(CASE WHEN classification NOT IN ('bad_bot','ai_bot','bot') THEN 1 ELSE 0 END) AS other_blocks
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
          GROUP BY time_slot
          ORDER BY time_slot ASC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $out = [];
        foreach ($rows as $r) {
            $out[] = [
                'time'             => $r['time_slot'],
                'total_blocks'     => (int)$r['total_blocks'],
                'bad_bot_blocks'   => (int)$r['bad_bot_blocks'],
                'verified_bot_blocks' => (int)$r['verified_bot_blocks'],
                'ai_bot_blocks'    => (int)$r['ai_bot_blocks'],
                'bot_blocks'       => (int)$r['bot_blocks'],
                'other_blocks'     => (int)$r['other_blocks'],
            ];
        }
        return $out;
    }

    public function handle_widget_toggle() {
        if (!isset($_GET['baskerville_debug'])) return;

        $v = strtolower(sanitize_text_field($_GET['baskerville_debug']));
        $enable  = in_array($v, ['1','on','true','yes'], true);
        $disable = in_array($v, ['0','off','false','no','clear'], true);

        if ($enable) {
            setcookie('baskerville_show_widgets', '1', [
                'expires'  => time() + 60*60*24*30,
                'path'     => '/',
                'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
                'httponly' => false,
                'samesite' => 'Lax',
            ]);
            $_COOKIE['baskerville_show_widgets'] = '1';
        } elseif ($disable) {
            setcookie('baskerville_show_widgets', '', [
                'expires'  => time() - 3600,
                'path'     => '/',
                'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
                'httponly' => false,
                'samesite' => 'Lax',
            ]);
            unset($_COOKIE['baskerville_show_widgets']);
        }

        // Подскажем кэшу не кэшировать эту выдачу
        if (!headers_sent()) {
            if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
            nocache_headers();
        }
    }

    public function log_page_visit() {
        // Только публичные HTML-страницы
        if (is_admin()) return;
        if (defined('REST_REQUEST') && REST_REQUEST) return;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/wp-json/') === 0) return;
        if (wp_doing_ajax()) return;
        if (is_feed() || is_trackback()) return;

        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        if ($accept && !preg_match('~text/html|application/xhtml\+xml|\*/\*~i', $accept)) {
            return;
        }

//         $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
//         if (!in_array($method, ['GET','HEAD'], true)) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $headers = [
            'accept'           => $_SERVER['HTTP_ACCEPT'] ?? null,
            'accept_language'  => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'user_agent'       => $ua,
            'sec_ch_ua'        => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        ];

        // Классифицируем без клиентских полей (только серверные заголовки и кука)
        $evaluation     = $this->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
        $fp_cookie = $this->read_fp_cookie();
        if ($fp_cookie) {
            // перезапишем/улучшим оценку
            $evaluation = array_merge($evaluation, [
                'score' => (int)$fp_cookie['score'],
            ]);
            // помечаем had_fp=1 позже через update_visit_stats_by_key (как и сейчас через handle_fp),
            // но для первичной вставки можно оставить как есть; у нас есть visit_key для последующего апдейта.
        }

        $classification = $this->classify_client(['fingerprint' => []], ['headers' => $headers]);

        // Детектор «бурстов» без JS: много HTML-хитов за короткое окно — mark as bad_bot
        $this->maybe_mark_ip_as_bad_bot_on_burst($ip, $classification);

        $cookie_id = $this->get_cookie_id();
        $visit_key = $this->make_visit_key($ip, $cookie_id);
        $this->current_visit_key = $visit_key;

        // короткая кука на всякий случай (если кэш/инлайновый скрипт не увидит PHP-переменную)
        setcookie('baskerville_visit_key', $visit_key, [
          'expires'  => time()+300, 'path'=>'/', 'secure'=>is_ssl(), 'httponly'=>false, 'samesite'=>'Lax'
        ]);

        $this->save_visit_stats($ip, $cookie_id ?? '', $evaluation, $classification, $ua, 'page', $visit_key);
    }

    private function make_visit_key(string $ip, ?string $bid): string {
        return hash('sha256', $ip.'|'.$bid.'|'.microtime(true).'|'.bin2hex(random_bytes(8)));
    }

    private function maybe_upgrade_schema() {
        global $wpdb;
        $t = $wpdb->prefix . 'baskerville_stats';

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'had_fp'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN had_fp TINYINT(1) NOT NULL DEFAULT 0"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'fp_received_at'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN fp_received_at DATETIME NULL"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'visit_count'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN visit_count INT(11) NOT NULL DEFAULT 1"); }

        $idx_any    = $wpdb->get_var("SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{$t}' AND index_name='visit_key' LIMIT 1");
        $idx_unique = $wpdb->get_var("SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{$t}' AND index_name='visit_key' AND non_unique=0 LIMIT 1");
        if ($idx_any && !$idx_unique) { $wpdb->query("DROP INDEX visit_key ON $t"); }
        if (!$idx_unique) { $wpdb->query("ALTER TABLE $t ADD UNIQUE KEY visit_key (visit_key)"); }


        $idx = $wpdb->get_results("SHOW INDEX FROM $t WHERE Key_name='idx_burst'");
        if (!$idx) {
            $wpdb->query("CREATE INDEX idx_burst ON $t (ip, event_type, had_fp, timestamp_utc)");
        }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'fingerprint_hash'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN fingerprint_hash VARCHAR(64) NULL"); $wpdb->query("CREATE INDEX fingerprint_hash ON $t (fingerprint_hash)"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'block_reason'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN block_reason VARCHAR(128) NULL AFTER classification_reason");
            $wpdb->query("CREATE INDEX block_reason ON $t (block_reason)");
        }

        // add top_factor_json (LONGTEXT) + top_factor (VARCHAR) + INDEX
        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'top_factor_json'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN top_factor_json LONGTEXT NULL"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'top_factor'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN top_factor VARCHAR(64) NULL AFTER top_factor_json");
            $wpdb->query("CREATE INDEX top_factor ON $t (top_factor)");
        }
    }


    private function looks_like_browser_ua(string $ua): bool {
        $ua = strtolower($ua);
        // любые из распространённых браузерных токенов
        return (bool) preg_match('~(mozilla/|chrome/|safari/|firefox/|edg/|opera|opr/)~i', $ua);
    }

    /** Если с IP слишком много page-хитов БЕЗ FP за короткое окно — помечаем как bad_bot */
    private function maybe_mark_ip_as_bad_bot_on_burst(string $ip, array &$classification): void {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
        $threshold  = (int) get_option('baskerville_nojs_threshold', 20);

        // считаем ТОЛЬКО page-записи без полученного FP (had_fp=0) за последнее окно
        $cnt = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table
             WHERE ip=%s
               AND event_type='page'
               AND had_fp=0
               AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)",
            $ip, $window_sec
        ));

        if ($cnt >= $threshold) {
            $classification = [
                'classification' => 'bad_bot',
                'reason' => sprintf('Excessive no-JS page hits: %d in %ds', $cnt, $window_sec),
                'risk_score' => max(50, (int)($classification['risk_score'] ?? 0)),
                'details' => [
                    'has_cookie' => (bool)$this->get_cookie_id(),
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($_SERVER['HTTP_USER_AGENT'] ?? ''),
                    'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 100),
                    'burst_window_sec' => $window_sec,
                    'burst_threshold'  => $threshold,
                ]
            ];
        }
    }


    public function init() {
        load_plugin_textdomain('baskerville', false, dirname(plugin_basename(__FILE__)) . '/languages');
        add_action('wp_footer', array($this, 'add_fingerprinting_script'));
    }

    public function add_fingerprinting_script() {
        $rest_url = esc_url_raw( rest_url('baskerville/v1/fp') );
        $wp_nonce = wp_create_nonce('wp_rest');
        ?>
        <script>
        (function () {
          const REST_URL = '<?php echo esc_js($rest_url); ?>';
          const WP_NONCE = '<?php echo esc_js($wp_nonce); ?>';

          // Флаг показа: URL (?baskerville_debug=on) или кука baskerville_show_widgets=1
          const urlFlag = new URLSearchParams(location.search).get('baskerville_debug');
          const showFromUrl = ['1','on','true','yes'].includes((urlFlag||'').toLowerCase());
          const showFromCookie = document.cookie.split('; ').includes('baskerville_show_widgets=1');
          const SHOW_WIDGET = showFromUrl || showFromCookie;

          // === одноразовая отправка на TTL ===
            const FP_MARK_KEY = 'baskerville_fp_sent_at';
            const FP_TAB_KEY  = 'baskerville_fp_sent_tab';
            const FP_TTL_MS   = 6*60*60*1000;

            function fpWasSentThisTab(){ try{return sessionStorage.getItem(FP_TAB_KEY)==='1';}catch{return false;} }
            function fpWasSentRecently(){ try{const t=Number(localStorage.getItem(FP_MARK_KEY)||0);return t>0 && (Date.now()-t)<FP_TTL_MS;}catch{return false;} }
            function markFpSent(){ try{localStorage.setItem(FP_MARK_KEY,String(Date.now()));}catch{} try{sessionStorage.setItem(FP_TAB_KEY,'1');}catch{} }

            function uaFamily(u){u=String(u||'').toLowerCase();const m=u.match(/(chrome|safari|firefox|edg|opr|opera)\/?\d+/);return m?m[1]:'other';}
            try{
              const fam=uaFamily(navigator.userAgent);
              const prev=localStorage.getItem('baskerville_ua_family');
              if (prev && prev!==fam) localStorage.removeItem(FP_MARK_KEY);
              localStorage.setItem('baskerville_ua_family', fam);
            }catch{}

          // Если виджеты не были отрисованы сервером (кэш), создадим контейнеры динамически
          function ensureWidgets() {
            if (!SHOW_WIDGET) return;
            if (!document.getElementById('baskerville-fingerprint')) {
              const f = document.createElement('div');
              f.id = 'baskerville-fingerprint';
              f.style.cssText = 'position:fixed;top:80px;left:10px;background:rgba(0,0,0,.7);color:#fff;padding:15px;border-radius:8px;z-index:9999;max-width:500px;font-family:monospace;font-size:12px;max-height:80vh;overflow-y:auto;';
              f.innerHTML = '<div style="font-weight:bold;margin-bottom:10px;color:#4CAF50;">🔍 Baskerville Fingerprint</div><div id="fingerprint-data">Loading fingerprint...</div><button onclick="document.getElementById(\'baskerville-fingerprint\').style.display=\'none\'" style="position:absolute;top:5px;right:8px;background:none;border:none;color:white;cursor:pointer;font-size:16px;">×</button>';
              document.body.appendChild(f);
            }
            if (!document.getElementById('baskerville-score')) {
              const s = document.createElement('div');
              s.id = 'baskerville-score';
              s.style.cssText = 'position:fixed;top:80px;right:10px;background:rgba(0,0,0,.8);color:#fff;padding:15px;border-radius:8px;z-index:9999;min-width:200px;font-family:monospace;font-size:14px;border:2px solid #4CAF50;';
              s.innerHTML = '<div style="font-weight:bold;margin-bottom:10px;color:#4CAF50;">🛡️ Risk Score</div><div id="score-data">Calculating...</div><button onclick="document.getElementById(\'baskerville-score\').style.display=\'none\'" style="position:absolute;top:5px;right:8px;background:none;border:none;color:white;cursor:pointer;font-size:16px;">×</button>';
              document.body.appendChild(s);
            }
          }
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', ensureWidgets);
          } else {
            ensureWidgets();
          }

          // === утилиты ===
          const hash = async (str) => {
            const enc = new TextEncoder();
            const data = enc.encode(str);
            const buf = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
          };

          const canvasFingerprint = () => {
            try {
              const c = document.createElement('canvas');
              const ctx = c.getContext('2d');
              ctx.textBaseline = 'top';
              ctx.font = '14px Arial';
              ctx.fillStyle = '#f60';
              ctx.fillRect(0, 0, 100, 100);
              ctx.fillStyle = '#069';
              ctx.fillText('Baskerville canvas test', 10, 50);
              return c.toDataURL();
            } catch { return 'unsupported'; }
          };

          const webglFingerprint = () => {
            try {
              const c = document.createElement('canvas');
              const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
              if (!gl) return 'no-webgl';
              const dbg = gl.getExtension('WEBGL_debug_renderer_info');
              const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : 'unknown';
              const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'unknown';
              const exts = (gl.getSupportedExtensions && gl.getSupportedExtensions()) || [];
              return { vendor, renderer, extCount: exts.length };
            } catch { return 'unsupported'; }
          };

          const audioFingerprint = async () => {
            try {
              const Ctx = window.OfflineAudioContext || window.AudioContext || window.webkitAudioContext;
              const ctx = new Ctx(1, 44100, 44100);
              return { sampleRate: ctx.sampleRate };
            } catch { return 'unsupported'; }
          };

          const mathPrecisionQuirk = () => {
            try {
              return [
                Math.acos(0.123),
                Math.tan(0.5),
                Math.log(42),
                Math.sin(Math.PI/3),
              ].map(x=>x.toPrecision(15)).join(',');
            } catch { return 'unsupported'; }
          };

          (async function () {
            try {
              const canvas = canvasFingerprint();
              const webgl = webglFingerprint();
              const audio = await audioFingerprint();
              const mathQuirk = mathPrecisionQuirk();

              const storage = {};
              if (navigator.storage?.estimate) {
                try { Object.assign(storage, await navigator.storage.estimate()); } catch {}
              }

              const permissions = {};
              if (navigator.permissions?.query) {
                for (const n of ['notifications','clipboard-read']) {
                  try { permissions[n] = (await navigator.permissions.query({name:n})).state; }
                  catch { permissions[n] = 'unknown'; }
                }
              }

              const fp = {
                userAgent: navigator.userAgent,
                screen: `${screen.width}x${screen.height}`,
                viewport: `${window.innerWidth}x${window.innerHeight}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                languages: navigator.languages,
                touchSupport: {
                  touchEvent: 'ontouchstart' in window,
                  maxTouchPoints: navigator.maxTouchPoints || 0
                },
                device: {
                  platform: navigator.platform,
                  memory: navigator.deviceMemory || 'unknown',
                  cores: navigator.hardwareConcurrency || 'unknown',
                  webdriver: navigator.webdriver || false
                },
                quirks: { canvas, webgl, audio, mathQuirk },
                dpr: window.devicePixelRatio || 1,
                colorDepth: screen.colorDepth || null,
                outerToInner: ((window.outerWidth||0)*(window.outerHeight||0))/((window.innerWidth||1)*(window.innerHeight||1)),
                aspectRatio: (window.innerWidth/(window.innerHeight||1)),
                viewportToScreen: ((window.innerWidth*window.innerHeight)/(screen.width*screen.height || 1)),
                tzOffsetNow: new Date().getTimezoneOffset(),
                tzOffsetJan: new Date(new Date().getFullYear(),0,1).getTimezoneOffset(),
                tzOffsetJul: new Date(new Date().getFullYear(),6,1).getTimezoneOffset(),
                vendor: navigator.vendor || null,
                productSub: navigator.productSub || null,
                pluginsCount: (navigator.plugins && navigator.plugins.length) || 0,
                pdfViewer: ('pdfViewerEnabled' in navigator) ? navigator.pdfViewerEnabled : null,
                storage,
                webglExtCount: (typeof webgl==='object' && webgl.extCount) ? webgl.extCount : 0,
                permissions
              };

              const concat = [
                fp.userAgent, fp.screen, fp.viewport, fp.timezone, fp.language,
                fp.device.platform, fp.device.memory, fp.device.cores, fp.device.webdriver,
                typeof canvas==='string'?canvas:JSON.stringify(canvas),
                typeof webgl==='string'?webgl:JSON.stringify(webgl),
                typeof audio==='string'?audio:JSON.stringify(audio),
                mathQuirk
              ].join('||');

              const fingerprintHash = await hash(concat);

              if (SHOW_WIDGET) {
                const formatValue = (v) => v==null ? 'null'
                  : (typeof v==='string' && v.length>50 ? v.slice(0,47)+'…'
                     : (typeof v==='object' ? JSON.stringify(v) : String(v)));
                const el = document.getElementById('fingerprint-data');
                if (el) el.innerHTML = `
                  <div style="margin-bottom:6px;"><span style="color:#FFA500;">Hash:</span> ${fingerprintHash.slice(0,16)}...</div>
                  <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Screen:</span> ${fp.screen}</div>
                  <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Viewport:</span> ${fp.viewport}</div>
                  <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Timezone:</span> ${fp.timezone}</div>
                  <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Language:</span> ${fp.language}</div>
                  <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Device:</span> ${formatValue(fp.device)}</div>
                  <div style="margin-bottom:6px;"><span style="color:#87CEEB;">WebGL:</span> ${formatValue(fp.quirks.webgl)}</div>
                  <div style="margin-bottom:6px;"><span style="color:#FFB6C1;">DPR:</span> ${fp.dpr}</div>
                `;
              }

              function readCookie(name){
                const m = document.cookie.match(new RegExp('(?:^|; )'+name.replace(/([.$?*|{}()[\]\\/+^])/g,'\\$1')+'=([^;]*)'));
                return m ? decodeURIComponent(m[1]) : null;
              }

              const payload = {
                  fingerprint: fp,
                  fingerprintHash,
                  url: location.href,
                  referrer: document.referrer || null,
                  ts: Date.now(),
                  visitKey: readCookie('baskerville_visit_key') || null
              };

              if (fpWasSentThisTab() || fpWasSentRecently()) {
                // FP уже есть (и сервер держит HttpOnly baskerville_fp) — POST не нужен
}             else {
                  const send = async () => {
                    try {
                      const res = await fetch(REST_URL, {
                        method: 'POST',
                        headers: {'Content-Type':'application/json','X-WP-Nonce': WP_NONCE},
                        body: JSON.stringify(payload),
                        keepalive: true
                      });
                      if (res.ok) {
                        const result = await res.json();
                        if (SHOW_WIDGET && result?.ok) {
                          const scoreEl = document.getElementById('score-data');
                          if (scoreEl) {
                            const sc = result.score ?? 0;
                            const scoreColor = sc >= 60 ? '#ff6b6b' : sc >= 40 ? '#ffa726' : '#4CAF50';
                            const map = (c)=>({human:['#4CAF50','👤','HUMAN'],bad_bot:['#ff6b6b','🚫','BAD BOT'],ai_bot:['#ff9800','🤖','AI BOT'],bot:['#673AB7','🕷️','BOT']})[c]||['#757575','❓','UNKNOWN'];
                            const [color,icon,label] = map(result.classification?.classification);
                            scoreEl.innerHTML = `
                              <div style="margin-bottom:8px;"><span style="color:${scoreColor};font-size:24px;font-weight:bold;">${sc}/100</span></div>
                              <div style="margin-bottom:6px;"><span style="color:#4CAF50;">Action:</span> <span style="color:${scoreColor};font-weight:bold;">${String(result.action||'').toUpperCase()}</span></div>
                              <div style="margin-bottom:8px;padding:4px 8px;background:rgba(0,0,0,.2);border-left:3px solid ${color};border-radius:4px;">
                                <span style="color:${color};font-weight:bold;">${icon} ${label}</span>
                                <div style="font-size:11px;color:#ccc;margin-top:2px;">${result.classification?.reason||'No reason provided'}</div>
                              </div>
                            `;
                          }
                        }
                      } else {
                        const blob = new Blob([JSON.stringify(payload)], {type:'application/json'});
                        navigator.sendBeacon?.(REST_URL, blob);
                      }
                    } catch {
                      try {
                        const blob = new Blob([JSON.stringify(payload)], {type:'application/json'});
                        navigator.sendBeacon?.(REST_URL, blob);
                      } catch {}
                    }
                  };
                  ('requestIdleCallback' in window)
                    ? requestIdleCallback(send, {timeout: 2000})
                    : setTimeout(send, 1000);
              }
            } catch (e) {
              const el = document.getElementById('fingerprint-data');
              if (el) el.innerHTML = `<div style="color:#ff6b6b;">Error: ${e.message}</div>`;
              // не бросаем дальше — просто молча
            }
          })();
        })();
        </script>
        <?php
    }

    public function load_classes() {
        require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-core.php';
        require_once BASKERVILLE_PLUGIN_PATH . 'admin/class-baskerville-admin.php';

        $this->core = new Baskerville_Core();
        $this->maybe_upgrade_schema();

        if (is_admin()) {
            $this->admin = new Baskerville_Admin();
        }
    }

    public function register_rest_routes() {
        error_log('Baskerville: registering REST routes');
        register_rest_route('baskerville/v1', '/fp', [
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'handle_fp'),
            'permission_callback' => function () {
                return true; // публичный эндпоинт; проверим nonce внутри
            }
        ]);

        register_rest_route('baskerville/v1', '/stats', [
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'handle_stats'),
            'permission_callback' => function () {
                return true; // публичный эндпоинт для просмотра статистики
            }
        ]);

        register_rest_route('baskerville/v1', '/stats/data', [
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'handle_stats_data'),
            'permission_callback' => function () {
                return true; // публичный эндпоинт для данных статистики
            }
        ]);
    }

    public function is_ai_bot_user_agent($user_agent) {
        if (empty($user_agent)) {
            return false;
        }

        $ua = strtolower($user_agent);

        $ai_crawlers = [
            'gptbot',                // OpenAI
            'openai.*crawler',       // OpenAI legacy
            'openai-httplib',        // Python OpenAI lib
            'chatgpt',               // Any generic ChatGPT client
            'anthropic',             // Claude / Anthropic
            'claudebot',             // ClaudeBot
            'google-extended',       // Google's opt-out agent
            'ai crawler',            // Generic
            'bytespider',            // ByteDance
            'yisouspider',           // Baidu affiliate
            'youdao',                // NetEase AI
            'ccbot',                 // Common Crawl (training source)
            'petalbot',              // Huawei
            'facebookbot',           // Facebook/Meta AI research
            'facebot',               // Meta
            'amazonbot',             // Amazon AI research
            'cohere',                // Cohere.ai
            'ai\scrawler',          // catch-all
            'meta-externalagent',    // facebook training
        ];

        foreach ($ai_crawlers as $pattern) {
            if (preg_match('/' . $pattern . '/i', $ua)) {
                return true;
            }
        }

        return false;
    }

    private function cookie_secret(): string {
        $secret = (string) get_option('baskerville_cookie_secret', '');
        if (!$secret) {
            $secret = bin2hex(random_bytes(32));
            update_option('baskerville_cookie_secret', $secret, true);
        }
        return $secret;
    }


    private function update_visit_stats_by_key(string $visit_key, array $evaluation, array $classification, ?string $fp_hash = null): bool {
        global $wpdb;
        $t = $wpdb->prefix.'baskerville_stats';

        // попробуем также прочитать серверную fp-куку (если есть)
        $fp_cookie = $this->read_fp_cookie();
        [$top_json, $top_name] = $this->extract_top_factors($evaluation, $fp_cookie);

        $data = [
            'score'                 => (int)$evaluation['score'],
            'classification'        => (string)$classification['classification'],
            'evaluation_json'       => json_encode($evaluation),
            'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
            'classification_reason' => (string)($classification['reason'] ?? ''),
            'had_fp'                => 1,
            'fp_received_at'        => current_time('mysql', true),
        ];
        $fmt = ['%d','%s','%s','%s','%s','%d','%s'];

        if ($fp_hash)   { $data['fingerprint_hash'] = $fp_hash;   $fmt[] = '%s'; }
        if ($top_json)  { $data['top_factor_json']  = $top_json;  $fmt[] = '%s'; }
        if ($top_name)  { $data['top_factor']       = $top_name;  $fmt[] = '%s'; }

        $ok = $wpdb->update($t, $data, ['visit_key' => $visit_key], $fmt, ['%s']);
        if ($ok === false) {
            error_log('Baskerville: update by visit_key failed - '.$wpdb->last_error);
            return false;
        }
        return $ok > 0;
    }


    private function sign_cookie(string $token, int $ts, string $ipk): string {
        // включаем ip_key в подпись
        return hash_hmac('sha256', $token . '.' . $ts . '.' . $ipk, $this->cookie_secret());
    }

    private function make_cookie_value(): string {
        $token = bin2hex(random_bytes(16));
        $ts    = time();
        $ipk   = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
        $sig   = $this->sign_cookie($token, $ts, $ipk);
        // новый формат: token.ts.ipk.sig
        return $token . '.' . $ts . '.' . $ipk . '.' . $sig;
    }

    /** Возвращает токен, если подпись валидна и не просрочена. Поддерживает старый формат (3 части). */
    public function get_cookie_id(): ?string {
        $raw = $_COOKIE['baskerville_id'] ?? '';
        if (!$raw) return null;
        $parts = explode('.', $raw);

        if (count($parts) === 4) {
            [$token, $ts, $ipk, $sig] = $parts;
            if (!ctype_xdigit($token) || !ctype_digit($ts)) return null;
            $cur_ipk = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
            // подпись от текущего ip_key
            if (!hash_equals($this->sign_cookie($token, (int)$ts, $cur_ipk), $sig)) return null;
            if ((int)$ts < time() - 60*60*24*90) return null;
            return $token;
        }

        // legacy 3-part: token.ts.sig — принимаем, но при первой возможности перевыпустим
        if (count($parts) === 3) {
            [$token, $ts, $sig] = $parts;
            if (!ctype_xdigit($token) || !ctype_digit($ts)) return null;
            $legacy_ok = hash_equals(hash_hmac('sha256', $token . '.' . (int)$ts, $this->cookie_secret()), $sig);
            if (!$legacy_ok) return null;
            if ((int)$ts < time() - 60*60*24*90) return null;
            // пометим для ротации в ensure_baskerville_cookie()
            return $token;
        }

        return null;
    }

    /** Ставим HttpOnly/Secure куку, если её нет или она невалидна */
    public function ensure_baskerville_cookie(): void {
        if (headers_sent()) return;

        $this->had_cookie_on_arrival = ($this->get_cookie_id() !== null);

        if (!$this->had_cookie_on_arrival) {
            $value = $this->make_cookie_value();
            // чтобы текущий же запрос мог использовать id — подложим в $_COOKIE
            $_COOKIE['baskerville_id'] = $value;

            setcookie('baskerville_id', $value, [
                'expires'  => time() + 60*60*24*365, // год хранения
                'path'     => '/',
                'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }
    }


    public function is_bot_user_agent($user_agent) {
        if (empty($user_agent)) {
            return false;
        }

        $ua = strtolower($user_agent);

        $bot_patterns = [
            'bot', 'spider', 'crawl', 'slurp',
            'googlebot', 'bingbot', 'baiduspider', 'yandexbot', 'duckduckbot',
            'sogou', 'exabot', 'seznambot', 'petalbot', 'applebot',
            'facebookexternalhit', 'facebookcatalog', 'twitterbot', 'linkedinbot',
            'pinterestbot', 'whatsapp', 'telegrambot', 'slackbot', 'discordbot',
            'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'uptimerobot',
            'structured-data',
            'curl', 'wget', 'python-requests', 'aiohttp', 'urllib', 'httpie',
            'go-http-client', 'okhttp', 'java', 'libcurl', 'node-fetch',
            'axios', 'postmanruntime', 'insomnia', 'restsharp', 'powershell'
        ];

        foreach ($bot_patterns as $pattern) {
            if (strpos($ua, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    public function classify_client(array $payload, array $server_ctx = []) {
        $user_agent = $server_ctx['headers']['user_agent'] ?? '';
        $ua_lower   = strtolower($user_agent);

        // Былa ли КУКА в исходном запросе (не доверяем подменам $_COOKIE)
        $client_cookie_header = $_SERVER['HTTP_COOKIE'] ?? '';
        $had_cookie = (strpos($client_cookie_header, 'baskerville_id=') !== false) && ($this->get_cookie_id() !== null);

        // Оценка риска
        $evaluation = $this->baskerville_score_fp($payload, $server_ctx);
        $risk_score = (int) ($evaluation['score'] ?? 0);

        // Похоже ли на браузер
        $looks_like_browser = (bool) preg_match('~(mozilla/|chrome/|safari/|firefox/|edg/|opr/|opera)~i', $user_agent);

        // Явные небраузерные клиенты
        $nonbrowser_signatures = [
            'curl','wget','python-requests','go-http-client','httpie','libcurl',
            'java','okhttp','node-fetch','axios','aiohttp','urllib','postmanruntime',
            'insomnia','restsharp','powershell','httpclient','http.rb','ruby','perl',
            'traefik','kube-probe','healthcheck','pingdom','datadog','sumologic'
        ];
        $is_nonbrowser_client = false;
        foreach ($nonbrowser_signatures as $sig) {
            if (strpos($ua_lower, $sig) !== false) { $is_nonbrowser_client = true; break; }
        }
        // Пустой/очень короткий UA тоже считаем небраузерным
        if (!$is_nonbrowser_client && strlen(trim($ua_lower)) < 6) { $is_nonbrowser_client = true; }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $vc = $this->verify_crawler_ip($ip, $user_agent);
        $verified_crawler = ($vc['claimed'] && $vc['verified']);

        if ($vc['claimed'] && !$vc['verified']) {
            $risk_score = max($risk_score, 50);
        }
        if ($verified_crawler) {
            return [
                'classification' => 'verified_bot',
                'reason' => 'Verified crawler (' . ($vc['host'] ?: 'rDNS') . ')',
                'crawler_verified' => true,
                'risk_score' => min(10, $risk_score),
            ];
        }

        // 1) Явные AI-боты по UA — приоритетно
        if ($this->is_ai_bot_user_agent($user_agent)) {
            return [
                'classification' => 'ai_bot',
                'reason'         => 'AI bot detected by user agent',
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie' => $had_cookie,
                    'is_ai_bot'  => true,
                    'is_bot_ua'  => $this->is_bot_user_agent($user_agent),
                    'user_agent' => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : '')
                ]
            ];
        }

        // 2) BAD BOT: нет куки + небраузерный клиент (включая пустой/короткий UA) и не «хороший» краулер
        if (!$had_cookie && ($is_nonbrowser_client || (!$looks_like_browser && !$verified_crawler))) {
            return [
                'classification' => 'bad_bot',
                'reason'         => 'No prior cookie + non-browser User-Agent',
                'risk_score'     => max(50, $risk_score),
                'details'        => [
                    'has_cookie' => false,
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($user_agent),
                    'user_agent' => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : '')
                ]
            ];
        }

        // 3) BAD BOT: высокий риск и не похоже на браузер
        if ($risk_score >= 50 && !$looks_like_browser && !$verified_crawler) {
            return [
                'classification' => 'bad_bot',
                'reason'         => 'High risk (≥50) and non-browser UA',
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie' => $had_cookie,
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($user_agent),
                    'user_agent' => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : '')
                ]
            ];
        }

        // 4) Прочие боты: бот-UA (в т.ч. хорошие краулеры) ИЛИ высокий риск
        $threshold = 30;
        if ($this->is_bot_user_agent($user_agent) || $risk_score >= $threshold) {
            return [
                'classification' => 'bot',
                'reason'         => $this->is_bot_user_agent($user_agent)
                                        ? 'Bot detected by user agent'
                                        : 'High risk score',
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie'               => $had_cookie,
                    'is_ai_bot'                => false,
                    'is_bot_ua'                => $this->is_bot_user_agent($user_agent),
                    'user_agent'               => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                    'score_threshold_exceeded' => $risk_score >= $threshold
                ]
            ];
        }

        // 5) Human
        return [
            'classification' => 'human',
            'reason'         => 'Appears to be human user',
            'risk_score'     => $risk_score,
            'details'        => [
                'has_cookie'               => $had_cookie,
                'is_ai_bot'                => false,
                'is_bot_ua'                => false,
                'user_agent'               => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                'score_threshold_exceeded' => false
            ]
        ];
    }


    public function baskerville_score_fp(array $payload, array $server_ctx = []) : array {
        $fp  = $payload['fingerprint'] ?? [];
        $svh = $server_ctx['headers'] ?? [];

        $score = 0;
        $reasons = [];
        $contrib = [];

        // ---- helpers ----
        $ua = strtolower($fp['userAgent'] ?? ($svh['user_agent'] ?? ''));
        $is_mobile_ua = (bool)preg_match('~(iphone|android|mobile|ipad|ipod|iemobile|blackberry|opera mini)~i', $ua);
        $is_ios = (bool)preg_match('~(iphone|ipad|ipod)~i', $ua);
        $is_android = (bool)preg_match('~android~i', $ua);
        $is_windows = (bool)preg_match('~windows nt~i', $ua);
        $is_mac = (bool)preg_match('~mac os x~i', $ua);


        $dpr = null;
        $webglExtCount = 0;
        $pluginsCount = 0;
        $maxTouchPoints = 0;
        $outerToInner = 0.0;
        $viewportToScreen = 0.0;
        $lang = '';
        $acceptLang = strtolower($svh['accept_language'] ?? '');
        $hasDST = null;


        $has_js_fp = !empty($fp);

        $ua_server = strtolower($svh['user_agent'] ?? '');
        if (preg_match('~(curl|wget|python-requests|go-http-client|okhttp|node-fetch|postmanruntime)~', $ua_server)) {
            $score += 30; $reasons[] = 'Non-browser HTTP client';
            $contrib[] = ['key'=>'non_browser_http', 'delta'=>30, 'why'=>'Non-browser HTTP client'];
        }
        if (!$this->looks_like_browser_ua($ua_server)) {
            $score += 30;
            $reasons[] = 'Non-browser-like User-Agent';
            $contrib[] = ['key'=>'non_browser_user_agent', 'delta'=>30, 'why'=>'Non-browser-like User-Agent'];

        }
        if (empty($svh['accept_language'])) {
            $score += 5;  $reasons[] = 'Missing Accept-Language';
            $contrib[] = ['key'=>'missing_accept_language', 'delta'=>5, 'why'=>'Missing Accept-Language'];
        }
        if (preg_match('~chrome/~i', $ua_server) && empty($svh['sec_ch_ua'])) {
            $score += 5;  $reasons[] = 'Missing Client Hints for Chrome-like UA';
            $contrib[] = ['key'=>'missing_hints_chrome', 'delta'=>5, 'why'=>'Missing Client Hints for Chrome-like UA'];
        }

        if ($this->is_bot_user_agent($ua_server)) {
            // Сильный аплифт: фиксируем минимум 70 и добавляем 25 поверх уже набранного
            // (чтобы гарантированно уйти в зону challenge/rate_limit даже при прочих «мягких» сигналах)
            $score += 25;
            if ($score < 70) $score = 70;
            $reasons[] = 'Bot UA detected';
            $contrib[] = ['key'=>'bot_ua', 'delta'=>25, 'why'=>'Bot UA detected'];
        }

        if ($this->is_ai_bot_user_agent($ua_server)) {
            $score += 10;
            $reasons[] = 'AI bot UA detected';
            $contrib[] = ['key'=>'ai_bot_ua', 'delta'=>10, 'why'=>'AI bot UA detected'];
        }

        if ($has_js_fp) {
            $screen = $fp['screen'] ?? '';
            $viewport = $fp['viewport'] ?? '';
            [$sw,$sh] = array_map('intval', explode('x', $screen.'x0'));
            [$vw,$vh] = array_map('intval', explode('x', $viewport.'x0'));

            $dpr = (float)($fp['dpr'] ?? 1.0);
            $pluginsCount = (int)($fp['pluginsCount'] ?? 0);
            $webdriver = !empty($fp['device']['webdriver']);
            $maxTouchPoints = (int)($fp['touchSupport']['maxTouchPoints'] ?? 0);
            $touchEvent = !empty($fp['touchSupport']['touchEvent']);
            $pdfViewer = $fp['pdfViewer'] ?? null;
            $webglExtCount = (int)($fp['webglExtCount'] ?? 0);
            $outerToInner = (float)($fp['outerToInner'] ?? 0);
            $viewportToScreen = (float)($fp['viewportToScreen'] ?? 0);
            $lang = strtolower($fp['language'] ?? '');
            $acceptLang = strtolower($svh['accept_language'] ?? '');

            $tzJan = (int)($fp['tzOffsetJan'] ?? 0);
            $tzJul = (int)($fp['tzOffsetJul'] ?? 0);
            $hasDST = ($tzJan !== 0 && $tzJul !== 0 && $tzJan !== $tzJul);

            if ($webdriver) {
                $score += 35; $reasons[] = 'navigator.webdriver=true';
                $contrib[] = ['key'=>'webdriver', 'delta'=>35, 'why'=>'navigator.webdriver=true'];
            }

            // безопасная проверка WebGL без доступа к $fp['quirks'] напрямую
            $webglMode = $fp['quirks']['webgl'] ?? null;
            if ($webglExtCount === 0 && $webglMode !== null && $webglMode !== 'no-webgl') {
                $score += 10; $reasons[] = 'WebGL extensions = 0';
                $contrib[] = ['key'=>'no_web_gl', 'delta'=>10, 'why'=>'WebGL extensions = 0'];
            }

            // 2) DPR vs UA
            if ($is_mobile_ua && $dpr <= 1.0) {
                $score += 20; $reasons[] = 'Mobile UA but DPR<=1';
                $contrib[] = ['key'=>'mobile_ua_small_dpr', 'delta'=>20, 'why'=>'Mobile UA but DPR<=1'];
            }
            if ($is_windows && $dpr > 1.5) {
                // Windows c DPR>1.5 бывает из-за масштабирования, но реже
                $score += 6;  $reasons[] = 'Windows with high DPR';
                $contrib[] = ['key'=>'windows_high_dpr', 'delta'=>6, 'why'=>'Windows with high DPR'];
            }
            if ($is_mac && $dpr < 2 && preg_match('~\bMacintosh\b~i', $fp['userAgent'] ?? '')) {
                // Современные маки почти всегда DPR=2 (Retina)
                $score += 5;  $reasons[] = 'Mac UA but DPR<2';
                $contrib[] = ['key'=>'mac_ua_low_dpr', 'delta'=>5, 'why'=>'Mac UA but DPR<2'];
            }

            // 3) Viewport vs Screen
            if ($sw > 0 && $sh > 0 && $vw > 0 && $vh > 0) {
                if ($viewportToScreen && $viewportToScreen < 0.25) {
                    $score += 15;
                    $reasons[] = 'Very small viewport relative to screen (<0.25)';
                    $contrib[] = ['key'=>'small_viewport', 'delta'=>15, 'why'=>'Very small viewport relative to screen (<0.25)'];
                }
                if ($vw < 800 && !$is_mobile_ua && $dpr <= 1.1) {
                    $score += 8;
                    $reasons[] = 'Desktop UA with very small viewport';
                    $contrib[] = ['key'=>'desktop_ua_small_viewport', 'delta'=>8, 'why'=>'Desktop UA with very small viewport'];
                }
            } else {
                $score += 3; $reasons[] = 'Missing/invalid screen or viewport';
                $contrib[] = ['key'=>'missing_viewport', 'delta'=>3, 'why'=>'Missing/invalid screen or viewport'];
            }

            // 4) Touch vs UA
            if ($is_mobile_ua && $maxTouchPoints === 0 && !$touchEvent) {
                $score += 12; $reasons[] = 'Mobile UA without touch support';
                $contrib[] = ['key'=>'mobile_ua_no_touch', 'delta'=>12, 'why'=>'Mobile UA without touch support'];
            }
            if (!$is_mobile_ua && $maxTouchPoints > 0 && $dpr <= 1.1 && $vw > 1200) {
                $score += 4; $reasons[] = 'Desktop UA with touch points (mismatch)';
                $contrib[] = ['key'=>'desktop_ua_with_touch', 'delta'=>4, 'why'=>'Desktop UA with touch points (mismatch)'];
            }

            // 5) Plugins
            if ($pluginsCount === 0 && $is_windows) {
                $score += 6; $reasons[] = 'Windows with zero plugins';
                $contrib[] = ['key'=>'zero_plugins', 'delta'=>6, 'why'=>'Windows with zero plugins'];
            }

            // 6) PDF viewer flag (Chrome-специфика)
            if ($pdfViewer === false && preg_match('~chrome/|crios/|edg/~i', $ua)) {
                $score += 4; $reasons[] = 'Chrome-like UA without pdfViewer';
                $contrib[] = ['key'=>'chrome_no_pdf', 'delta'=>4, 'why'=>'Chrome-like UA without pdfViewer'];
            }

            // 7) Outer/inner отношения окна
            if ($outerToInner > 1.6 || $outerToInner < 1.0) {
                // у headless часто странные рамки
                $score += 5; $reasons[] = 'Odd outer/inner ratio';
                $contrib[] = ['key'=>'odd_outer_inner_ratio', 'delta'=>5, 'why'=>'Odd outer/inner ratio'];
            }

            // 8) Языки: сверка navigator.language и Accept-Language
            if ($lang && $acceptLang && strpos($acceptLang, substr($lang,0,2)) === false) {
                $score += 5; $reasons[] = 'Language mismatch vs Accept-Language';
                $contrib[] = ['key'=>'language_mismatch', 'delta'=>5, 'why'=>'Language mismatch vs Accept-Language'];
            }

            // 9) DST: в изолированных дата-центрах/контейнерах часто без DST
            if ($is_mobile_ua && !$hasDST) {
                $score += 3; $reasons[] = 'Mobile UA but no DST observed';
                $contrib[] = ['key'=>'mobile_ua_no_dst', 'delta'=>3, 'why'=>'Mobile UA but no DST observed'];
            }
        }

        // Нормировка/порог
        if ($score < 0) $score = 0;
        if ($score > 100) $score = 100;

        // Рекомендация
        $action = 'allow';
        if     ($score >= 60) $action = 'challenge'; // или ban для очень строгих
        elseif ($score >= 40) $action = 'rate_limit';
        else                   $action = 'allow';

        // top factors: сортируем по |delta| убыв.
        usort($contrib, function($a,$b){ return abs($b['delta']) <=> abs($a['delta']); });
        $top = array_slice($contrib, 0, 6);

        return [
            'score'   => $score,
            'action'  => $action,
            'reasons' => $reasons,
            'signals' => [
                'is_mobile_ua' => $is_mobile_ua,
                'dpr' => $dpr,
                'viewportToScreen' => $viewportToScreen,
                'webglExtCount' => $webglExtCount,
                'pluginsCount' => $pluginsCount,
                'maxTouchPoints' => $maxTouchPoints,
                'outerToInner' => $outerToInner,
                'lang' => $lang,
                'accept_language' => $acceptLang,
                'hasDST' => $hasDST,
            ],
            'contrib' => $contrib,
            'top_factors' => $top,
        ];
    }

    public function handle_fp( WP_REST_Request $request ) {
        $nonce = $request->get_header('x-wp-nonce');
        if ($nonce && ! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_REST_Response(['error' => 'invalid_nonce'], 403);
        }

        $body = $request->get_json_params();
        if (empty($body)) {
            return new WP_REST_Response(['error' => 'empty_payload'], 400);
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $headers = [
            'accept'          => $_SERVER['HTTP_ACCEPT'] ?? null,
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'user_agent'      => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'sec_ch_ua'       => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        ];
        $cookie_id = $this->get_cookie_id();

        // считаем
        try {
            $evaluation     = $this->baskerville_score_fp($body, ['headers' => $headers]);
            $classification = $this->classify_client($body, ['headers' => $headers]);
        } catch (Exception $e) {
            error_log('Baskerville evaluation error: ' . $e->getMessage());
            $evaluation = ['score' => 0, 'action' => 'error', 'reasons' => ['evaluation_error'], 'top_factors'=>[]];
            $classification = ['classification' => 'unknown', 'reason' => 'Classification error', 'risk_score' => 0];
        }

        // кука fp (HttpOnly, подписанная)
        $ua   = $headers['user_agent'] ?? '';
        $ua_hash = sha1((string)$ua);
        $ttl_sec = 6*60*60;
        $payload_fp = [
            'v'=>1,'ts'=>time(),'ttl'=>$ttl_sec,
            'ipk'=>$this->ip_key($ip),
            'ua'=>substr($ua_hash,0,16),
            'bid'=>substr($cookie_id ?: '', 0, 16),
            'score'=>(int)($evaluation['score'] ?? 0),
            'top'=>array_map(function($x){ return [
                'key'=>(string)($x['key']??''), 'delta'=>(int)($x['delta']??0), 'why'=>(string)($x['why']??'')
            ];}, array_slice($evaluation['top_factors'] ?? [], 0, 6))
        ];
        $raw = json_encode($payload_fp, JSON_UNESCAPED_SLASHES);
        $sig = hash_hmac('sha256', $raw, $this->cookie_secret());
        $val = $this->b64u_enc($raw) . '.' . $sig;
        setcookie('baskerville_fp', $val, [
            'expires'=>time()+$ttl_sec,'path'=>'/','secure'=>is_ssl(),'httponly'=>true,'samesite'=>'Lax',
        ]);

        // mark fp seen
        if ($ip) $this->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180));
        if ($cookie_id) $this->fc_set("fp_seen_cookie:{$cookie_id}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180));
        $this->fc_delete("nojs_cnt:{$ip}");

        $fp_hash   = isset($body['fingerprintHash']) ? substr($body['fingerprintHash'], 0, 64) : null;
        $visit_key = isset($body['visitKey']) ? preg_replace('~[^a-f0-9]~i', '', (string)$body['visitKey']) : '';

        if ($visit_key) {
            $this->update_visit_stats_by_key($visit_key, $evaluation, $classification, $fp_hash);
            return new WP_REST_Response([
                'ok'=>true,'score'=>(int)($evaluation['score']??0),
                'action'=>$evaluation['action'] ?? 'allow',
                'why'=>$evaluation['reasons'] ?? [],
                'classification'=>$classification,
            ], 200);
        }

        // fallback: прикрепить к последнему page-хиту без FP
        global $wpdb;
        $table = $wpdb->prefix.'baskerville_stats';
        $wpdb->query("SET time_zone = '+00:00'");

        $attach_window_sec = (int) get_option('baskerville_fp_attach_window_sec', 180);
        $row_id = null;
        if ($ip && $cookie_id) {
            $row_id = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM $table
                 WHERE ip=%s AND baskerville_id=%s AND event_type='page' AND had_fp=0
                   AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)
                 ORDER BY timestamp_utc DESC LIMIT 1",
                $ip, $cookie_id, $attach_window_sec
            ));
        }

        [$top_json, $top_name] = $this->extract_top_factors($evaluation, $this->read_fp_cookie());
        $score = (int)($evaluation['score'] ?? 0);
        $cls   = (string)($classification['classification'] ?? 'unknown');
        $why   = implode('; ', $evaluation['reasons'] ?? []);
        $cls_r = (string)($classification['reason'] ?? '');

        if ($row_id) {
            $wpdb->update($table, [
                'score'=>$score,'classification'=>$cls,'evaluation_json'=>json_encode($evaluation),
                'score_reasons'=>$why,'classification_reason'=>$cls_r,'had_fp'=>1,
                'fp_received_at'=>current_time('mysql', true),'fingerprint_hash'=>$fp_hash,
                'top_factor_json'=>$top_json,'top_factor'=>$top_name,
            ], ['id'=>(int)$row_id], ['%d','%s','%s','%s','%s','%d','%s','%s','%s','%s'], ['%d']);
        } else {
            $visit_key = hash('sha256', ($ip ?? '') . '|' . ($cookie_id ?? '') . '|' . microtime(true) . '|' . wp_generate_uuid4());
            $wpdb->insert($table, [
                'visit_key'=>$visit_key,'ip'=>$ip ?: '','baskerville_id'=>$cookie_id ?: '',
                'timestamp_utc'=>current_time('mysql', true),'score'=>$score,'classification'=>$cls,
                'user_agent'=>$headers['user_agent'] ?? '','evaluation_json'=>json_encode($evaluation),
                'score_reasons'=>$why,'classification_reason'=>$cls_r,'event_type'=>'page',
                'had_fp'=>1,'fp_received_at'=>current_time('mysql', true),'fingerprint_hash'=>$fp_hash,
                'top_factor_json'=>$top_json,'top_factor'=>$top_name,
            ], ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%d','%s','%s','%s']);
        }

        return new WP_REST_Response([
            'ok'=>true,'score'=>$score,'action'=>$evaluation['action'] ?? 'allow',
            'why'=>$evaluation['reasons'] ?? [], 'classification'=>$classification,
        ], 200);
    }

    public function create_stats_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'baskerville_stats';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
          id bigint(20) NOT NULL AUTO_INCREMENT,
          visit_key varchar(255) NOT NULL,
          ip varchar(45) NOT NULL,
          baskerville_id varchar(100) NOT NULL,
          fingerprint_hash varchar(64) NULL,
          timestamp_utc datetime NOT NULL,
          score int(3) NOT NULL DEFAULT 0,
          classification varchar(50) NOT NULL DEFAULT 'unknown',
          user_agent text NOT NULL,
          evaluation_json longtext NOT NULL,
          score_reasons text NOT NULL,
          classification_reason text NOT NULL,
          block_reason varchar(128) NULL,
          event_type varchar(16) NOT NULL DEFAULT 'fp',

          had_fp tinyint(1) NOT NULL DEFAULT 0,
          fp_received_at datetime NULL,
          visit_count int(11) NOT NULL DEFAULT 1,

          top_factor_json longtext NULL,
          top_factor varchar(64) NULL,

          created_at timestamp DEFAULT CURRENT_TIMESTAMP,
          updated_at timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          UNIQUE KEY visit_key (visit_key),
          KEY ip (ip),
          KEY baskerville_id (baskerville_id),
          KEY timestamp_utc (timestamp_utc),
          KEY classification (classification),
          KEY score (score),
          KEY event_type (event_type),
          KEY fingerprint_hash (fingerprint_hash),
          KEY block_reason (block_reason),
          KEY top_factor (top_factor)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        // Add version option to track schema changes
        add_option('baskerville_db_version', '1.0');
    }

    /** Возвращает [json_string|null, top_name|null] из $evaluation['top_factors'] или из fp-cookie. */
    private function extract_top_factors(array $evaluation, ?array $fp_cookie = null): array {
        $top = $evaluation['top_factors'] ?? $evaluation['contrib'] ?? null;

        if ((!is_array($top) || !$top) && is_array($fp_cookie) && !empty($fp_cookie['top'])) {
            $top = $fp_cookie['top'];
        }

        if (!is_array($top) || !$top) return [null, null];

        // нормализуем: берем первые 6 факторов
        $norm = [];
        foreach (array_slice($top, 0, 6) as $x) {
            $norm[] = [
                'key'   => (string)($x['key']   ?? ''),
                'delta' => (int)   ($x['delta'] ?? 0),
                'why'   => (string)($x['why']   ?? '')
            ];
        }

        // главный фактор = по максимальному |delta|, fallback — первый по порядку
        $main = null; $best = -1;
        foreach ($norm as $x) {
            $w = abs((int)$x['delta']);
            if ($w > $best) { $best = $w; $main = (string)$x['key']; }
        }
        if (!$main && !empty($norm[0]['key'])) $main = (string)$norm[0]['key'];

        // ограничим имя (на всякий случай)
        if ($main !== null) { $main = mb_substr($main, 0, 64); }

        return [json_encode($norm, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES), $main];
    }

    public function get_retention_days() {
        return (int) get_option('baskerville_retention_days', BASKERVILLE_DEFAULT_RETENTION_DAYS);
    }

    public function cleanup_old_stats($force = false) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'baskerville_stats';
        $retention_days = $this->get_retention_days();

        // Safety check - don't clean if retention is less than 1 day unless forced
        if ($retention_days < 1 && !$force) {
            error_log('Baskerville: Cleanup skipped - retention period too short');
            return false;
        }

        // Delete records older than retention period
        $result = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE timestamp_utc < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                $retention_days
            )
        );

        if ($result === false) {
            error_log('Baskerville: Cleanup failed - ' . $wpdb->last_error);
            return false;
        }

        if ($result > 0) {
            error_log("Baskerville: Cleaned up $result old statistics records (older than $retention_days days)");
        }

        return $result;
    }

    public function maybe_cleanup_stats() {
        // Run cleanup occasionally (random chance to spread load)
        if (wp_rand(1, 100) <= 5) { // 5% chance on each request
            $this->cleanup_old_stats();
        }
    }

    public function get_timeseries_data($hours = 24) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        // на всякий — приводим таймзону коннекта к UTC
        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            FROM_UNIXTIME(
              FLOOR(UNIX_TIMESTAMP(CONVERT_TZ(timestamp_utc,'+00:00','+00:00'))/900)*900
            ) AS time_slot,
            COUNT(*) AS total_visits,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score
          FROM $table_name
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
          GROUP BY time_slot
          ORDER BY time_slot ASC
        ";
        $results = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A);

        $out = [];
        foreach ($results ?: [] as $r) {
            $total   = (int)$r['total_visits'];
            $human   = (int)$r['human_count'];
            $bad     = (int)$r['bad_bot_count'];
            $ai      = (int)$r['ai_bot_count'];
            $bot     = (int)$r['bot_count'];
            $verified = (int)$r['verified_bot_count'];
            $botsum   = $bad + $ai + $bot + $verified;

            $out[] = [
                'time'            => $r['time_slot'],
                'total_visits'    => $total,
                'human_count'     => $human,
                'bad_bot_count'   => $bad,
                'ai_bot_count'    => $ai,
                'bot_count'       => $bot,
                'verified_bot_count' => $verified,
                'bot_percentage'  => $total ? round($botsum*100/$total,1) : 0,
                'avg_score'       => round((float)$r['avg_score'],1),
            ];
        }
        return $out;
    }

    public function get_summary_stats_window($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours*3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) AS total_visits,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score
          FROM $table
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $total = (int)($row['total_visits'] ?? 0);
        $bots = (int)($row['bad_bot_count'] ?? 0)
              + (int)($row['ai_bot_count'] ?? 0)
              + (int)($row['bot_count'] ?? 0)
              + (int)($row['verified_bot_count'] ?? 0);
        $hum   = (int)($row['human_count'] ?? 0);

        return [
            'total_visits'     => $total,
            'human_count'      => $hum,
            'human_percentage' => $total ? round($hum*100/$total, 1) : 0,
            'bad_bot_count'    => (int)($row['bad_bot_count'] ?? 0),
            'ai_bot_count'     => (int)($row['ai_bot_count'] ?? 0),
            'bot_count'        => (int)($row['bot_count'] ?? 0),
            'bot_total'        => $bots,
            'bot_percentage'   => $total ? round($bots*100/$total, 1) : 0,
            'avg_score'        => round((float)($row['avg_score'] ?? 0), 1),
            'hours'            => $hours,
        ];
    }


    public function get_summary_stats() {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';
        $days  = (int)$this->get_retention_days();
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days*86400);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) total_visits,
            COUNT(DISTINCT ip) unique_ips,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score,
            MIN(timestamp_utc) first_record,
            MAX(timestamp_utc) last_record
          FROM $table
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A);
        if (!$row) return [];

        $total = (int)$row['total_visits'];
        $bots = (int)($row['bad_bot_count'] ?? 0)
              + (int)($row['ai_bot_count'] ?? 0)
              + (int)($row['bot_count'] ?? 0)
              + (int)($row['verified_bot_count'] ?? 0);

        return [
            'total_visits'     => $total,
            'unique_ips'       => (int)$row['unique_ips'],
            'human_count'      => (int)$row['human_count'],
            'human_percentage' => $total ? round($row['human_count']*100/$total,1) : 0,
            'bad_bot_count'    => (int)$row['bad_bot_count'],
            'ai_bot_count'     => (int)$row['ai_bot_count'],
            'bot_count'        => (int)$row['bot_count'],
            'bot_total'        => $bots,
            'bot_percentage'   => $total ? round($bots*100/$total,1) : 0,
            'avg_score'        => round((float)$row['avg_score'],1),
            'retention_days'   => $days,
            'first_record'     => $row['first_record'],
            'last_record'      => $row['last_record'],
        ];
    }

    public function save_visit_stats($ip, $baskerville_id, $evaluation, $classification, $user_agent, $event_type = 'fp', $visit_key = null) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        $visit_key = $visit_key ?: $this->make_visit_key($ip, $baskerville_id);

        $fp_cookie = $this->read_fp_cookie();
        [$top_json, $top_name] = $this->extract_top_factors((array)$evaluation, $fp_cookie);

        $data = [
            'visit_key' => $visit_key,
            'ip' => $ip,
            'baskerville_id' => $baskerville_id,
            'timestamp_utc' => current_time('mysql', true),
            'score' => (int)$evaluation['score'],
            'classification' => (string)$classification['classification'],
            'user_agent' => $user_agent,
            'evaluation_json' => json_encode($evaluation),
            'score_reasons' => implode('; ', $evaluation['reasons'] ?? []),
            'classification_reason' => (string)($classification['reason'] ?? ''),
            'event_type' => $event_type,
            'top_factor_json' => $top_json,
            'top_factor' => $top_name,
        ];
        $fmt = ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%s'];

        $ok = $wpdb->insert($table_name, $data, $fmt);
        if ($ok === false) {
            error_log('Baskerville: insert failed - '.$wpdb->last_error);
            return false;
        }
        return $visit_key;
    }

    public function handle_stats(WP_REST_Request $request) {
        // Return HTML page for statistics visualization
        $stats_url = rest_url('baskerville/v1/stats/data');

        // Set proper headers
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=UTF-8');
        }

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Baskerville Statistics</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 30px;
                }
                h1 {
                    text-align: center;
                    color: #2c3e50;
                    margin-bottom: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }
                .stat-card.human { background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); }
                .stat-card.bot { background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%); }
                .stat-card.ai-bot { background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); }
                .stat-card.score { background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); }
                .stat-card.block { background: linear-gradient(135deg, #e53935 0%, #d32f2f 100%); }

                .stat-number {
                    font-size: 2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                .stat-label {
                    font-size: 0.9em;
                    opacity: 0.9;
                }
                .chart-container {
                    margin: 30px 0;
                    height: 400px;
                }
                .controls {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 20px;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                .control-button {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    background: #3498db;
                    color: white;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                .control-button:hover {
                    background: #2980b9;
                }
                .control-button.active {
                    background: #2c3e50;
                }
                .loading {
                    text-align: center;
                    padding: 20px;
                    color: #666;
                }
              .charts-row {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 20px;
                align-items: stretch;
                margin-top: 10px;
              }
              .baskerville-logo{
                  height: 46px;      /* подгоните при желании */
                  width: auto;
                  object-fit: contain;
                  display: block;    /* чтобы в флексе не прыгал */
              }
                .table-ua { width:100%; border-collapse:collapse; }
                .table-ua th, .table-ua td { padding:8px; border-bottom:1px solid #eee; vertical-align:top; }
                .table-ua th { text-align:left; font-weight:600; color:#2c3e50; }
                .table-ua td.num { text-align:right; white-space:nowrap; }
                .table-ua td.ua { word-break:break-word; }
                .badge { display:inline-block; padding:2px 8px; border-radius:999px; background:#f0f3f7; font-size:.85em; color:#455a64; }

              .chart-half {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 1px 6px rgba(0,0,0,0.06);
                padding: 14px;
                height: 360px;
              }
              @media (max-width: 900px) {
                .charts-row { grid-template-columns: 1fr; }
                .chart-half { height: 320px; }
              }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                  <img
                    src="<?php echo esc_url( BASKERVILLE_PLUGIN_URL . 'assets/logo-baskerville.png?v=' . BASKERVILLE_VERSION ); ?>"
                    alt="Baskerville"
                    class="baskerville-logo"
                  />
                  Baskerville
                </h1>

                <div id="summary-stats" class="stats-grid">
                    <div class="loading">Loading statistics...</div>
                </div>

                <div class="controls">
                    <button class="control-button active" onclick="loadData(24)">24 Hours</button>
                    <button class="control-button" onclick="loadData(72)">3 Days</button>
                    <button class="control-button" onclick="loadData(168)">7 Days</button>
                    <button class="control-button" onclick="loadData(336)">14 Days</button>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="humAutoBar"></canvas>
                  </div>
                  <div class="chart-half">
                    <canvas id="humAutoPie"></canvas>
                  </div>
                </div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
                <div class="chart-container">
                  <canvas id="blocksChart"></canvas>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="blockReasonsPie"></canvas>
                  </div>
                  <div class="chart-half" id="blockReasonsTable" style="overflow:auto"></div>
                </div>
                <div class="chart-container" style="height:auto;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-weight:600;">AI bot User-Agents — unique IPs (last <span id="aiUAHours">24</span>h)</div>
                    <input id="aiUAFilter" type="search" placeholder="Filter UA…" style="padding:6px 10px;border:1px solid #ddd;border-radius:6px;min-width:220px;">
                  </div>
                  <div id="aiUAList" style="overflow:auto; max-height: 420px;"></div>
                </div>

                <div class="chart-container">
                  <canvas id="scoreHistChart"></canvas>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="topFactorBar"></canvas>
                  </div>
                  <div class="chart-half" id="topFactorTable" style="overflow:auto"></div>
                </div>



            </div>

            <script>
                let chart = null;
                let currentHours = 24;
                 let chartHumAuto = null;
                 let chartHumAutoPie = null;
                 let chartBlocks = null;
                 let chartScoreHist = null;

                const STATS_URL = '<?php echo esc_js($stats_url); ?>';

                function updateTopFactorHistogram(tf) {
                  const el = document.getElementById('topFactorBar');
                  const tbl = document.getElementById('topFactorTable');
                  if (!el || !tf) return;

                  const labels = (tf.items || []).map(i => i.factor);
                  const counts = (tf.items || []).map(i => i.count);
                  const avgs   = (tf.items || []).map(i => i.avg_score);
                  const share  = (tf.items || []).map(i => i.percent);

                  // Гистограмма по счётчикам (bar). В тултипе — доля и средний скор.
                  if (window.chartTopFactor) window.chartTopFactor.destroy();
                  window.chartTopFactor = new Chart(el.getContext('2d'), {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [{
                        label: 'Count (score > ' + (tf.min_score ?? 30) + ')',
                        data: counts,
                        backgroundColor: '#9C27B0', // фиолетовый, чтобы не путать с Humans/Automated
                        borderColor: '#9C27B0',
                        borderWidth: 1
                      }]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { title: { display: true, text: 'Top factor' } },
                        y: { beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Top factors — score > ' + (tf.min_score ?? 30) + ' (last ' + (tf.hours ?? '') + 'h)' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const i = items[0].dataIndex;
                              return [
                                'Share: ' + (share[i] || 0) + '%',
                                'Avg score: ' + (avgs[i] ?? '—')
                              ];
                            }
                          }
                        },
                        legend: { display: false }
                      }
                    }
                  });

                  // Мини-таблица (топ 20, если их много)
                  if (tbl) {
                    const rows = (tf.items || []).slice(0, 20).map(i =>
                      `<tr>
                         <td>${escHtml(i.factor)}</td>
                         <td style="text-align:right;">${i.count}</td>
                         <td style="text-align:right;">${i.percent}%</td>
                         <td style="text-align:right;">${i.avg_score}</td>
                       </tr>`
                    ).join('');
                    tbl.innerHTML = `
                      <div style="font-weight:600;margin-bottom:8px;">
                        Top factors (score > ${tf.min_score ?? 30}) — last ${tf.hours ?? ''}h
                        <span class="badge">Total: ${tf.total || 0}</span>
                      </div>
                      <table style="width:100%;border-collapse:collapse;">
                        <thead>
                          <tr>
                            <th style="text-align:left;border-bottom:1px solid #eee;padding:6px 0;">Factor</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Count</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Share</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Avg score</th>
                          </tr>
                        </thead>
                        <tbody>${rows || `<tr><td colspan="4" style="padding:10px;color:#777;">No data</td></tr>`}</tbody>
                      </table>
                    `;
                  }
                }

                function updateScoreHistogram(hist) {
                  const el = document.getElementById('scoreHistChart');
                  if (!el || !hist) return;
                  const ctx = el.getContext('2d');
                  if (chartScoreHist) chartScoreHist.destroy();

                  const labels = hist.labels || [];
                  const humans = hist.human_counts || hist.humanCounts || [];
                  const autos  = hist.automated_counts || hist.automatedCounts || [];
                  const bucketSize = Number(hist.bucket_size || 10);

                  const avgFromBuckets = (labels, counts) => {
                    let sum = 0, tot = 0;
                    labels.forEach((lab, i) => {
                      const m = String(lab).match(/(\d+)[–-](\d+)/);
                      if (!m) return;
                      const mid = (parseInt(m[1], 10) + parseInt(m[2], 10)) / 2;
                      const c = counts[i] || 0;
                      sum += mid * c; tot += c;
                    });
                    return tot ? (sum / tot) : null;
                  };

                  const avgH = avgFromBuckets(labels, humans);
                  const avgA = avgFromBuckets(labels, autos);

                  // helper: rounded rect
                  const roundRect = (ctx, x, y, w, h, r) => {
                    const rr = Math.min(r, w/2, h/2);
                    ctx.beginPath();
                    ctx.moveTo(x + rr, y);
                    ctx.arcTo(x + w, y, x + w, y + h, rr);
                    ctx.arcTo(x + w, y + h, x, y + h, rr);
                    ctx.arcTo(x, y + h, x, y, rr);
                    ctx.arcTo(x, y, x + w, y, rr);
                    ctx.closePath();
                  };

                  const avgLinesPlugin = {
                    id: 'avgLines',
                    afterDatasetsDraw(chart) {
                      const { ctx, chartArea, scales } = chart;
                      const x = scales.x;
                      const yTop = chartArea.top;
                      const yBottom = chartArea.bottom;

                      const drawAvg = (val, color, label, yOffset) => {
                        if (val == null || isNaN(val)) return;

                        let idx = Math.floor(val / bucketSize);
                        idx = Math.max(0, Math.min(labels.length - 1, idx));
                        const xPix = x.getPixelForValue(idx);

                        // линия
                        ctx.save();
                        ctx.setLineDash([6, 6]);
                        ctx.strokeStyle = color;
                        ctx.lineWidth = 2;
                        ctx.beginPath();
                        ctx.moveTo(xPix, yTop);
                        ctx.lineTo(xPix, yBottom);
                        ctx.stroke();
                        ctx.setLineDash([]);

                        // подпись с серой подложкой
                        ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
                        const pad = 6;
                        const text = label;
                        const metrics = ctx.measureText(text);
                        const textW = metrics.width;
                        const textH = 16; // примерно для 12px шрифта

                        // стараемся не выходить за край
                        const prefersLeft = (chartArea.right - xPix) < (textW + 12) && (xPix - chartArea.left) > (textW + 12);
                        let textX = prefersLeft ? (xPix - textW - pad) : (xPix + pad);
                        textX = Math.max(chartArea.left + 2, Math.min(textX, chartArea.right - textW - 2));
                        const textY = yTop + (yOffset || 4);

                        // тень/фон
                        ctx.fillStyle = 'rgba(0,0,0,0.15)';
                        roundRect(ctx, textX - 4, textY - 2, textW + 8, textH, 4);
                        ctx.fill();

                        // собственно текст
                        ctx.fillStyle = color;
                        ctx.textBaseline = 'top';
                        ctx.fillText(text, textX, textY);
                        ctx.restore();
                      };

                      // зелёная выше, оранжевая ниже
                      drawAvg(avgH, '#4CAF50', `avg human ${avgH?.toFixed(1)}`, 4);
                      drawAvg(avgA, '#FF9800', `avg automated ${avgA?.toFixed(1)}`, 24);
                    }
                  };

                  chartScoreHist = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        {
                          label: 'Humans',
                          data: humans,
                          backgroundColor: '#4CAF50',
                          borderColor: '#4CAF50',
                          borderWidth: 1
                        },
                        {
                          label: 'Automated',
                          data: autos,
                          backgroundColor: '#FF9800',
                          borderColor: '#FF9800',
                          borderWidth: 1
                        }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      layout: { padding: { top: 32 } }, // больше места под обе подписи
                      scales: {
                        x: { stacked: false, title: { display: true, text: 'Score buckets (width = ' + bucketSize + ')' } },
                        y: { beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Score Distribution — last ' + (hist.hours || '') + 'h' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const idx = items[0].dataIndex;
                              const h = humans[idx] || 0, a = autos[idx] || 0, t = h + a;
                              const hp = t ? Math.round((h * 100) / t) : 0;
                              const ap = t ? Math.round((a * 100) / t) : 0;
                              return [`Total: ${t}`, `Humans: ${h} (${hp}%)`, `Automated: ${a} (${ap}%)`];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    },
                    plugins: [avgLinesPlugin]
                  });
                }

                                                // безопасный вывод текста в HTML
                function escHtml(s){
                  return String(s || '')
                    .replaceAll('&','&amp;')
                    .replaceAll('<','&lt;')
                    .replaceAll('>','&gt;')
                    .replaceAll('"','&quot;')
                    .replaceAll("'",'&#39;');
                }

                let __aiUAData = null;

                function renderAIBotUAList(data, filterText='') {
                  const el = document.getElementById('aiUAList');
                  const hrs = document.getElementById('aiUAHours');
                  if (!el || !data) return;

                  if (hrs) hrs.textContent = String(data.hours || currentHours);

                  const items = (data.items || []);
                  const f = (filterText || '').trim().toLowerCase();
                  const filtered = f ? items.filter(it => (it.user_agent||'').toLowerCase().includes(f)) : items;

                  if (!filtered.length) {
                    el.innerHTML = `<div style="color:#777;padding:10px;">No AI-bot user agents${f ? ' for filter “'+escHtml(filterText)+'”' : ''}.</div>`;
                    return;
                  }

                  const rows = filtered.map(it => {
                    const ua = escHtml(it.user_agent || '');
                    return `<tr>
                      <td class="ua"><span title="${ua}">${ua}</span></td>
                      <td class="num">${it.unique_ips}</td>
                      <td class="num">${it.events}</td>
                    </tr>`;
                  }).join('');

                  el.innerHTML = `
                    <table class="table-ua">
                      <thead>
                        <tr>
                          <th>User-Agent</th>
                          <th style="width:140px;">Unique IPs</th>
                          <th style="width:120px;">Events</th>
                        </tr>
                      </thead>
                      <tbody>${rows}</tbody>
                      <tfoot>
                        <tr>
                          <td><span class="badge">Total unique IPs (all AI): ${data.total_unique_ips || 0}</span></td>
                          <td class="num" colspan="2"><span class="badge">${filtered.length} UA rows</span></td>
                        </tr>
                      </tfoot>
                    </table>
                  `;
                }

                function updateAIBotUAList(aiUA){
                  __aiUAData = aiUA || {items:[]};
                  renderAIBotUAList(__aiUAData, document.getElementById('aiUAFilter')?.value || '');
                }

                // live-фильтр
                document.addEventListener('input', (e)=>{
                  if (e.target && e.target.id === 'aiUAFilter') {
                    renderAIBotUAList(__aiUAData, e.target.value);
                  }
                });

                function updateBlocksChart(blocksSeries) {
                  const el = document.getElementById('blocksChart');
                  if (!el) return;
                  const ctx = el.getContext('2d');
                  if (window.chartBlocks) window.chartBlocks.destroy();

                  const labels  = blocksSeries.map(i => fmtHHMM(i.time));
                  const bad     = blocksSeries.map(i => i.bad_bot_blocks    || 0);
                  const ai      = blocksSeries.map(i => i.ai_bot_blocks     || 0);
                  const bot     = blocksSeries.map(i => i.bot_blocks        || 0);
                  const other   = blocksSeries.map(i => i.other_blocks      || 0);
                  const verified= blocksSeries.map(i => i.verified_bot_blocks || 0);
                  const totals  = blocksSeries.map(i => i.total_blocks      || 0);

                  window.chartBlocks = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: '403 Bad bots',           data: bad,      stack: 'blocks', backgroundColor: '#ff6b6b' },
                        { label: '403 AI bots',            data: ai,       stack: 'blocks', backgroundColor: '#ff9800' },
                        { label: '403 Bots',               data: bot,      stack: 'blocks', backgroundColor: '#673AB7' },
                        { label: '403 Other',              data: other,    stack: 'blocks', backgroundColor: '#90A4AE' },
                        { label: '403 Verified crawlers',  data: verified, stack: 'blocks', backgroundColor: '#03A9F4' }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { stacked: true, title: { display: true, text: 'Time, UTC' } },
                        y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Blocked decisions (403)' } }
                      },
                      plugins: {
                        title: { display: true, text: '403 Decisions by Bot Category — last ' + currentHours + 'h' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const idx = items[0].dataIndex;
                              return ['Total 403: ' + (totals[idx] || 0)];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    }
                  });
                }

                // Возвращает HH:MM из строки вида "YYYY-MM-DD HH:MM:SS" (или любой строки с временем)
                function fmtHHMM(ts) {
                  const m = String(ts || '').match(/\b(\d{2}):(\d{2})/);
                  return m ? m[1] + ':' + m[2] : String(ts || '');
                }

                async function loadData(hours = 24) {
                    try {
                        currentHours = hours;

                        const t = (typeof event !== 'undefined' && event && event.target) ? event.target : null;
                        document.querySelectorAll('.control-button').forEach(btn => btn.classList.remove('active'));
                        if (t) t.classList.add('active');

                        const response = await fetch(STATS_URL + '?hours=' + hours + '&_=' + Date.now(), { cache: 'no-store' });

                        const data = await response.json();
                        updateSummaryStats(data.summary_window || data.summary, data.blocks_summary, data.block_reasons);
                        updateHumAutoCharts(data.timeseries);
                        updateChart(data.timeseries);
                        updateBlockReasons(data.block_reasons || { total:0, items:[] });
                        updateBlocksChart(data.timeseries_blocks || []);
                        updateScoreHistogram(data.score_histogram);
                        updateAIBotUAList(data.ai_ua);
                        updateTopFactorHistogram(data.top_factor_histogram);

                    } catch (error) {
                        console.error('Error loading data:', error);
                    }
                }

                function updateBlockReasons(reasons) {
                  // Pie
                  const elPie = document.getElementById('blockReasonsPie');
                  if (elPie) {
                    const ctx = elPie.getContext('2d');
                    if (window.chartBlockReasonsPie) window.chartBlockReasonsPie.destroy();

                    const labels = (reasons.items || []).map(i => i.reason);
                    const data   = (reasons.items || []).map(i => i.count);

                    window.chartBlockReasonsPie = new Chart(ctx, {
                      type: 'pie',
                      data: { labels, datasets: [{ data }] },
                      options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                          title: { display: true, text: '403 by Reason — last ' + currentHours + 'h' },
                          tooltip: {
                            callbacks: {
                              label: (c) => ' ' + c.label + ': ' + c.parsed + ' (' + ((c.parsed/(reasons.total||1))*100).toFixed(1) + '%)'
                            }
                          },
                          legend: { position: 'bottom' }
                        }
                      }
                    });
                  }

                  // Table
                  const elTbl = document.getElementById('blockReasonsTable');
                  if (elTbl) {
                    const total = reasons.total || 0;
                    const rows = (reasons.items || []).map(i =>
                      '<tr><td>' + i.reason + '</td><td style="text-align:right;">' + i.count + '</td><td style="text-align:right;">' + i.percent + '%</td></tr>'
                    ).join('');
                    elTbl.innerHTML = `
                      <div style="font-weight:600;margin-bottom:8px;">403 Reasons — totals</div>
                      <table style="width:100%;border-collapse:collapse;">
                        <thead><tr>
                          <th style="text-align:left;border-bottom:1px solid #eee;padding:6px 0;">Reason</th>
                          <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Count</th>
                          <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Share</th>
                        </tr></thead>
                        <tbody>${rows || `<tr><td colspan="3" style="padding:10px;color:#777;">No data</td></tr>`}</tbody>
                        <tfoot>
                          <tr><td style="border-top:1px solid #eee;padding:6px 0;">Total</td>
                              <td style="text-align:right;border-top:1px solid #eee;padding:6px 0;">${total}</td>
                              <td style="text-align:right;border-top:1px solid #eee;padding:6px 0;">100%</td></tr>
                        </tfoot>
                      </table>
                    `;
                  }
                }


                function updateSummaryStats(summaryLike, blocksSummary, reasons) {
                  const blocked = (blocksSummary && blocksSummary.total_blocks) ? blocksSummary.total_blocks : 0;
                  const humanPct = summaryLike?.human_percentage || 0;
                  const botPct   = summaryLike?.bot_percentage || 0;

                  const top3 = (reasons && reasons.items ? reasons.items.slice(0,3) : []);
                  const mini = top3.length
                    ? `<div style="font-size:.85em;margin-top:8px;text-align:left;">
                         <div style="opacity:.9;margin-bottom:4px;">Top reasons:</div>
                         ${top3.map(i => `<div>• ${i.reason}: ${i.count} (${i.percent}%)</div>`).join('')}
                       </div>`
                    : '';

                  const statsHtml = `
                    <div class="stat-card">
                      <div class="stat-number">${summaryLike.total_visits || 0}</div>
                      <div class="stat-label">Total Visits — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card human">
                      <div class="stat-number">${humanPct}%</div>
                      <div class="stat-label">Human Traffic — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card bot">
                      <div class="stat-number">${botPct}%</div>
                      <div class="stat-label">Automated Traffic — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card block">
                      <div class="stat-number">${blocked}</div>
                      <div class="stat-label">Blocked (403) — last ${currentHours}h</div>
                      ${mini}
                    </div>
                  `;
                  document.getElementById('summary-stats').innerHTML = statsHtml;
                }

                function updateHumAutoCharts(timeseries) {
                  const barCtx = document.getElementById('humAutoBar')?.getContext('2d');
                  const pieCtx = document.getElementById('humAutoPie')?.getContext('2d');
                  if (!barCtx || !pieCtx) return;

                  // Сбор данных
                  const labels = timeseries.map(i => fmtHHMM(i.time));
                  const humans = timeseries.map(i => i.human_count || 0);
                  const automated = timeseries.map(i =>
                      (i.bad_bot_count||0) + (i.ai_bot_count||0) + (i.bot_count||0) + (i.verified_bot_count||0)
                    );


                  // Totals для круговой диаграммы — за выбранный период (а не retention_days)
                  const totalHumans = humans.reduce((a,b) => a+b, 0);
                  const totalAutomated = automated.reduce((a,b) => a+b, 0);

                  // Пересоздаём графики, если уже были
                  if (chartHumAuto) chartHumAuto.destroy();
                  if (chartHumAutoPie) chartHumAutoPie.destroy();

                  // 1) Stacked Bar: Humans vs Automated
                  chartHumAuto = new Chart(barCtx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: 'Humans',    data: humans,    stack: 'visits2', backgroundColor: '#4CAF50' },
                        { label: 'Automated', data: automated, stack: 'visits2', backgroundColor: '#FF9800' }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { stacked: true, title: { display: true, text: 'Time, UTC' } },
                        y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Humans vs Automated — last ' + currentHours + 'h' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const idx = items[0].dataIndex;
                              const total = (humans[idx]||0) + (automated[idx]||0);
                              const hp = total ? Math.round((humans[idx]*100)/total) : 0;
                              const ap = total ? Math.round((automated[idx]*100)/total) : 0;
                              return [`Total: ${total}`, `Humans: ${humans[idx]} (${hp}%)`, `Automated: ${automated[idx]} (${ap}%)`];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    }
                  });

                  // 2) Pie: Totals Humans vs Automated
                  chartHumAutoPie = new Chart(pieCtx, {
                    type: 'pie',
                    data: {
                      labels: ['Humans', 'Automated'],
                      datasets: [{
                        data: [totalHumans, totalAutomated],
                        backgroundColor: ['#4CAF50', '#FF9800']
                      }]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: {
                        title: { display: true, text: 'Totals — last ' + currentHours + 'h' },
                        tooltip: {
                          callbacks: {
                            label(ctx) {
                              const v = ctx.parsed || 0;
                              const sum = totalHumans + totalAutomated || 1;
                              const pct = Math.round((v*100)/sum);
                              return ` ${ctx.label}: ${v} (${pct}%)`;
                            }
                          }
                        },
                        legend: { position: 'bottom' }
                      }
                    }
                  });
                }

                function updateChart(timeseries) {
                  const ctx = document.getElementById('trafficChart').getContext('2d');
                  if (chart) chart.destroy();

                  const labels = timeseries.map(i => fmtHHMM(i.time));
                  const humans   = timeseries.map(i => i.human_count || 0);
                  const badBots  = timeseries.map(i => i.bad_bot_count || 0);
                  const aiBots   = timeseries.map(i => i.ai_bot_count || 0);
                  const bots     = timeseries.map(i => i.bot_count || 0);
                  const verified = timeseries.map(i => i.verified_bot_count || 0);

                  chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: 'Humans',   data: humans,  stack: 'visits', backgroundColor: '#4CAF50' },
                        { label: 'Bad bots', data: badBots, stack: 'visits', backgroundColor: '#ff6b6b' },
                        { label: 'AI bots',  data: aiBots,  stack: 'visits', backgroundColor: '#ff9800' }, // оранжевый
                        { label: 'Bots',     data: bots,    stack: 'visits', backgroundColor: '#673AB7' }, // фиолетовый, явно отличается
                        { label: 'Verified crawlers', data: verified, stack: 'visits', backgroundColor: '#03A9F4' }
                      ]

                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: {
                          stacked: true,
                          title: { display: true, text: 'Time, UTC' }
                        },
                        y: {
                          stacked: true,
                          beginAtZero: true,
                          title: { display: true, text: 'Visits' }
                        }
                      },
                      plugins: {
                        title: { display: true, text: 'Traffic Analysis - Last ' + currentHours + ' Hours' },
                        tooltip: {
                          callbacks: {
                            // показываем сводку по слотам без процентов
                            afterBody: function(items) {
                              const idx = items[0].dataIndex;
                              const it  = timeseries[idx];
                              return [
                                `Total: ${it.total_visits}`,
                                `Humans: ${it.human_count} | Bad: ${it.bad_bot_count} | AI: ${it.ai_bot_count} | Bots: ${it.bot_count}`,
                                `Avg score: ${it.avg_score}`
                              ];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    }
                  });
                }

                // Load initial data
                loadData(24);

                // Auto-refresh every 5 minutes
                setInterval(() => loadData(currentHours), 5 * 60 * 1000);
            </script>

        </body>
        </html>
        <?php

        $html = ob_get_clean();

        // Output HTML directly to avoid WP REST API escaping
        wp_die($html, 'Baskerville Statistics', ['response' => 200]);
    }

    public function get_ai_bot_user_agents($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        // гарантируем UTC
        $wpdb->query("SET time_zone = '+00:00'");

        // Считаем уникальные IP на каждый UA + общее число событий
        $sql = "
          SELECT
            user_agent,
            COUNT(DISTINCT ip) AS unique_ips,
            COUNT(*) AS events
          FROM $table
          WHERE classification='ai_bot' AND timestamp_utc >= %s
          GROUP BY user_agent
          ORDER BY unique_ips DESC, events DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        // Общий охват по уникальным IP (не равен сумме по строкам — IP может встречаться у разных UA)
        $total_unique_ips = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip) FROM $table WHERE classification='ai_bot' AND timestamp_utc >= %s",
            $cutoff
        ));

        // Небольшая нормализация длины UA для ответа
        $items = array_map(function($r){
            return [
                'user_agent' => mb_substr((string)$r['user_agent'], 0, 500),
                'unique_ips' => (int)$r['unique_ips'],
                'events'     => (int)$r['events'],
            ];
        }, $rows);

        return [
            'hours'            => $hours,
            'total_unique_ips' => $total_unique_ips,
            'items'            => $items,
        ];
    }

    public function get_score_histogram($hours = 24, $bucket_size = 10) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours = max(1, min(720, (int)$hours));
        $bucket_size = max(1, min(50, (int)$bucket_size)); // 1..50
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $num_buckets = (int)ceil(100 / $bucket_size);
        $last_idx = $num_buckets - 1;

        $labels = [];
        $human = array_fill(0, $num_buckets, 0);
        $auto  = array_fill(0, $num_buckets, 0);
        $total = array_fill(0, $num_buckets, 0);
        for ($i = 0; $i < $num_buckets; $i++) {
            $start = $i * $bucket_size;
            $end   = ($i === $last_idx) ? 100 : ($i + 1) * $bucket_size - 1;
            $labels[$i] = sprintf('%d–%d', $start, $end);
        }

        $wpdb->query("SET time_zone = '+00:00'");

        // Гистограмма ТОЛЬКО по had_fp=1
        $sql = "
          SELECT
            LEAST(FLOOR(score / %d), %d) AS b,
            SUM(CASE WHEN classification='human' THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN 1 ELSE 0 END) AS automated_count,
            COUNT(*) AS total_count
          FROM $table
          WHERE event_type IN ('page','fp')
            AND timestamp_utc >= %s
            AND score IS NOT NULL
            AND had_fp = 1
          GROUP BY b
          ORDER BY b
        ";

        $rows = $wpdb->get_results($wpdb->prepare($sql, $bucket_size, $last_idx, $cutoff), ARRAY_A) ?: [];
        foreach ($rows as $r) {
            $idx = (int)$r['b'];
            if ($idx < 0 || $idx > $last_idx) continue;
            $human[$idx] = (int)$r['human_count'];
            $auto[$idx]  = (int)$r['automated_count'];
            $total[$idx] = (int)$r['total_count'];
        }

        // Средние скоры (также только по had_fp=1)
        $row = $wpdb->get_row($wpdb->prepare("
          SELECT
            SUM(CASE WHEN classification='human' THEN score ELSE 0 END)        AS human_sum,
            SUM(CASE WHEN classification='human' THEN 1 ELSE 0 END)            AS human_n,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN score ELSE 0 END) AS auto_sum,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN 1 ELSE 0 END)     AS auto_n
          FROM $table
          WHERE event_type IN ('page','fp') AND had_fp=1 AND timestamp_utc >= %s
        ", $cutoff), ARRAY_A) ?: ['human_sum'=>0,'human_n'=>0,'auto_sum'=>0,'auto_n'=>0];

        $avg_human = ((int)$row['human_n'] > 0) ? round(((float)$row['human_sum']) / (int)$row['human_n'], 1) : null;
        $avg_auto  = ((int)$row['auto_n']  > 0) ? round(((float)$row['auto_sum'])  / (int)$row['auto_n'],  1) : null;

        return [
            'bucket_size'       => $bucket_size,
            'labels'            => $labels,
            'human_counts'      => $human,
            'automated_counts'  => $auto,
            'total_counts'      => $total,
            'hours'             => $hours,
            'avg_human_score'   => $avg_human,   // ← НОВОЕ
            'avg_auto_score'    => $avg_auto,    // ← НОВОЕ
        ];
    }


    public function get_block_summary($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) AS total_blocks,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_blocks,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_blocks,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_blocks,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_blocks,
            SUM(CASE WHEN classification NOT IN ('bad_bot','ai_bot','bot') THEN 1 ELSE 0 END) AS other_blocks
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        return [
            'total_blocks'   => (int)($row['total_blocks']      ?? 0),
            'bad_bot_blocks' => (int)($row['bad_bot_blocks']    ?? 0),
            'ai_bot_blocks'  => (int)($row['ai_bot_blocks']     ?? 0),
            'verified_bot_blocks' => (int)($row['verified_bot_blocks'] ?? 0),
            'bot_blocks'     => (int)($row['bot_blocks']        ?? 0),
            'other_blocks'   => (int)($row['other_blocks']      ?? 0),
            'hours'          => $hours,
        ];
    }

    public function handle_stats_data(WP_REST_Request $request) {
        if (!headers_sent()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
        }

        $hours = max(1, min(720, (int)($request->get_param('hours') ?: 24)));

        $timeseries        = $this->get_timeseries_data($hours);
        $summary           = $this->get_summary_stats();              // по retention
        $summary_window    = $this->get_summary_stats_window($hours);
        $timeseries_blocks = $this->get_block_timeseries_data($hours); // по окну hours
        $blocks_summary    = $this->get_block_summary($hours);         // по окну hours
        $block_reasons     = $this->get_block_reasons_breakdown($hours, 8);

        $score_histogram   = $this->get_score_histogram($hours, 10);
        $ai_ua_list = $this->get_ai_bot_user_agents($hours);
        $top_factor_hist = $this->get_top_factor_histogram($hours, 30);


        return new WP_REST_Response([
            'ok'          => true,
            'timeseries'  => $timeseries,
            'summary'     => $summary,
            'summary_window'    => $summary_window,
            'blocks_summary' => $blocks_summary,
            'timeseries_blocks' => $timeseries_blocks,
            'score_histogram'    => $score_histogram,
            'block_reasons'     => $block_reasons,
            'ai_ua'              => $ai_ua_list,
            'hours'       => $hours,
            'generated_at'=> gmdate('c'),
            'top_factor_histogram' => $top_factor_hist,
        ], 200);
    }


    public function activate() {
        $this->create_stats_table();
        $this->maybe_upgrade_schema();
        if (!get_option('baskerville_retention_days')) {
            add_option('baskerville_retention_days', BASKERVILLE_DEFAULT_RETENTION_DAYS);
        }
        if (!get_option('baskerville_cookie_secret')) {
            add_option('baskerville_cookie_secret', bin2hex(random_bytes(32)));
        }
        if (!wp_next_scheduled('baskerville_cleanup_stats')) {
            wp_schedule_event(time(), 'daily', 'baskerville_cleanup_stats');
        }

        if (!get_option('baskerville_nocookie_window_sec'))   add_option('baskerville_nocookie_window_sec', 60);
        if (!get_option('baskerville_nocookie_threshold'))    add_option('baskerville_nocookie_threshold', 10);
        if (!get_option('baskerville_nocookie_ban_minutes'))  add_option('baskerville_nocookie_ban_minutes', 10);

        if (!get_option('baskerville_nojs_window_sec'))  add_option('baskerville_nojs_window_sec', 60);
        if (!get_option('baskerville_nojs_threshold'))   add_option('baskerville_nojs_threshold', 20);
        if (!get_option('baskerville_fp_seen_ttl_sec'))  add_option('baskerville_fp_seen_ttl_sec', 180);
        if (!get_option('baskerville_ban_ttl_sec')) add_option('baskerville_ban_ttl_sec', 600);
        if (!get_option('baskerville_fp_attach_window_sec')) add_option('baskerville_fp_attach_window_sec', 180);
        if (!get_option('baskerville_ip_whitelist')) add_option('baskerville_ip_whitelist', '');


        flush_rewrite_rules();
    }

    public function deactivate() {
        // Clean up scheduled event
        wp_clear_scheduled_hook('baskerville_cleanup_stats');
        flush_rewrite_rules();
    }
}

new Baskerville();
