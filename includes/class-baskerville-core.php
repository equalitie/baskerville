<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Core {

    /** Whether the client had a valid baskerville_id on arrival */
    private bool $had_cookie_on_arrival = false;

    /** Cache for whitelisted IPs to avoid repeated get_option() calls */
    private ?array $whitelist_cache = null;

    public function __construct() {
        $this->init_hooks();
    }

    private function init_hooks() {
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }

    public function enqueue_scripts() {
        wp_enqueue_style(
            'baskerville-style',
            BASKERVILLE_PLUGIN_URL . 'assets/css/baskerville.css',
            array(),
            BASKERVILLE_VERSION
        );

        wp_enqueue_script(
            'baskerville-script',
            BASKERVILLE_PLUGIN_URL . 'assets/js/baskerville.js',
            array('jquery'),
            BASKERVILLE_VERSION,
            true
        );
    }

    public function enqueue_admin_scripts() {
        wp_enqueue_style(
            'baskerville-admin-style',
            BASKERVILLE_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            BASKERVILLE_VERSION
        );

        wp_enqueue_script(
            'baskerville-admin-script',
            BASKERVILLE_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            BASKERVILLE_VERSION,
            true
        );
    }

    public function init() {
        load_plugin_textdomain('baskerville', false, dirname(plugin_basename(BASKERVILLE_PLUGIN_FILE)).'/languages');
        add_action('wp_footer', [$this, 'add_fingerprinting_script']);
    }

    /* ==== helpers: base64url & ip-key ==== */
    public function b64u_enc(string $s): string {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    public function b64u_dec(string $s): string {
        $s = strtr($s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) $s .= str_repeat('=', 4 - $pad);
        return base64_decode($s);
    }

    /** Secret for signing cookies (also used by REST endpoint) */
    public function cookie_secret(): string {
        $secret = (string) get_option('baskerville_cookie_secret', '');
        if (!$secret) {
            $secret = bin2hex(random_bytes(32));
            update_option('baskerville_cookie_secret', $secret, true);
        }
        return $secret;
    }

    /** Sign the main cookie: include ip_key in HMAC */
    private function sign_cookie(string $token, int $ts, string $ipk): string {
        return hash_hmac('sha256', $token . '.' . $ts . '.' . $ipk, $this->cookie_secret());
    }

    /** IPv4 -> first 3 octets; IPv6 -> first 4 hextets */
    public function ip_key(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $p = explode('.', $ip);
            return implode('.', array_slice($p, 0, 3)); // /24
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip = strtolower($ip);
            $h = explode(':', $ip);
            return implode(':', array_slice($h, 0, 4)); // /64
        }
        return 'unknown';
    }

    public function make_cookie_value(): string {
        $token = bin2hex(random_bytes(16));
        $ts    = time();
        $ipk   = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
        $sig   = $this->sign_cookie($token, $ts, $ipk);
        // new format: token.ts.ipk.sig
        return $token . '.' . $ts . '.' . $ipk . '.' . $sig;
    }

    /** Returns token if signature is valid and not expired. Supports legacy format (3 parts). */
    public function get_cookie_id(): ?string {
        $raw = $_COOKIE['baskerville_id'] ?? '';
        if (!$raw) return null;
        $parts = explode('.', $raw);

        if (count($parts) === 4) {
            [$token, $ts, $ipk, $sig] = $parts;
            if (!ctype_xdigit($token) || !ctype_digit($ts)) return null;
            $cur_ipk = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
            // signature from CURRENT ip_key
            if (!hash_equals($this->sign_cookie($token, (int)$ts, $cur_ipk), $sig)) return null;
            if ((int)$ts < time() - 60*60*24*90) return null;
            return $token;
        }

        // legacy 3-part: token.ts.sig — accept, but will reissue at first opportunity
        if (count($parts) === 3) {
            [$token, $ts, $sig] = $parts;
            if (!ctype_xdigit($token) || !ctype_digit($ts)) return null;
            $legacy_ok = hash_equals(hash_hmac('sha256', $token . '.' . (int)$ts, $this->cookie_secret()), $sig);
            if (!$legacy_ok) return null;
            if ((int)$ts < time() - 60*60*24*90) return null;
            return $token;
        }

        return null;
    }

    /** Set HttpOnly/Secure cookie if it doesn't exist or is invalid */
    public function ensure_baskerville_cookie(): void {
        if (headers_sent()) return;

        $this->had_cookie_on_arrival = ($this->get_cookie_id() !== null);

        if (!$this->had_cookie_on_arrival) {
            $value = $this->make_cookie_value();
            // so the current request can use the id — inject into $_COOKIE
            $_COOKIE['baskerville_id'] = $value;

            setcookie('baskerville_id', $value, [
                'expires'  => time() + 60*60*24*365, // one year retention
                'path'     => '/',
                'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }
    }

    // ---- ARRIVAL COOKIE CHECK (by raw header) ----
    public function arrival_has_valid_cookie(): bool {
        $hdr = $_SERVER['HTTP_COOKIE'] ?? '';
        if ($hdr === '' || strpos($hdr, 'baskerville_id=') === false) return false;
        if (!preg_match('~(?:^|;\s*)baskerville_id=([^;]+)~i', $hdr, $m)) return false;
        $raw = urldecode($m[1]);
        $parts = explode('.', $raw);

        // new format: token.ts.ipk.sig
        if (count($parts) === 4) {
            [$token, $ts, $ipk, $sig] = $parts;
            if (!ctype_xdigit($token) || !ctype_digit($ts)) return false;
            $cur_ipk = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
            $calc = $this->sign_cookie($token, (int)$ts, $cur_ipk);
            if (!hash_equals($calc, $sig)) return false;
            if ((int)$ts < time() - 60*60*24*90) return false;
            return true;
        }

        // legacy 3-part: token.ts.sig (keep for backward compatibility)
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

    public function read_fp_cookie(): ?array {
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

        // Binding to ip_key and UA-hash
        $ipk_now = $this->ip_key($_SERVER['REMOTE_ADDR'] ?? '');
        $ua_hash = sha1((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        if (($data['ipk'] ?? '') !== $ipk_now) return null;
        if (($data['ua']  ?? '') !== substr($ua_hash, 0, 16)) return null;

        return $data;
    }

    /* ===== Fast cache: APCu + file fallback ===== */

    /** set arbitrary value with TTL */
    public function fc_set(string $key, $value, int $ttl): bool {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) {
            return apcu_store($k, $value, $ttl);
        }
        $data = ['v'=>$value,'e'=>time()+$ttl];
        return (bool) @file_put_contents($this->fc_path($k), serialize($data), LOCK_EX);
    }

    /** get arbitrary value or null */
    public function fc_get(string $key) {
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
    public function fc_inc_in_window(string $key, int $window_sec): int {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) {
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

    public function fc_delete(string $key): void {
        $k = $this->fc_key($key);
        if ($this->fc_has_apcu()) { apcu_delete($k); return; }
        @unlink($this->fc_path($k));
    }

    /**
     * Cleanup expired cache files (zombie files that were never read again)
     * @param int $max_age_sec Maximum age for files (default 86400 = 24 hours)
     * @return int Number of files deleted
     */
    public function fc_cleanup_old_files($max_age_sec = 86400) {
        // APCu cleans itself automatically
        if ($this->fc_has_apcu()) return 0;

        $dir = $this->fc_dir();
        if (!is_dir($dir)) return 0;

        $deleted = 0;
        $now = time();
        $files = @glob($dir . '/*.cache');
        if (!$files) return 0;

        foreach ($files as $file) {
            // Skip if file was modified recently (within max_age)
            $mtime = @filemtime($file);
            if ($mtime === false || $mtime > ($now - $max_age_sec)) {
                continue;
            }

            // Read and check TTL
            $raw = @file_get_contents($file);
            if ($raw === false) {
                @unlink($file);
                $deleted++;
                continue;
            }

            $data = @unserialize($raw);
            if (!is_array($data)) {
                // Corrupted file - delete it
                @unlink($file);
                $deleted++;
                continue;
            }

            // Delete expired files
            if (($data['e'] ?? 0) < $now) {
                @unlink($file);
                $deleted++;
            }
        }

        return $deleted;
    }

    /**
     * Clear all GeoIP country cache entries
     * @return int Number of entries cleared
     */
    public function fc_clear_geoip_cache() {
        $cleared = 0;

        if ($this->fc_has_apcu()) {
            // APCu: iterate and delete country:* keys
            $iterator = new \APCUIterator('/^baskerville:country:/');
            foreach ($iterator as $entry) {
                if (apcu_delete($entry['key'])) {
                    $cleared++;
                }
            }
        } else {
            // File cache: find and delete country:* cache files
            $dir = $this->fc_dir();
            if (!is_dir($dir)) return 0;

            $files = @glob($dir . '/*.cache');
            if (!$files) return 0;

            foreach ($files as $file) {
                $raw = @file_get_contents($file);
                if ($raw === false) continue;

                // Check if this is a country cache file by checking the key hash
                // We need to check all country:* patterns
                $basename = basename($file, '.cache');

                // Generate sample hashes to identify country cache files
                // This is not perfect but will work for most cases
                // Better approach: store metadata in cache files

                // For now, just delete files that look like country cache
                // by checking if they're relatively fresh (< 7 days) and small
                $mtime = @filemtime($file);
                if ($mtime && (time() - $mtime) < (7 * 86400)) {
                    $size = filesize($file);
                    // Country codes are small (2-3 bytes), serialized ~50-100 bytes
                    if ($size < 200) {
                        if (@unlink($file)) {
                            $cleared++;
                        }
                    }
                }
            }
        }

        return $cleared;
    }

    public function fc_has_apcu(): bool {
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

    // ---- Check "is this a public HTML page" (as in log_page_visit) ----
    public function is_public_html_request(): bool {
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

    public function is_whitelisted_ip(string $ip): bool {
        // Load whitelist once per request and cache in memory
        if ($this->whitelist_cache === null) {
            $raw = (string) get_option('baskerville_ip_whitelist', '');
            if ($raw === '') {
                $this->whitelist_cache = [];
            } else {
                $this->whitelist_cache = array_filter(
                    preg_split('~[\s,]+~', $raw),
                    function($w) { return $w !== ''; }
                );
            }
        }
        return in_array($ip, $this->whitelist_cache, true);
    }

    /**
     * Get country code for IP address
     * Priority: 1) NGINX GeoIP, 2) Cloudflare, 3) MaxMind local DB
     * @param string $ip
     * @return string|null Two-letter country code (e.g., 'US', 'RU') or null if unknown
     */
    public function get_country_by_ip($ip) {
        if (empty($ip)) return null;

        // Check cache first (7 days TTL)
        $cache_key = "country:{$ip}";
        $cached = $this->fc_get($cache_key);
        if ($cached !== null) {
            return $cached === 'XX' ? null : $cached;
        }

        $country = null;

        // 1. Check NGINX GeoIP variables (fastest)
        if (!empty($_SERVER['GEOIP2_COUNTRY_CODE'])) {
            $country = strtoupper($_SERVER['GEOIP2_COUNTRY_CODE']);
        }
        elseif (!empty($_SERVER['GEOIP_COUNTRY_CODE'])) {
            $country = strtoupper($_SERVER['GEOIP_COUNTRY_CODE']);
        }
        elseif (!empty($_SERVER['HTTP_X_COUNTRY_CODE'])) {
            $country = strtoupper($_SERVER['HTTP_X_COUNTRY_CODE']);
        }
        // 2. Check Cloudflare header
        elseif (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $country = strtoupper($_SERVER['HTTP_CF_IPCOUNTRY']);
        }
        // 3. Fallback to MaxMind local database
        else {
            $country = $this->lookup_country_maxmind($ip);
        }

        // Normalize and validate
        if ($country && strlen($country) === 2 && ctype_alpha($country)) {
            $country = strtoupper($country);
        } else {
            $country = null;
        }

        // Cache result (use 'XX' for null to distinguish from cache miss)
        $this->fc_set($cache_key, $country ?: 'XX', 7 * 86400);

        return $country;
    }

    /**
     * Lookup country code using MaxMind GeoLite2 database
     * @param string $ip
     * @return string|null
     */
    private function lookup_country_maxmind($ip) {
        $db_path = WP_CONTENT_DIR . '/uploads/geoip/GeoLite2-Country.mmdb';
        if (!file_exists($db_path)) return null;

        if (!class_exists('GeoIp2\Database\Reader')) {
            $autoload = BASKERVILLE_PLUGIN_PATH . 'vendor/autoload.php';
            if (file_exists($autoload)) {
                require_once $autoload;
            } else {
                return null;
            }
        }

        try {
            $reader = new \GeoIp2\Database\Reader($db_path);
            $record = $reader->country($ip);
            return $record->country->isoCode;
        } catch (\Exception $e) {
            error_log('Baskerville GeoIP lookup failed: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Test all GeoIP sources for a given IP (for admin diagnostics)
     * @param string $ip
     * @return array
     */
    public function test_geoip_sources($ip) {
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $is_current_ip = ($ip === $current_ip);

        $results = array(
            'nginx_geoip2' => null,
            'nginx_geoip_legacy' => null,
            'nginx_custom_header' => null,
            'cloudflare' => null,
            'maxmind' => null,
            'maxmind_debug' => array(),
            'is_current_ip' => $is_current_ip,
            'current_ip' => $current_ip,
        );

        // NGINX and Cloudflare only work for current request IP
        if ($is_current_ip) {
            // Check NGINX variables (these are set per-request, so we check current $_SERVER)
            if (!empty($_SERVER['GEOIP2_COUNTRY_CODE'])) {
                $results['nginx_geoip2'] = strtoupper($_SERVER['GEOIP2_COUNTRY_CODE']);
            }
            if (!empty($_SERVER['GEOIP_COUNTRY_CODE'])) {
                $results['nginx_geoip_legacy'] = strtoupper($_SERVER['GEOIP_COUNTRY_CODE']);
            }
            if (!empty($_SERVER['HTTP_X_COUNTRY_CODE'])) {
                $results['nginx_custom_header'] = strtoupper($_SERVER['HTTP_X_COUNTRY_CODE']);
            }

            // Check Cloudflare header
            if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
                $results['cloudflare'] = strtoupper($_SERVER['HTTP_CF_IPCOUNTRY']);
            }
        } else {
            // For non-current IPs, note that server-side sources only work for current IP
            $results['nginx_geoip2'] = 'N/A (only for current IP)';
            $results['nginx_geoip_legacy'] = 'N/A (only for current IP)';
            $results['nginx_custom_header'] = 'N/A (only for current IP)';
            $results['cloudflare'] = 'N/A (only for current IP)';
        }

        // Test MaxMind directly with detailed diagnostics
        $db_path = WP_CONTENT_DIR . '/uploads/geoip/GeoLite2-Country.mmdb';
        $results['maxmind_debug']['expected_path'] = $db_path;
        $results['maxmind_debug']['file_exists'] = file_exists($db_path);
        $results['maxmind_debug']['is_readable'] = is_readable($db_path);
        $results['maxmind_debug']['file_size'] = file_exists($db_path) ? filesize($db_path) : 0;
        $results['maxmind_debug']['wp_content_dir'] = WP_CONTENT_DIR;

        // Check if vendor autoload exists
        $autoload_path = BASKERVILLE_PLUGIN_PATH . 'vendor/autoload.php';
        $results['maxmind_debug']['autoload_exists'] = file_exists($autoload_path);
        $results['maxmind_debug']['autoload_path'] = $autoload_path;

        // Load autoload if exists
        if ($results['maxmind_debug']['autoload_exists'] && !class_exists('GeoIp2\Database\Reader')) {
            require_once $autoload_path;
        }

        // Check if GeoIp2 class is available (after loading autoload)
        $results['maxmind_debug']['class_exists'] = class_exists('GeoIp2\Database\Reader');

        try {
            $results['maxmind'] = $this->lookup_country_maxmind($ip);
            if ($results['maxmind']) {
                $results['maxmind_debug']['lookup_success'] = true;
            } else {
                $results['maxmind_debug']['lookup_success'] = false;
                $results['maxmind_debug']['lookup_result'] = 'Returned null';
            }
        } catch (\Exception $e) {
            $results['maxmind'] = 'Error: ' . $e->getMessage();
            $results['maxmind_debug']['lookup_success'] = false;
            $results['maxmind_debug']['error'] = $e->getMessage();
        }

        return $results;
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

        // Hint to cache not to cache this output
        if (!headers_sent()) {
            if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
            nocache_headers();
        }
    }

    public function add_fingerprinting_script() {
        $rest_url = esc_url_raw( rest_url('baskerville/v1/fp') );
        $wp_nonce = wp_create_nonce('wp_rest');
        ?>
        <script>
        (function () {
          const REST_URL = '<?php echo esc_js($rest_url); ?>';
          const WP_NONCE = '<?php echo esc_js($wp_nonce); ?>';
          const urlFlag = new URLSearchParams(location.search).get('baskerville_debug');
          const showFromUrl = ['1','on','true','yes'].includes((urlFlag||'').toLowerCase());
          const showFromCookie = document.cookie.split('; ').includes('baskerville_show_widgets=1');
          const SHOW_WIDGET = showFromUrl || showFromCookie;

          const FP_MARK_KEY = 'baskerville_fp_sent_at';
          const FP_TAB_KEY  = 'baskerville_fp_sent_tab';
          const FP_TTL_MS   = 6*60*60*1000;

          function fpWasSentThisTab(){ try{return sessionStorage.getItem(FP_TAB_KEY)==='1';}catch{return false;} }
          function fpWasSentRecently(){ try{const t=Number(localStorage.getItem(FP_MARK_KEY)||0);return t>0 && (Date.now()-t)<FP_TTL_MS;}catch{return false;} }
          function markFpSent(){ try{localStorage.setItem(FP_MARK_KEY,String(Date.now()));}catch{} try{sessionStorage.setItem(FP_TAB_KEY,'1');}catch{} }

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
              } else {
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
            }
          })();
        })();
        </script>
        <?php
    }
}
