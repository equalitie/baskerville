<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Core {

    /** Было ли у клиента валидное baskerville_id при приходе */
    private bool $had_cookie_on_arrival = false;

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

    /** Секрет для подписи кук (используется и REST-эндпоинтом) */
    public function cookie_secret(): string {
        $secret = (string) get_option('baskerville_cookie_secret', '');
        if (!$secret) {
            $secret = bin2hex(random_bytes(32));
            update_option('baskerville_cookie_secret', $secret, true);
        }
        return $secret;
    }

    /** Подпись основной куки: включаем ip_key в HMAC */
    private function sign_cookie(string $token, int $ts, string $ipk): string {
        return hash_hmac('sha256', $token . '.' . $ts . '.' . $ipk, $this->cookie_secret());
    }

    /** IPv4 -> первые 3 октета; IPv6 -> первые 4 хекстета */
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
            // подпись от ТЕКУЩЕГО ip_key
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

    // ---- ARRIVAL COOKIE CHECK (по «сырому» заголовку) ----
    public function arrival_has_valid_cookie(): bool {
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

        // Привязка к ip_key и UA-hash
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

    // ---- Признак «это публичная HTML-страница» (как в log_page_visit) ----
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
        $raw = (string) get_option('baskerville_ip_whitelist', '');
        if ($raw === '') return false;
        foreach (preg_split('~[\	s,]+~', $raw) as $w) {
            if ($w !== '' && $w === $ip) return true;
        }
        return false;
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
