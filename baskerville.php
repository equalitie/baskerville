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

    public function __construct() {
        add_action('init', array($this, 'init'));
        add_action('plugins_loaded', array($this, 'load_classes'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('baskerville_cleanup_stats', array($this, 'cleanup_old_stats'));
        add_action('send_headers', [$this, 'ensure_baskerville_cookie'], 0);
        add_action('template_redirect', [$this, 'log_page_visit'], 0);
        add_action('init', [$this, 'handle_widget_toggle'], 0);
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
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
        $classification = $this->classify_client(['fingerprint' => []], ['headers' => $headers]);

        // Детектор «бурстов» без JS: много HTML-хитов за короткое окно — mark as bad_bot
        $this->maybe_mark_ip_as_bad_bot_on_burst($ip, $classification);

        // Сохраняем как page-ивент
        $cookie_id = $this->get_cookie_id();
        $this->save_visit_stats($ip, $cookie_id ?? '', $evaluation, $classification, $ua, 'page');
    }

    private function looks_like_browser_ua(string $ua): bool {
        $ua = strtolower($ua);
        // любые из распространённых браузерных токенов
        return (bool) preg_match('~(mozilla/|chrome/|safari/|firefox/|edg/|opera|opr/)~i', $ua);
    }

    /** Если с IP слишком много page-хитов в узком окне — помечаем как bad_bot */
    private function maybe_mark_ip_as_bad_bot_on_burst(string $ip, array &$classification): void {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        // Порог/окно — можно вынести в options
        $window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
        $threshold  = (int) get_option('baskerville_nojs_threshold', 20);

        // Считаем только page-ивенты за окно
        $cnt = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table
             WHERE ip=%s AND event_type='page'
               AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)",
            $ip, $window_sec
        ));

        if ($cnt >= $threshold) {
            $classification = [
                'classification' => 'bad_bot',
                'reason' => sprintf('Excessive no-JS page hits: %d in %ds', $cnt, $window_sec),
                'risk_score' => max(50, (int)($classification['risk_score'] ?? 0)), // повышаем риск
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

          // ==== дальше — твой существующий код сбора fingerprint и отправки ====

          const hash = async (str) => {
            const encoder = new TextEncoder();
            const data = encoder.encode(str);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
          };

          const canvasFingerprint = () => {
            try {
              const canvas = document.createElement('canvas');
              const ctx = canvas.getContext('2d');
              ctx.textBaseline = 'top';
              ctx.font = '14px Arial';
              ctx.fillStyle = '#f60';
              ctx.fillRect(0, 0, 100, 100);
              ctx.fillStyle = '#069';
              ctx.fillText('Baskerville canvas test', 10, 50);
              return canvas.toDataURL();
            } catch { return 'unsupported'; }
          };

          const webglFingerprint = () => {
            try {
              const canvas = document.createElement('canvas');
              const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
              if (!gl) return 'no-webgl';
              const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
              const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
              const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';
              const exts = (gl.getSupportedExtensions && gl.getSupportedExtensions()) || [];
              return { vendor, renderer, extCount: exts.length };
            } catch { return 'unsupported'; }
          };

          const audioFingerprint = async () => {
            try {
              const ctx = window.OfflineAudioContext ? new OfflineAudioContext(1, 44100, 44100) : new (window.AudioContext || window.webkitAudioContext)();
              return { sampleRate: ctx.sampleRate };
            } catch { return 'unsupported'; }
          };

          const mathPrecisionQuirk = () => {
            try {
              return [
                Math.acos(0.123),
                Math.tan(0.5),
                Math.log(42),
                Math.sin(Math.PI / 3),
              ].map(x => x.toPrecision(15)).join(',');
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
                  try { permissions[n] = (await navigator.permissions.query({name:n})).state; } catch { permissions[n] = 'unknown'; }
                }
              }

              const fp = {
                userAgent: navigator.userAgent,
                screen: `${screen.width}x${screen.height}`,
                viewport: `${window.innerWidth}x${window.innerHeight}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                languages: navigator.languages,
                touchSupport: { touchEvent: 'ontouchstart' in window, maxTouchPoints: navigator.maxTouchPoints || 0 },
                device: { platform: navigator.platform, memory: navigator.deviceMemory || 'unknown', cores: navigator.hardwareConcurrency || 'unknown', webdriver: navigator.webdriver || false },
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
                const formatValue = (v) => v==null ? 'null' : (typeof v==='string' && v.length>50 ? v.slice(0,47)+'…' : (typeof v==='object' ? JSON.stringify(v) : String(v)));
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

              const payload = { fingerprint: fp, fingerprintHash, url: location.href, ts: Date.now() };

              const send = async () => {
                try {
                  const res = await fetch(REST_URL, { method:'POST', headers:{'Content-Type':'application/json','X-WP-Nonce':WP_NONCE}, body:JSON.stringify(payload), keepalive:true });
                  if (res.ok) {
                    const result = await res.json();
                    if (SHOW_WIDGET && result.ok) {
                      const scoreEl = document.getElementById('score-data');
                      if (scoreEl) {
                        const scoreColor = result.score >= 60 ? '#ff6b6b' : result.score >= 40 ? '#ffa726' : '#4CAF50';
                        const map = (c)=>({human:['#4CAF50','👤','HUMAN'],bad_bot:['#ff6b6b','🚫','BAD BOT'],ai_bot:['#ff9800','🤖','AI BOT'],bot:['#673AB7','🕷️','BOT']})[c]||['#757575','❓','UNKNOWN'];
                        const [color,icon,label] = map(result.classification?.classification);
                        scoreEl.innerHTML = `
                          <div style="margin-bottom:8px;"><span style="color:${scoreColor};font-size:24px;font-weight:bold;">${result.score}/100</span></div>
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
              ('requestIdleCallback' in window) ? requestIdleCallback(send, {timeout:2000}) : setTimeout(send, 1000);
            } catch (e) {
              const el = document.getElementById('fingerprint-data');
              if (el) el.innerHTML = `<div style="color:#ff6b6b;">Error: ${e.message}</div>`;
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
            'yandexbot',             // Russia's search/LLM training
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


    private function sign_cookie(string $token, int $ts): string {
        return hash_hmac('sha256', $token . '.' . $ts, $this->cookie_secret());
    }

    /**
     * Формат куки: <token>.<ts>.<sig>
     * token = 16 байт random hex, ts = unix time, sig = HMAC(token.ts)
     */
    private function make_cookie_value(): string {
        $token = bin2hex(random_bytes(16));
        $ts    = time();
        $sig   = $this->sign_cookie($token, $ts);
        return $token . '.' . $ts . '.' . $sig;
    }

    /** Возвращает токен (token) если кука валидна и не просрочена, иначе null */
    public function get_cookie_id(): ?string {
        $raw = $_COOKIE['baskerville_id'] ?? '';
        if (!$raw) return null;
        $parts = explode('.', $raw);
        if (count($parts) !== 3) return null;
        [$token, $ts, $sig] = $parts;
        if (!ctype_xdigit($token) || !ctype_digit($ts)) return null;
        if (!hash_equals($this->sign_cookie($token, (int)$ts), $sig)) return null;

        // TTL куки (например, 90 дней для статуса «валидна»)
        if ((int)$ts < time() - 60*60*24*90) return null;

        return $token;
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

        // Разрешённые «хорошие» краулеры (останутся просто bot)
        $good_crawlers = ['googlebot','bingbot','duckduckbot','applebot','yandexbot','baiduspider',
                          'facebookexternalhit','twitterbot','linkedinbot','slackbot','discordbot'];
        $is_good_crawler = false;
        foreach ($good_crawlers as $g) {
            if (strpos($ua_lower, $g) !== false) { $is_good_crawler = true; break; }
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
        if (!$had_cookie && ($is_nonbrowser_client || (!$looks_like_browser && !$is_good_crawler))) {
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
        if ($risk_score >= 50 && !$looks_like_browser && !$is_good_crawler) {
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
        if ($this->is_bot_user_agent($user_agent) || $risk_score >= 50) {
            return [
                'classification' => 'bot',
                'reason'         => $this->is_bot_user_agent($user_agent)
                                        ? 'Bot detected by user agent'
                                        : 'High risk score (≥50)',
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie'               => $had_cookie,
                    'is_ai_bot'                => false,
                    'is_bot_ua'                => $this->is_bot_user_agent($user_agent),
                    'user_agent'               => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                    'score_threshold_exceeded' => $risk_score >= 50
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

        // ---- helpers ----
        $ua = strtolower($fp['userAgent'] ?? ($svh['user_agent'] ?? ''));
        $is_mobile_ua = (bool)preg_match('~(iphone|android|mobile|ipad|ipod|iemobile|blackberry|opera mini)~i', $ua);
        $is_ios = (bool)preg_match('~(iphone|ipad|ipod)~i', $ua);
        $is_android = (bool)preg_match('~android~i', $ua);
        $is_windows = (bool)preg_match('~windows nt~i', $ua);
        $is_mac = (bool)preg_match('~mac os x~i', $ua);

        $has_js_fp = !empty($fp);

        $ua_server = strtolower($svh['user_agent'] ?? '');
        if (preg_match('~(curl|wget|python-requests|go-http-client|okhttp|node-fetch|postmanruntime)~', $ua_server)) {
            $score += 30; $reasons[] = 'Non-browser HTTP client';
        }
        if (!$this->looks_like_browser_ua($ua_server)) {
            $score += 30;
            $reasons[] = 'Non-browser-like User-Agent';
        }
        if (empty($svh['accept_language'])) {
            $score += 5;  $reasons[] = 'Missing Accept-Language';
        }
        if (preg_match('~chrome/~i', $ua_server) && empty($svh['sec_ch_ua'])) {
            $score += 5;  $reasons[] = 'Missing Client Hints for Chrome-like UA';
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

            if ($webdriver) { $score += 35; $reasons[] = 'navigator.webdriver=true'; }

            // безопасная проверка WebGL без доступа к $fp['quirks'] напрямую
            $webglMode = $fp['quirks']['webgl'] ?? null;
            if ($webglExtCount === 0 && $webglMode !== null && $webglMode !== 'no-webgl') {
                $score += 10; $reasons[] = 'WebGL extensions = 0';
            }

            // 2) DPR vs UA
            if ($is_mobile_ua && $dpr <= 1.0) {
                $score += 20; $reasons[] = 'Mobile UA but DPR<=1';
            }
            if ($is_windows && $dpr > 1.5) {
                // Windows c DPR>1.5 бывает из-за масштабирования, но реже
                $score += 6;  $reasons[] = 'Windows with high DPR';
            }
            if ($is_mac && $dpr < 2 && preg_match('~\bMacintosh\b~i', $fp['userAgent'] ?? '')) {
                // Современные маки почти всегда DPR=2 (Retina)
                $score += 5;  $reasons[] = 'Mac UA but DPR<2';
            }

            $ua_server = strtolower($svh['user_agent'] ?? '');
            if (preg_match('~(curl|wget|python-requests|go-http-client|okhttp|node-fetch|postmanruntime)~', $ua_server)) {
                $score += 30; $reasons[] = 'Non-browser HTTP client';
            }
            if (empty($svh['accept_language'])) {
                $score += 5;  $reasons[] = 'Missing Accept-Language';
            }
            if (preg_match('~chrome/~i', $ua_server) && empty($svh['sec_ch_ua'])) {
                $score += 5;  $reasons[] = 'Missing Client Hints for Chrome-like UA';
            }

            // 3) Viewport vs Screen
            if ($sw > 0 && $sh > 0 && $vw > 0 && $vh > 0) {
                if ($viewportToScreen && $viewportToScreen < 0.25) {
                    $score += 15; $reasons[] = 'Very small viewport relative to screen (<0.25)';
                }
                if ($vw < 800 && !$is_mobile_ua && $dpr <= 1.1) {
                    $score += 8;  $reasons[] = 'Desktop UA with very small viewport';
                }
            } else {
                $score += 3; $reasons[] = 'Missing/invalid screen or viewport';
            }

            // 4) Touch vs UA
            if ($is_mobile_ua && $maxTouchPoints === 0 && !$touchEvent) {
                $score += 12; $reasons[] = 'Mobile UA without touch support';
            }
            if (!$is_mobile_ua && $maxTouchPoints > 0 && $dpr <= 1.1 && $vw > 1200) {
                $score += 4; $reasons[] = 'Desktop UA with touch points (mismatch)';
            }

            // 5) Plugins
            if ($pluginsCount === 0 && $is_windows) {
                $score += 6; $reasons[] = 'Windows with zero plugins';
            }

            // 6) PDF viewer flag (Chrome-специфика)
            if ($pdfViewer === false && preg_match('~chrome/|crios/|edg/~i', $ua)) {
                $score += 4; $reasons[] = 'Chrome-like UA without pdfViewer';
            }

            // 7) Outer/inner отношения окна
            if ($outerToInner > 1.6 || $outerToInner < 1.0) {
                // у headless часто странные рамки
                $score += 5; $reasons[] = 'Odd outer/inner ratio';
            }

            // 8) Языки: сверка navigator.language и Accept-Language
            if ($lang && $acceptLang && strpos($acceptLang, substr($lang,0,2)) === false) {
                $score += 5; $reasons[] = 'Language mismatch vs Accept-Language';
            }

            // 9) DST: в изолированных дата-центрах/контейнерах часто без DST
            if ($is_mobile_ua && !$hasDST) {
                $score += 3; $reasons[] = 'Mobile UA but no DST observed';
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
        ];
    }

    public function handle_fp( WP_REST_Request $request ) {
        // verify nonce header if present
        $nonce = $request->get_header('x-wp-nonce');
        if ($nonce && ! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_REST_Response(['error' => 'invalid_nonce'], 403);
        }

        $body = $request->get_json_params();
        if (empty($body)) {
            return new WP_REST_Response(['error' => 'empty_payload'], 400);
        }

        // augment with server-side info
        $server_info = [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'headers' => [
                'accept' => $_SERVER['HTTP_ACCEPT'] ?? null,
                'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
            ],
            'server_time' => current_time('mysql')
        ];

        $cookie_id = $this->get_cookie_id();
        $cookie_id_log = $cookie_id ? substr($cookie_id, 0, 8) . '…' : 'none';

        try {
            $evaluation     = $this->baskerville_score_fp($body, ['headers' => $server_info['headers']]);
            $classification = $this->classify_client($body, ['headers' => $server_info['headers']]);

            error_log('Baskerville evaluation result: ' . json_encode($evaluation));
            error_log('Baskerville classification result: ' . json_encode($classification));
        } catch (Exception $e) {
            error_log('Baskerville evaluation error: ' . $e->getMessage());
            $evaluation = ['score' => 0, 'action' => 'error', 'reasons' => ['evaluation_error']];
            $classification = ['classification' => 'unknown', 'reason' => 'Classification error', 'risk_score' => 0];
        }

        $log = [
            'id' => $cookie_id_log,
            'score' => $evaluation['score'],
            'action' => $evaluation['action'],
            'reasons' => $evaluation['reasons'],
            'classification' => $classification['classification'],
            'classification_reason' => $classification['reason'],
            'ua' => $body['fingerprint']['userAgent'] ?? 'unknown',
            'screen' => $body['fingerprint']['screen'] ?? 'unknown',
            'viewport' => $body['fingerprint']['viewport'] ?? 'unknown',
            'dpr' => $body['fingerprint']['dpr'] ?? 'unknown',
            'platform' => $body['fingerprint']['device']['platform'] ?? 'unknown',
            'webdriver' => $body['fingerprint']['device']['webdriver'] ?? false,
        ];

        error_log('Baskerville FP Summary: ' . json_encode($log));

        // Save visit statistics to database
        $save_result = $this->save_visit_stats(
            $server_info['ip'],
            $cookie_id ?? '',
            $evaluation,
            $classification,
            $server_info['headers']['user_agent'] ?? '',
            'fp'
        );

        if ($save_result === false) {
            error_log('Baskerville: Failed to save visit statistics to database');
        }


        return new WP_REST_Response([
            'ok'    => true,
            'score' => $evaluation['score'],
            'action'=> $evaluation['action'],
            'why'   => $evaluation['reasons'],
            'classification' => $classification,
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
          timestamp_utc datetime NOT NULL,
          score int(3) NOT NULL DEFAULT 0,
          classification varchar(50) NOT NULL DEFAULT 'unknown',
          user_agent text NOT NULL,
          evaluation_json longtext NOT NULL,
          score_reasons text NOT NULL,
          classification_reason text NOT NULL,
          event_type varchar(16) NOT NULL DEFAULT 'fp',
          created_at timestamp DEFAULT CURRENT_TIMESTAMP,
          updated_at timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          KEY visit_key (visit_key),
          KEY ip (ip),
          KEY baskerville_id (baskerville_id),
          KEY timestamp_utc (timestamp_utc),
          KEY classification (classification),
          KEY score (score),
          KEY event_type (event_type)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        // Add version option to track schema changes
        add_option('baskerville_db_version', '1.0');
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
            AVG(score) AS avg_score
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
            $botsum  = $bad + $ai + $bot;

            $out[] = [
                'time'            => $r['time_slot'],
                'total_visits'    => $total,
                'human_count'     => $human,
                'bad_bot_count'   => $bad,
                'ai_bot_count'    => $ai,
                'bot_count'       => $bot,
                'bot_percentage'  => $total ? round($botsum*100/$total,1) : 0,
                'avg_score'       => round((float)$r['avg_score'],1),
            ];
        }
        return $out;
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
            AVG(score) avg_score,
            MIN(timestamp_utc) first_record,
            MAX(timestamp_utc) last_record
          FROM $table
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A);
        if (!$row) return [];

        $total = (int)$row['total_visits'];
        $bots  = (int)$row['bad_bot_count'] + (int)$row['ai_bot_count'] + (int)$row['bot_count'];

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

    public function save_visit_stats($ip, $baskerville_id, $evaluation, $classification, $user_agent, $event_type = 'fp') {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        $visit_key = hash('sha256', $ip.'|'.$baskerville_id.'|'.microtime(true).'|'.wp_generate_uuid4());

        $data = [
            'visit_key' => $visit_key,
            'ip' => $ip,
            'baskerville_id' => $baskerville_id,
            'timestamp_utc' => current_time('mysql', true),
            'score' => $evaluation['score'],
            'classification' => $classification['classification'],
            'user_agent' => $user_agent,
            'evaluation_json' => json_encode($evaluation),
            'score_reasons' => implode('; ', $evaluation['reasons']),
            'classification_reason' => $classification['reason'],
            'event_type' => $event_type, // <— NEW
        ];

        $result = $wpdb->insert($table_name, $data,
            ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s']
        );

        if ($result === false) {
            error_log('Baskerville: Failed to save visit stats - ' . $wpdb->last_error);
            return false;
        }
        return true;
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
                <h1>🛡️ Baskerville Traffic Analytics</h1>

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
            </div>

            <script>
                let chart = null;
                let currentHours = 24;
                let chartHumAuto = null;
                let chartHumAutoPie = null;

                const STATS_URL = '<?php echo esc_js($stats_url); ?>';

                // Возвращает HH:MM из строки вида "YYYY-MM-DD HH:MM:SS" (или любой строки с временем)
                function fmtHHMM(ts) {
                  const m = String(ts || '').match(/\b(\d{2}):(\d{2})/);
                  return m ? `${m[1]}:${m[2]}` : String(ts || '');
                }

                async function loadData(hours = 24) {
                    try {
                        currentHours = hours;

                        // Update active button
                        document.querySelectorAll('.control-button').forEach(btn => btn.classList.remove('active'));
                        event?.target?.classList.add('active');

                        const response = await fetch(`${STATS_URL}?hours=${hours}&_=${Date.now()}`, { cache: 'no-store' });

                        const data = await response.json();

                        updateSummaryStats(data.summary);
                        updateHumAutoCharts(data.timeseries);
                        updateChart(data.timeseries);
                    } catch (error) {
                        console.error('Error loading data:', error);
                    }
                }

                function updateSummaryStats(summary) {
                    const statsHtml = `
                        <div class="stat-card">
                            <div class="stat-number">${summary.total_visits || 0}</div>
                            <div class="stat-label">Total Visits</div>
                        </div>
                        <div class="stat-card human">
                            <div class="stat-number">${summary.human_percentage || 0}%</div>
                            <div class="stat-label">Human Traffic</div>
                        </div>
                        <div class="stat-card bot">
                            <div class="stat-number">${summary.bot_percentage || 0}%</div>
                            <div class="stat-label">Bot Traffic</div>
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
                  const automated = timeseries.map(i => (i.bad_bot_count||0) + (i.ai_bot_count||0) + (i.bot_count||0));

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
                        title: { display: true, text: `Humans vs Automated — last ${currentHours}h` },
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
                        title: { display: true, text: `Totals — last ${currentHours}h` },
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

                  chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: 'Humans',   data: humans,  stack: 'visits', backgroundColor: '#4CAF50' },
                        { label: 'Bad bots', data: badBots, stack: 'visits', backgroundColor: '#ff6b6b' },
                        { label: 'AI bots',  data: aiBots,  stack: 'visits', backgroundColor: '#ff9800' }, // оранжевый
                        { label: 'Bots',     data: bots,    stack: 'visits', backgroundColor: '#673AB7' }, // фиолетовый, явно отличается
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
                        title: { display: true, text: `Traffic Analysis - Last ${currentHours} Hours` },
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

    public function handle_stats_data(WP_REST_Request $request) {
        if (!headers_sent()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
        }

        $hours = max(1, min(720, (int)($request->get_param('hours') ?: 24)));

        $timeseries = $this->get_timeseries_data($hours);
        $summary    = $this->get_summary_stats();

        return new WP_REST_Response([
            'ok'          => true,
            'timeseries'  => $timeseries,
            'summary'     => $summary,
            'hours'       => $hours,
            'generated_at'=> gmdate('c'),
        ], 200);
    }


    public function activate() {
        $this->create_stats_table();
        if (!get_option('baskerville_retention_days')) {
            add_option('baskerville_retention_days', BASKERVILLE_DEFAULT_RETENTION_DAYS);
        }
        if (!get_option('baskerville_cookie_secret')) {
            add_option('baskerville_cookie_secret', bin2hex(random_bytes(32)));
        }
        if (!wp_next_scheduled('baskerville_cleanup_stats')) {
            wp_schedule_event(time(), 'daily', 'baskerville_cleanup_stats');
        }
        flush_rewrite_rules();
    }

    public function deactivate() {
        // Clean up scheduled event
        wp_clear_scheduled_hook('baskerville_cleanup_stats');
        flush_rewrite_rules();
    }
}

new Baskerville();
