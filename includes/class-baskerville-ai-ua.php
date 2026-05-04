<?php

class Baskerville_AI_UA {

    /** @var Baskerville_Core */
    private $core;

    /**
     * AI companies that publish official IP ranges.
     * Key = internal bot name (matches get_ai_ip_ranges keys),
     * Value = company name (matches get_ai_bot_company output).
     */
    private const VERIFIED_AI_COMPANIES = [
        'ClaudeBot'      => 'Anthropic',
        'GPTBot'         => 'OpenAI',
        'OAISearchBot'   => 'OpenAI',
        'GoogleExtended' => 'Google',
    ];

    public function __construct(Baskerville_Core $core) {
        $this->core = $core;
    }

    public function looks_like_browser_ua(string $ua): bool {
        // any common browser tokens
        return (bool) preg_match('~(mozilla/|chrome/|safari/|firefox/|edg/|opera|opr/)~i', $ua);
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
            'perplexitybot',         // Perplexity
            'ai\scrawler',           // catch-all
            'meta-externalagent',    // facebook training
        ];

        foreach ($ai_crawlers as $pattern) {
            if (preg_match('/' . $pattern . '/i', $ua)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the company/owner name for an AI bot user agent
     * @param string $user_agent
     * @return string Company name or 'Unknown'
     */
    public function get_ai_bot_company($user_agent) {
        if (empty($user_agent)) {
            return esc_html__('Unknown', 'baskerville-ai-security');
        }

        $ua = strtolower($user_agent);

        // Mapping: pattern => company name
        $ai_bot_companies = [
            'gptbot'              => 'OpenAI',
            'openai.*crawler'     => 'OpenAI',
            'openai-httplib'      => 'OpenAI',
            'chatgpt'             => 'OpenAI',
            'anthropic'           => 'Anthropic',
            'claudebot'           => 'Anthropic',
            'google-extended'     => 'Google',
            'bytespider'          => 'ByteDance',
            'yisouspider'         => 'Baidu',
            'youdao'              => 'NetEase',
            'ccbot'               => 'Common Crawl',
            'petalbot'            => 'Huawei',
            'facebookbot'         => 'Meta',
            'facebot'             => 'Meta',
            'meta-externalagent'  => 'Meta',
            'amazonbot'           => 'Amazon',
            'cohere'              => 'Cohere',
            'perplexitybot'       => 'Perplexity',
            'ai\scrawler'         => 'Generic',
            'ai crawler'          => 'Generic',
        ];

        foreach ($ai_bot_companies as $pattern => $company) {
            if (preg_match('/' . $pattern . '/i', $ua)) {
                return $company;
            }
        }

        return esc_html__('Unknown', 'baskerville-ai-security');
    }

    /**
     * Parse IP prefixes from an AI company's JSON.
     * Supports two formats:
     *   Anthropic/Google: {"prefixes": [{"ipv4Prefix":"1.2.3.0/24"}, {"ipv6Prefix":"..."}]}
     *   OpenAI:           {"prefixes": ["1.2.3.0/24", ...]}
     */
    private function parse_ai_prefixes(array $data): array {
        $result = [];
        foreach ($data['prefixes'] ?? [] as $item) {
            if (is_string($item) && $item !== '') {
                $result[] = $item;
            } elseif (is_array($item)) {
                $cidr = $item['ipv4Prefix'] ?? $item['ipv6Prefix'] ?? '';
                if ($cidr !== '') $result[] = $cidr;
            }
        }
        return $result;
    }

    /**
     * Check whether $ip falls within a CIDR range (IPv4 or IPv6).
     */
    private function ip_in_cidr(string $ip, string $cidr): bool {
        $parts  = explode('/', $cidr, 2);
        $range  = $parts[0];
        $prefix = isset($parts[1]) ? (int) $parts[1] : -1;

        $is_ipv6 = strpos($range, ':') !== false;

        if ($is_ipv6) {
            $ip_bin    = @inet_pton($ip);
            $range_bin = @inet_pton($range);
            if ($ip_bin === false || $range_bin === false || strlen($ip_bin) !== 16) return false;
            if ($prefix < 0) return $ip_bin === $range_bin;
            $prefix = min($prefix, 128);
            $full_bytes = intdiv($prefix, 8);
            $rem        = $prefix % 8;
            $mask       = str_repeat("\xff", $full_bytes);
            if ($rem > 0) $mask .= chr(0xff & (0xff << (8 - $rem)));
            $mask = str_pad($mask, 16, "\x00");
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary string masking
            return ($ip_bin & $mask) === ($range_bin & $mask);
        } else {
            $ip_long    = ip2long($ip);
            $range_long = ip2long($range);
            if ($ip_long === false || $range_long === false) return false;
            if ($prefix < 0) return $ip_long === $range_long;
            $prefix = min($prefix, 32);
            if ($prefix === 0) return true;
            $mask = -1 << (32 - $prefix);
            return ($ip_long & $mask) === ($range_long & $mask);
        }
    }

    /**
     * Fetch and cache IP ranges published by AI companies.
     * Cached for 1 hour via fc_get/fc_set (APCu or file).
     * Returns: ['ClaudeBot' => ['1.2.3.0/24', ...], 'GPTBot' => [...], ...]
     */
    private function get_ai_ip_ranges(): array {
        $cached = $this->core->fc_get('ai_ip_ranges');
        if (is_array($cached)) return $cached;

        $sources = [
            'ClaudeBot'      => 'https://claude.com/crawling/bots.json',
            'GPTBot'         => 'https://openai.com/gptbot.json',
            'OAISearchBot'   => 'https://openai.com/searchbot.json',
            'GoogleExtended' => 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
        ];

        // Keep old data on partial failure so we don't lose valid ranges
        $existing = is_array($cached) ? $cached : [];
        $result   = [];

        foreach ($sources as $name => $url) {
            $response = wp_remote_get($url, [
                'timeout'    => 5,
                'user-agent' => 'BaskervillePlugin/1.0',
            ]);
            if (is_wp_error($response)) {
                wpsec_log("[AiBotVerificator] {$name} fetch failed: " . $response->get_error_message());
                $result[$name] = $existing[$name] ?? [];
                continue;
            }
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            if (!is_array($data)) {
                wpsec_log("[AiBotVerificator] {$name}: invalid JSON");
                $result[$name] = $existing[$name] ?? [];
                continue;
            }
            $prefixes      = $this->parse_ai_prefixes($data);
            $result[$name] = $prefixes;
            wpsec_log("[AiBotVerificator] {$name}: loaded " . count($prefixes) . ' prefixes');
        }

        $this->core->fc_set('ai_ip_ranges', $result, HOUR_IN_SECONDS);
        return $result;
    }

    /**
     * Returns the internal bot name (e.g. "ClaudeBot", "GPTBot") if $ip belongs
     * to a published AI crawler range, or "" otherwise.
     */
    public function get_ai_bot_name_by_ip(string $ip): string {
        foreach ($this->get_ai_ip_ranges() as $name => $cidrs) {
            foreach ($cidrs as $cidr) {
                if ($this->ip_in_cidr($ip, $cidr)) return $name;
            }
        }
        return '';
    }

    public function verify_crawler_ip(string $ip, string $ua): array {
        $ua = strtolower($ua);
        $expect = null;

        if (strpos($ua,'googlebot') !== false)         $expect = ['.googlebot.com','.google.com'];
        elseif (strpos($ua,'bingbot') !== false)       $expect = ['.search.msn.com'];
        elseif (strpos($ua,'applebot') !== false)      $expect = ['.applebot.apple.com'];
        elseif (strpos($ua,'duckduckbot') !== false)   $expect = ['.duckduckgo.com'];
        else return ['claimed'=>false,'verified'=>false,'host'=>null];

        // cache key
        $ck = 'rdns:'.$ip;
        $cached = $this->core->fc_get($ck);
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
        // cache 6h on pass, 1h on fail
        $this->core->fc_set($ck, $res, $ok ? 6*3600 : 3600);
        return $res;
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
            $score += 30; $reasons[] = __( 'Non-browser HTTP client', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'non_browser_http', 'delta'=>30, 'why'=> __( 'Non-browser HTTP client', 'baskerville-ai-security' )];
        }
        if (!$this->looks_like_browser_ua($ua_server)) {
            $score += 30;
            $reasons[] = __( 'Non-browser-like User-Agent', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'non_browser_user_agent', 'delta'=>30, 'why'=> __( 'Non-browser-like User-Agent', 'baskerville-ai-security' )];
        }
        if (empty($svh['accept_language'])) {
            $score += 5;  $reasons[] = __( 'Missing Accept-Language', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'missing_accept_language', 'delta'=>5, 'why'=> __( 'Missing Accept-Language', 'baskerville-ai-security' )];
        }
        if (preg_match('~chrome/~i', $ua_server) && empty($svh['sec_ch_ua'])) {
            $score += 5;  $reasons[] = __( 'Missing Client Hints for Chrome-like UA', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'missing_hints_chrome', 'delta'=>5, 'why'=> __( 'Missing Client Hints for Chrome-like UA', 'baskerville-ai-security' )];
        }

        // Check HTTP protocol version - modern browsers use HTTP/2 or HTTP/3
        $server_protocol = strtoupper($svh['server_protocol'] ?? '');
        if (!empty($server_protocol) && preg_match('~^HTTP/1\.[01]$~', $server_protocol)) {
            // HTTP/1.0 or HTTP/1.1 - likely a bot/script
            // Modern browsers (Chrome, Firefox, Safari, Edge) use HTTP/2 or HTTP/3
            $score += 15;
            $reasons[] = __( 'Using HTTP/1.x (modern browsers use HTTP/2+)', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'http1_protocol', 'delta'=>15, 'why'=> __( 'Using HTTP/1.x instead of HTTP/2+', 'baskerville-ai-security' )];
        }

        if ($this->is_bot_user_agent($ua_server)) {
            $score += 25;
            if ($score < 70) $score = 70;
            $reasons[] = __( 'Bot UA detected', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'bot_ua', 'delta'=>25, 'why'=> __( 'Bot UA detected', 'baskerville-ai-security' )];
        }

        if ($this->is_ai_bot_user_agent($ua_server)) {
            $score += 10;
            $reasons[] = __( 'AI bot UA detected', 'baskerville-ai-security' );
            $contrib[] = ['key'=>'ai_bot_ua', 'delta'=>10, 'why'=> __( 'AI bot UA detected', 'baskerville-ai-security' )];
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
                $contrib[] = ['key'=>'webdriver', 'delta'=>35, 'why'=> 'navigator.webdriver=true'];
            }

            $webglMode = $fp['quirks']['webgl'] ?? null;
            if ($webglExtCount === 0 && $webglMode !== null && $webglMode !== 'no-webgl') {
                $score += 10; $reasons[] = __( 'WebGL extensions = 0', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'no_web_gl', 'delta'=>10, 'why'=> __( 'WebGL extensions = 0', 'baskerville-ai-security' )];
            }

            // 2) DPR vs UA
            if ($is_mobile_ua && $dpr <= 1.0) {
                $score += 20; $reasons[] = __( 'Mobile UA but DPR<=1', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'mobile_ua_small_dpr', 'delta'=>20, 'why'=> __( 'Mobile UA but DPR<=1', 'baskerville-ai-security' )];
            }
            if ($is_windows && $dpr > 1.5) {
                $score += 6;  $reasons[] = __( 'Windows with high DPR', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'windows_high_dpr', 'delta'=>6, 'why'=> __( 'Windows with high DPR', 'baskerville-ai-security' )];
            }
            if ($is_mac && $dpr < 2 && preg_match('~\bMacintosh\b~i', $fp['userAgent'] ?? '')) {
                $score += 5;  $reasons[] = __( 'Mac UA but DPR<2', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'mac_ua_low_dpr', 'delta'=>5, 'why'=> __( 'Mac UA but DPR<2', 'baskerville-ai-security' )];
            }

            // 3) Viewport vs Screen
            if ($sw > 0 && $sh > 0 && $vw > 0 && $vh > 0) {
                if ($viewportToScreen && $viewportToScreen < 0.25) {
                    $score += 15;
                    $reasons[] = __( 'Very small viewport relative to screen (<0.25)', 'baskerville-ai-security' );
                    $contrib[] = ['key'=>'small_viewport', 'delta'=>15, 'why'=> __( 'Very small viewport relative to screen (<0.25)', 'baskerville-ai-security' )];
                }
                if ($vw < 800 && !$is_mobile_ua && $dpr <= 1.1) {
                    $score += 8;
                    $reasons[] = __( 'Desktop UA with very small viewport', 'baskerville-ai-security' );
                    $contrib[] = ['key'=>'desktop_ua_small_viewport', 'delta'=>8, 'why'=> __( 'Desktop UA with very small viewport', 'baskerville-ai-security' )];
                }
            } else {
                $score += 3; $reasons[] = __( 'Missing/invalid screen or viewport', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'missing_viewport', 'delta'=>3, 'why'=> __( 'Missing/invalid screen or viewport', 'baskerville-ai-security' )];
            }

            // 4) Touch vs UA
            if ($is_mobile_ua && $maxTouchPoints === 0 && !$touchEvent) {
                $score += 12; $reasons[] = __( 'Mobile UA without touch support', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'mobile_ua_no_touch', 'delta'=>12, 'why'=> __( 'Mobile UA without touch support', 'baskerville-ai-security' )];
            }
            if (!$is_mobile_ua && $maxTouchPoints > 0 && $dpr <= 1.1 && $vw > 1200) {
                $score += 4; $reasons[] = __( 'Desktop UA with touch points (mismatch)', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'desktop_ua_with_touch', 'delta'=>4, 'why'=> __( 'Desktop UA with touch points (mismatch)', 'baskerville-ai-security' )];
            }

            // 5) Plugins
            if ($pluginsCount === 0 && $is_windows) {
                $score += 6; $reasons[] = __( 'Windows with zero plugins', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'zero_plugins', 'delta'=>6, 'why'=> __( 'Windows with zero plugins', 'baskerville-ai-security' )];
            }

            // 6) PDF viewer flag (Chrome-specific)
            if ($pdfViewer === false && preg_match('~chrome/|crios/|edg/~i', $ua)) {
                $score += 4; $reasons[] = __( 'Chrome-like UA without pdfViewer', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'chrome_no_pdf', 'delta'=>4, 'why'=> __( 'Chrome-like UA without pdfViewer', 'baskerville-ai-security' )];
            }

            // 7) Outer/inner window ratio
            if ($outerToInner > 1.6 || $outerToInner < 1.0) {
                $score += 5; $reasons[] = __( 'Odd outer/inner ratio', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'odd_outer_inner_ratio', 'delta'=>5, 'why'=> __( 'Odd outer/inner ratio', 'baskerville-ai-security' )];
            }

            // 8) Language check: compare navigator.language with Accept-Language
            if ($lang && $acceptLang && strpos($acceptLang, substr($lang,0,2)) === false) {
                $score += 5; $reasons[] = __( 'Language mismatch vs Accept-Language', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'language_mismatch', 'delta'=>5, 'why'=> __( 'Language mismatch vs Accept-Language', 'baskerville-ai-security' )];
            }

            // 9) DST
            if ($is_mobile_ua && !$hasDST) {
                $score += 3; $reasons[] = __( 'Mobile UA but no DST observed', 'baskerville-ai-security' );
                $contrib[] = ['key'=>'mobile_ua_no_dst', 'delta'=>3, 'why'=> __( 'Mobile UA but no DST observed', 'baskerville-ai-security' )];
            }
        }

        // Normalization/threshold
        if ($score < 0) $score = 0;
        if ($score > 100) $score = 100;

        // Recommendation
        $action = 'allow';
        if     ($score >= 60) $action = 'challenge';
        elseif ($score >= 40) $action = 'rate_limit';

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

    public function classify_client(array $payload, array $server_ctx = []) {
        $user_agent = $server_ctx['headers']['user_agent'] ?? '';
        $ua_lower   = strtolower($user_agent);

        // Was there a COOKIE in the original request
        $had_cookie = isset($_COOKIE['baskerville_id']) && ($this->core->get_cookie_id() !== null);

        // Risk assessment
        $evaluation = $this->baskerville_score_fp($payload, $server_ctx);
        $risk_score = (int) ($evaluation['score'] ?? 0);

        // Looks like a browser
        $looks_like_browser = $this->looks_like_browser_ua($user_agent);

        // Explicit non-browser clients
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
        if (!$is_nonbrowser_client && strlen(trim($ua_lower)) < 6) { $is_nonbrowser_client = true; }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        $vc = $this->verify_crawler_ip($ip, $user_agent);

        // Check if verified crawlers should be allowed (default: true)
        $options = get_option('baskerville_settings', array());
        $allow_verified = !isset($options['allow_verified_crawlers']) || $options['allow_verified_crawlers'];
        $verified_crawler = $allow_verified && ($vc['claimed'] && $vc['verified']);

        if ($vc['claimed'] && !$vc['verified']) {
            $risk_score = max($risk_score, 50);
        }
        if ($verified_crawler) {
            return [
                'classification' => 'verified_bot',
                /* translators: %s: crawler hostname or rDNS identifier */
                'reason' => sprintf( __( 'Verified crawler (%s)', 'baskerville-ai-security' ), $vc['host'] ?: 'rDNS' ),
                'crawler_verified' => true,
                'risk_score' => min(10, $risk_score),
            ];
        }

        // 1) AI IP range verification (authoritative — checked before UA)
        // Fetch once; reused below for the unverified/spoof check.
        $ai_ranges   = $this->get_ai_ip_ranges();
        $ip_bot_name = '';
        foreach ($ai_ranges as $name => $cidrs) {
            foreach ($cidrs as $cidr) {
                if ($this->ip_in_cidr($ip, $cidr)) { $ip_bot_name = $name; break 2; }
            }
        }
        if ($ip_bot_name) {
            $company = self::VERIFIED_AI_COMPANIES[$ip_bot_name] ?? $ip_bot_name;
            return [
                'classification' => 'verified_ai_bot',
                /* translators: %s: bot name from published IP range */
                'reason'         => sprintf( __( 'Verified AI bot by IP range (%s)', 'baskerville-ai-security' ), $ip_bot_name ),
                'risk_score'     => 0,
                'details'        => [
                    'ip_verified_as' => $ip_bot_name,
                    'company'        => $company,
                    'ua_claimed_ai'  => $this->is_ai_bot_user_agent($user_agent),
                    'user_agent'     => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                ],
            ];
        }

        // 2) AI bot by UA
        if ($this->is_ai_bot_user_agent($user_agent)) {
            $company = $this->get_ai_bot_company($user_agent);
            // Only flag as unverified/spoofed when we actually have ranges loaded for this company.
            // If ranges failed to fetch or the company isn't supported yet, fall through to ai_bot.
            $has_loaded_ranges = false;
            foreach (self::VERIFIED_AI_COMPANIES as $bot_name => $co) {
                if ($co === $company && !empty($ai_ranges[$bot_name])) {
                    $has_loaded_ranges = true;
                    break;
                }
            }
            if ($has_loaded_ranges) {
                return [
                    'classification' => 'ai_bot_unverified',
                    /* translators: %s: AI bot company name */
                    'reason'         => sprintf( __( 'AI bot UA (%s) but IP not in published ranges', 'baskerville-ai-security' ), $company ),
                    'risk_score'     => max(60, $risk_score),
                    'details'        => [
                        'has_cookie'     => $had_cookie,
                        'is_ai_bot'      => true,
                        'is_bot_ua'      => $this->is_bot_user_agent($user_agent),
                        'user_agent'     => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                        'company'        => $company,
                        'ip_verified_as' => null,
                    ],
                ];
            }
            // Company doesn't publish ranges — can't verify, treat as regular ai_bot
            return [
                'classification' => 'ai_bot',
                /* translators: %s: AI bot company name */
                'reason'         => sprintf( __( 'AI bot detected by user agent (%s)', 'baskerville-ai-security' ), $company ),
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie'     => $had_cookie,
                    'is_ai_bot'      => true,
                    'is_bot_ua'      => $this->is_bot_user_agent($user_agent),
                    'user_agent'     => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                    'company'        => $company,
                    'ip_verified_as' => null,
                ],
            ];
        }

        // 2) BAD BOT: no cookie + non-browser client and not a "good" crawler
        if (!$had_cookie && ($is_nonbrowser_client || (!$looks_like_browser && !$verified_crawler))) {
            return [
                'classification' => 'bad_bot',
                'reason'         => __( 'No prior cookie + non-browser User-Agent', 'baskerville-ai-security' ),
                'risk_score'     => max(50, $risk_score),
                'details'        => [
                    'has_cookie' => false,
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($user_agent),
                    'user_agent' => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : '')
                ]
            ];
        }

        // 3) BAD BOT: high risk and doesn't look like a browser
        if ($risk_score >= 50 && !$looks_like_browser && !$verified_crawler) {
            return [
                'classification' => 'bad_bot',
                'reason'         => __( 'High risk (≥50) and non-browser UA', 'baskerville-ai-security' ),
                'risk_score'     => $risk_score,
                'details'        => [
                    'has_cookie' => $had_cookie,
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($user_agent),
                    'user_agent' => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : '')
                ]
            ];
        }

        // 4) Other bots: bot-UA (including good crawlers) OR high risk
        $threshold = 30;
        if ($this->is_bot_user_agent($user_agent) || $risk_score >= $threshold) {
            return [
                'classification' => 'bot',
                'reason'         => $this->is_bot_user_agent($user_agent)
                                        ? __( 'Bot detected by user agent', 'baskerville-ai-security' )
                                        : __( 'High risk score', 'baskerville-ai-security' ),
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
            'reason'         => __( 'Appears to be human user', 'baskerville-ai-security' ),
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

    /** If there are too many page hits WITHOUT FP from an IP in a short window — mark as bad_bot */
    private function maybe_mark_ip_as_bad_bot_on_burst(string $ip, array &$classification): void {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
        $threshold  = (int) get_option('baskerville_nojs_threshold', 20);

        // count ONLY page records without received FP (had_fp=0) for the recent window
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $table is safe, constructed from $wpdb->prefix
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Real-time burst detection requires fresh data
        $cnt = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM %i
             WHERE ip=%s
               AND event_type='page'
               AND had_fp=0
               AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)",
            $table,
            $ip,
            $window_sec
        ));
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

        if ($cnt >= $threshold) {
            $classification = [
                'classification' => 'bad_bot',
                /* translators: %1$d is the number of page hits, %2$d is the time window in seconds */
                'reason' => sprintf(esc_html__('Excessive no-JS page hits: %1$d in %2$ds', 'baskerville-ai-security'), $cnt, $window_sec),
                'risk_score' => max(50, (int)($classification['risk_score'] ?? 0)),
                'details' => [
                    'has_cookie' => (bool)$this->core->get_cookie_id(),
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''))),
                    'user_agent' => substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 100),
                    'burst_window_sec' => $window_sec,
                    'burst_threshold'  => $threshold,
                ]
            ];
        }
    }
}
