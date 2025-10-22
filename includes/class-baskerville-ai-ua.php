<?php

class Baskerville_AI_UA {

    /** @var Baskerville_Core */
    private $core;

    public function __construct(Baskerville_Core $core) {
        $this->core = $core;
    }

    public function looks_like_browser_ua(string $ua): bool {
        // любые из распространённых браузерных токенов
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
                $score += 6;  $reasons[] = 'Windows with high DPR';
                $contrib[] = ['key'=>'windows_high_dpr', 'delta'=>6, 'why'=>'Windows with high DPR'];
            }
            if ($is_mac && $dpr < 2 && preg_match('~\bMacintosh\b~i', $fp['userAgent'] ?? '')) {
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
                $score += 5; $reasons[] = 'Odd outer/inner ratio';
                $contrib[] = ['key'=>'odd_outer_inner_ratio', 'delta'=>5, 'why'=>'Odd outer/inner ratio'];
            }

            // 8) Языки: сверка navigator.language и Accept-Language
            if ($lang && $acceptLang && strpos($acceptLang, substr($lang,0,2)) === false) {
                $score += 5; $reasons[] = 'Language mismatch vs Accept-Language';
                $contrib[] = ['key'=>'language_mismatch', 'delta'=>5, 'why'=>'Language mismatch vs Accept-Language'];
            }

            // 9) DST
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

        // Была ли КУКА в исходном запросе
        $client_cookie_header = $_SERVER['HTTP_COOKIE'] ?? '';
        $had_cookie = (strpos($client_cookie_header, 'baskerville_id=') !== false) && ($this->core->get_cookie_id() !== null);

        // Оценка риска
        $evaluation = $this->baskerville_score_fp($payload, $server_ctx);
        $risk_score = (int) ($evaluation['score'] ?? 0);

        // Похоже ли на браузер
        $looks_like_browser = $this->looks_like_browser_ua($user_agent);

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

        // 2) BAD BOT: нет куки + небраузерный клиент и не «хороший» краулер
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
                    'has_cookie' => (bool)$this->core->get_cookie_id(),
                    'is_ai_bot'  => false,
                    'is_bot_ua'  => $this->is_bot_user_agent($_SERVER['HTTP_USER_AGENT'] ?? ''),
                    'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 100),
                    'burst_window_sec' => $window_sec,
                    'burst_threshold'  => $threshold,
                ]
            ];
        }
    }
}
