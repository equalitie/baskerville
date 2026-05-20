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
        'ClaudeBot'           => 'Anthropic',
        'GPTBot'              => 'OpenAI',
        'OAISearchBot'        => 'OpenAI',
        'ChatGPT-User'        => 'OpenAI',
        'GoogleExtended'      => 'Google',
        'GoogleSpecial'       => 'Google',
        'GoogleUserTriggered' => 'Google',
        'PerplexityBot'       => 'Perplexity',
        'PerplexityUser'      => 'Perplexity',
        'MistralBot'          => 'Mistral',
        'MistralAIUser'       => 'Mistral',
        'DuckAssistBot'       => 'DuckDuckGo',
        'Bingbot'             => 'Microsoft',
        'CCBot'               => 'Common Crawl',
        'AmazonBot'           => 'Amazon',
    ];

    /**
     * Companies that verify via reverse DNS (no public IP-range JSON).
     * Key   = company name (as returned by get_ai_bot_company()).
     * Value = [
     *   'suffixes' => PTR hostname suffixes that confirm the company,
     *   'cidrs'    => fallback static CIDR list when PTR lookup fails/is missing.
     *                 (CIDRs are stable allocations owned by the company; safe to hardcode.)
     * ]
     */
    private const RDNS_VERIFIED_COMPANIES = [
        'Meta' => [
            'suffixes' => ['.facebook.com', '.fbscan.com'],
            'cidrs'    => [
                // Meta / Facebook AS32934 — primary data-center IPv6 block
                '2a03:2880::/32',
                // Meta older IPv6 ranges
                '2620:0:1c00::/40',
                '2620:0:1c10::/40',
                '2620:0:1c18::/40',
                // Meta IPv4 ranges
                '66.220.144.0/20',
                '69.63.176.0/20',
                '173.252.64.0/18',
                '31.13.24.0/21',
                '31.13.64.0/18',
                '31.13.96.0/19',
                '204.15.20.0/22',
            ],
        ],
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
            'facebookexternalhit', 'facebookcatalog', 'facebookbot', 'facebot', 'twitterbot', 'linkedinbot',
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
            // OpenAI
            'gptbot',                // GPTBot (official crawler)
            'chatgpt-user',          // ChatGPT browsing plugin
            'oai-searchbot',         // OAISearchBot (SearchGPT)
            'chatgpt',               // Generic ChatGPT client

            // Anthropic
            'claudebot',             // ClaudeBot (official crawler)
            'claude-user',           // Claude browsing/operator
            'claude-searchbot',      // Claude search
            'anthropic-ai',          // Anthropic generic

            // Google
            'google-extended',       // Google AI opt-out token
            'google-cloudvertexbot', // Vertex AI
            'google-notebooklm',     // NotebookLM
            'googleagent-mariner',   // Project Mariner
            'googleagent-urlcontext',// Gemini URL context
            'google-firebase',       // Firebase AI
            'gemini-deep-research',  // Gemini Deep Research
            'google-agent',          // Generic Google agent

            // Meta
            'meta-externalagent',    // Meta AI training crawler
            'meta-externalfetcher',  // Meta fetching agent
            'meta-webindexer',       // Meta web indexer
            // facebookbot and facebot are link-preview crawlers, not AI crawlers — verified via FCrDNS Meta only for meta-externalagent

            // Amazon / AWS
            'amazonbot',             // Amazon AI research
            'bedrockbot',            // Amazon Bedrock
            'novaact',               // Amazon Nova Act agent
            'amazonbuyforme',        // Amazon agentic shopping

            // ByteDance / TikTok
            'bytespider',            // ByteDance crawler
            'tiktokspider',          // TikTok web indexer

            // Perplexity
            'perplexitybot',         // PerplexityBot
            'perplexity-user',       // Perplexity user-facing requests

            // Mistral
            'mistralbot',            // MistralBot (index crawler)
            'mistralai-user',        // MistralAI-User

            // DeepSeek
            'deepseekbot',           // DeepSeek crawler

            // Microsoft / Bing
            'bingbot',               // Bingbot (Microsoft Copilot/AI Search)

            // DuckDuckGo
            'duckassistbot',         // DuckAssist AI

            // Cohere
            'cohere',                // Cohere training/inference

            // Common Crawl (major LLM training source)
            'ccbot',

            // Data aggregators / scraping-as-a-service
            'webzio-extended',       // Webz.io AI data
            'firecrawlagent',        // Firecrawl (LLM scraping)
            'youbot',                // You.com AI crawler
            'ai2bot',                // Allen Institute for AI
            'diffbot',               // Diffbot knowledge graph
            'omgilibot',             // Omgili / Webz
            'img2dataset',           // LAION img2dataset

            // Other / regional AI crawlers
            'yisouspider',           // Baidu affiliate
            'youdao',                // NetEase AI
            'petalbot',              // Huawei Petal Search
            'ai\scrawler',           // catch-all pattern
            'ai crawler',            // catch-all
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

        // Mapping: pattern => company name (more specific patterns first)
        $ai_bot_companies = [
            // OpenAI
            'gptbot'                  => 'OpenAI',
            'chatgpt-user'            => 'OpenAI',
            'oai-searchbot'           => 'OpenAI',
            'chatgpt'                 => 'OpenAI',

            // Anthropic
            'claudebot'               => 'Anthropic',
            'claude-user'             => 'Anthropic',
            'claude-searchbot'        => 'Anthropic',
            'anthropic-ai'            => 'Anthropic',

            // Google
            'google-cloudvertexbot'   => 'Google',
            'google-notebooklm'       => 'Google',
            'googleagent-mariner'     => 'Google',
            'googleagent-urlcontext'  => 'Google',
            'google-firebase'         => 'Google',
            'gemini-deep-research'    => 'Google',
            'google-extended'         => 'Google',
            'google-agent'            => 'Google',

            // Meta
            'meta-externalagent'      => 'Meta',
            'meta-externalfetcher'    => 'Meta',
            'meta-webindexer'         => 'Meta',

            // Amazon
            'amazonbot'               => 'Amazon',
            'bedrockbot'              => 'Amazon',
            'novaact'                 => 'Amazon',
            'amazonbuyforme'          => 'Amazon',

            // ByteDance / TikTok
            'tiktokspider'            => 'ByteDance',
            'bytespider'              => 'ByteDance',

            // Perplexity
            'perplexitybot'           => 'Perplexity',
            'perplexity-user'         => 'Perplexity',

            // Mistral
            'mistralbot'              => 'Mistral',
            'mistralai-user'          => 'Mistral',

            // DeepSeek
            'deepseekbot'             => 'DeepSeek',

            // Microsoft / Bing
            'bingbot'                 => 'Microsoft',

            // DuckDuckGo
            'duckassistbot'           => 'DuckDuckGo',

            // Cohere
            'cohere'                  => 'Cohere',

            // Common Crawl
            'ccbot'                   => 'Common Crawl',

            // Data aggregators
            'webzio-extended'         => 'Webz.io',
            'firecrawlagent'          => 'Firecrawl',
            'youbot'                  => 'You.com',
            'ai2bot'                  => 'Allen AI',
            'diffbot'                 => 'Diffbot',
            'omgilibot'               => 'Webz.io',
            'img2dataset'             => 'LAION',

            // Regional
            'yisouspider'             => 'Baidu',
            'youdao'                  => 'NetEase',
            'petalbot'                => 'Huawei',

            // Catch-all
            'ai\scrawler'             => 'Generic',
            'ai crawler'              => 'Generic',
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
        // Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            $ip = $m[1];
        }

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
     * Verify a bot IP via reverse DNS + forward confirmation.
     *
     * Algorithm (same as Googlebot/Meta official verification):
     *   1. PTR lookup: hostname = gethostbyaddr($ip)
     *   2. Check hostname ends with one of $allowed_suffixes
     *   3. Forward lookup: gethostbynamel($hostname) must contain $ip
     *
     * Result cached 15 min per IP to avoid repeated DNS round-trips on every request.
     *
     * @param string   $ip              Visitor IP
     * @param string[] $allowed_suffixes e.g. ['.facebook.com', '.fbscan.com']
     */
    /**
     * Build the PTR lookup hostname for an IP.
     * For IPv4: standard in-addr.arpa form.
     * For IPv6: expand to full 32 hex digits, reverse nibble by nibble, append ip6.arpa.
     * Returns empty string on invalid input.
     */
    private function ip_to_ptr_host(string $ip): string {
        $bin = @inet_pton($ip);
        if ($bin === false) return '';

        if (strlen($bin) === 4) {
            // IPv4
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }

        // IPv6: expand to 32 hex nibbles, reverse, join with dots
        $hex     = bin2hex($bin);                       // 32 hex chars
        $nibbles = str_split($hex, 1);                  // ['2','a','0','3',...]
        $reversed = array_reverse($nibbles);
        return implode('.', $reversed) . '.ip6.arpa';
    }

    private function verify_by_rdns(string $ip, array $allowed_suffixes): bool {
        $cache_key = 'ai_rdns_' . substr(md5($ip), 0, 12);
        $cached    = $this->core->fc_get($cache_key);
        if ($cached !== null) return (bool) $cached;

        $result = false;

        // Use dns_get_record() for PTR lookup — more reliable than gethostbyaddr() for IPv6
        $ptr_host = $this->ip_to_ptr_host($ip);
        $hostname = '';
        if ($ptr_host !== '') {
            $ptr_records = @dns_get_record($ptr_host, DNS_PTR);
            if (is_array($ptr_records) && !empty($ptr_records)) {
                $hostname = $ptr_records[0]['target'] ?? '';
            }
        }

        // Fallback to gethostbyaddr for systems where dns_get_record PTR fails
        if ($hostname === '') {
            $h = @gethostbyaddr($ip);
            if ($h !== false && $h !== $ip) {
                $hostname = $h;
            }
        }

        if ($hostname !== '') {
            foreach ($allowed_suffixes as $suffix) {
                if (substr($hostname, -strlen($suffix)) === $suffix) {
                    // Forward-confirm: resolve A + AAAA, normalize via inet_pton for IPv6 comparison
                    $ip_bin = @inet_pton($ip);
                    foreach (['A', 'AAAA'] as $type) {
                        $records = @dns_get_record($hostname, constant('DNS_' . $type));
                        if (is_array($records)) {
                            foreach ($records as $rec) {
                                $addr     = $rec['ip'] ?? $rec['ipv6'] ?? null;
                                if ($addr === null) continue;
                                $addr_bin = @inet_pton($addr);
                                if ($ip_bin !== false && $addr_bin !== false && $ip_bin === $addr_bin) {
                                    $result = true;
                                    break 2;
                                }
                            }
                        }
                    }
                    error_log(sprintf(
                        '[AiBotVerificator] rDNS %s → %s | forward match: %s',
                        $ip, $hostname, $result ? 'yes' : 'no'
                    ));
                    break;
                }
            }
        }

        if (defined('BASKERVILLE_DEBUG') && BASKERVILLE_DEBUG) {
            error_log(sprintf('[AiBotVerificator] verify_by_rdns %s ptr=%s host=%s result=%s',
                $ip, $ptr_host, $hostname, $result ? 'true' : 'false'));
        }

        $this->core->fc_set($cache_key, $result, 15 * MINUTE_IN_SECONDS);
        return $result;
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
            // Anthropic
            'ClaudeBot'           => 'https://claude.com/crawling/bots.json',
            // OpenAI
            'GPTBot'              => 'https://openai.com/gptbot.json',
            'OAISearchBot'        => 'https://openai.com/searchbot.json',
            'ChatGPT-User'        => 'https://openai.com/chatgpt-user.json',
            // Google
            'GoogleExtended'      => 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
            'GoogleSpecial'       => 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
            'GoogleUserTriggered' => 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
            // Perplexity
            'PerplexityBot'       => 'https://www.perplexity.ai/perplexitybot.json',
            'PerplexityUser'      => 'https://www.perplexity.ai/perplexity-user.json',
            // Mistral
            'MistralBot'          => 'https://mistral.ai/mistralai-index-ips.json',
            'MistralAIUser'       => 'https://mistral.ai/mistralai-user-ips.json',
            // DuckDuckGo
            'DuckAssistBot'       => 'https://duckduckgo.com/duckduckbot.json',
            // Microsoft / Bing
            'Bingbot'             => 'https://www.bing.com/toolbox/bingbot.json',
            // Common Crawl
            'CCBot'               => 'https://index.commoncrawl.org/ccbot.json',
            // Amazon
            'AmazonBot'           => 'https://developer.amazon.com/amazonbot/ip-addresses/',
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
                error_log("[AiBotVerificator] {$name} fetch failed: " . $response->get_error_message());
                $result[$name] = $existing[$name] ?? [];
                continue;
            }
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            if (!is_array($data)) {
                error_log("[AiBotVerificator] {$name}: invalid JSON");
                $result[$name] = $existing[$name] ?? [];
                continue;
            }
            $prefixes      = $this->parse_ai_prefixes($data);
            $result[$name] = $prefixes;
            error_log("[AiBotVerificator] {$name}: loaded " . count($prefixes) . ' prefixes');
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
        // Normalize IPv4-mapped IPv6 to plain IPv4
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            $ip = $m[1];
        }
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

        // 1) AI bot detection — UA check first (fast, no HTTP), then IP ranges only when needed.
        // We never fetch IP ranges for normal requests — only when UA already claims to be an AI bot.
        if ($this->is_ai_bot_user_agent($user_agent)) {
            $company   = $this->get_ai_bot_company($user_agent);
            $ai_ranges = $this->get_ai_ip_ranges(); // cached; HTTP only on hourly cache miss

            // Check if the IP actually belongs to this company's published ranges
            $ip_bot_name = '';
            foreach ($ai_ranges as $name => $cidrs) {
                foreach ($cidrs as $cidr) {
                    if ($this->ip_in_cidr($ip, $cidr)) { $ip_bot_name = $name; break 2; }
                }
            }

            if ($ip_bot_name) {
                // UA + IP both confirm → verified
                $verified_company = self::VERIFIED_AI_COMPANIES[$ip_bot_name] ?? $ip_bot_name;
                return [
                    'classification' => 'verified_ai_bot',
                    /* translators: %s: bot name from published IP range */
                    'reason'         => sprintf( __( 'Verified AI bot by IP range (%s)', 'baskerville-ai-security' ), $ip_bot_name ),
                    'risk_score'     => 0,
                    'details'        => [
                        'ip_verified_as' => $ip_bot_name,
                        'company'        => $verified_company,
                        'ua_claimed_ai'  => true,
                        'user_agent'     => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                    ],
                ];
            }

            // UA claims AI but IP didn't match — check if we actually have ranges for this company
            // (guards against false positives when ranges failed to load)
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
            // rDNS-verified companies (e.g. Meta — no published IP range JSON)
            if (isset(self::RDNS_VERIFIED_COMPANIES[$company])) {
                $entry    = self::RDNS_VERIFIED_COMPANIES[$company];
                $suffixes = $entry['suffixes'] ?? [];
                $cidrs    = $entry['cidrs']    ?? [];

                // 1) Try FCrDNS (PTR → suffix + forward match)
                $rdns_ok = $this->verify_by_rdns($ip, $suffixes);

                // 2) Fallback: check hardcoded static CIDRs for this company.
                //    PTR records may not exist for all IPs (e.g. Meta often has no PTR
                //    for /32 host addresses in 2a03:2880::/32).  Since CIDRs are
                //    owned by the company, an IP match is as trustworthy as FCrDNS.
                $cidr_ok = false;
                if (!$rdns_ok && !empty($cidrs)) {
                    foreach ($cidrs as $cidr) {
                        if ($this->ip_in_cidr($ip, $cidr)) {
                            $cidr_ok = true;
                            break;
                        }
                    }
                }

                if ($rdns_ok || $cidr_ok) {
                    $method = $rdns_ok ? 'rDNS' : 'static CIDR';
                    return [
                        'classification' => 'verified_ai_bot',
                        /* translators: %1$s: AI bot company name, %2$s: verification method */
                        'reason'         => sprintf( __( 'Verified AI bot by %2$s (%1$s)', 'baskerville-ai-security' ), $company, $method ),
                        'risk_score'     => 0,
                        'details'        => [
                            'ip_verified_as' => $company,
                            'company'        => $company,
                            'ua_claimed_ai'  => true,
                            'user_agent'     => substr($user_agent, 0, 100) . (strlen($user_agent) > 100 ? '...' : ''),
                        ],
                    ];
                }
                // Both rDNS and static CIDR failed — suspicious
                return [
                    'classification' => 'ai_bot_unverified',
                    /* translators: %s: AI bot company name */
                    'reason'         => sprintf( __( 'AI bot UA (%s) but rDNS verification failed', 'baskerville-ai-security' ), $company ),
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

            // Company doesn't publish ranges and doesn't use rDNS — can't verify, treat as regular ai_bot
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
