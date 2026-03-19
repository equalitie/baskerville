<?php
// Dependency for main this handles:
// the wordpress portion that actually tee's off the requests, 
// gathering the metadata needed and sending that metadata to the server for ML processing
// which required for processing requests into prediction pipeline and
// consuming predictions from pipeline and pushing any rules ML 
// pipeline generates back to customer to enforce and hosts solver for challenges and 
// verifying payments (required for authn & authz)

// require_once __DIR__ . '/gatekeeper.php';

if (!defined('ABSPATH')) {
    exit;
}

//-------------------------
//-------------------------
//constants
//-------------------------
//-------------------------

// just for debugging to console set to false when done "measuring"
if (!defined('WPSEC_DEBUG')) {
    //change to false in prod
    define('WPSEC_DEBUG', true); 
}

// clearinghouse endpoint - now go through workers to reduce network rtt
// define('CLEARINGHOUSE_ENDPOINT', 'https://greything.com/wpsec/logs');
// define('PERFORMANCE_TRACKER_ENDPOINT', 'https://greything.com/wpsec/perf');

define('CLEARINGHOUSE_ENDPOINT', 'https://baskerville.ai/wpsec/logs');
define('PERFORMANCE_TRACKER_ENDPOINT', 'https://baskerville.ai/wpsec/perf');


//-------------------------
//-------------------------
//collect data
//-------------------------
//-------------------------


function wpsec_get_all_headers() {
    if (function_exists('getallheaders')) {
        $h = getallheaders();
        if (is_array($h)) {
            return $h;
        }
    }

    $headers = [];
    foreach ($_SERVER as $name => $value) {
        if (strpos($name, 'HTTP_') === 0) {
            $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
            $headers[$key] = $value;
        }
    }

    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
    }
    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];
    }

    return $headers;
}




function wpsec_build_worker_request() {
    $server  = $_SERVER;
    $headers = wpsec_get_all_headers();

    $scheme = (!empty($server['HTTPS']) && $server['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $server['HTTP_HOST'] ?? ($server['SERVER_NAME'] ?? '');
    $uri    = $server['REQUEST_URI'] ?? '';
    $query  = $server['QUERY_STRING'] ?? '';
    $url    = $scheme . '://' . $host . $uri;

    $method         = $server['REQUEST_METHOD'] ?? '';
    $userAgent      = $server['HTTP_USER_AGENT'] ?? '';
    $acceptLanguage = $server['HTTP_ACCEPT_LANGUAGE'] ?? '';
    $acceptEncoding = $server['HTTP_ACCEPT_ENCODING'] ?? '';
    $doNotTrack     = $server['HTTP_DNT'] ?? '';
    $contentType    = $server['CONTENT_TYPE'] ?? ($headers['Content-Type'] ?? '');
    $referer        = $server['HTTP_REFERER'] ?? '';

    $clientIp    = $server['HTTP_X_FORWARDED_FOR'] ?? ($server['REMOTE_ADDR'] ?? '');
    $httpVersion = $server['SERVER_PROTOCOL'] ?? '';

    $isDirectTraffic   = empty($referer);
    $isConditionalGet  = !empty($server['HTTP_IF_MODIFIED_SINCE']) || !empty($server['HTTP_IF_NONE_MATCH']);
    $clientRequestHostOriginal = $headers['X-Forwarded-Host'] ?? $host;

    $cloudflareRay = $server['HTTP_CF_RAY'] ?? '';
    $countryCode   = $server['HTTP_CF_IPCOUNTRY'] ?? '';

    $geoip = [
        'country_name'  => '',
        'country_code'  => $countryCode,
    ];

    $enc = strtolower($acceptEncoding);
    $clientAcceptEncoding = [
        'gzip'    => strpos($enc, 'gzip') !== false,
        'deflate' => strpos($enc, 'deflate') !== false,
        'br'      => strpos($enc, 'br') !== false,
        'zstd'    => strpos($enc, 'zstd') !== false,
    ];

    $cookies = [
        'deflectCookie'         => $_COOKIE['deflectCookie']         ?? '',
        'sessionCookie'         => $_COOKIE['sessionCookie']         ?? '',
        'challengeCookie'       => $_COOKIE['challengeCookie']       ?? '',
        'challengePassedCookie' => $_COOKIE['challengePassedCookie'] ?? '',
    ];

    $cloudflareProperties = [
        'keepalive'                  => false,
        'asn'                        => 0,
        'asOrganization'             => '',
        'botManagement'              => [
            'score'               => 0,
            'verifiedBot'         => false,
            'staticResource'      => false,
            'corporateProxy'      => false,
            'verifiedBotCategory' => '',
            'botDetectionIds'     => [],
            'js_detection'        => [
                'passed' => false,
            ],
        ],
        'city'                       => '',
        'clientAcceptEncoding'       => $clientAcceptEncoding,
        'clientTcpRtt'               => '',
        'cloudflare_datacenter_code' => '',
        'continent'                  => '',
        'country'                    => '',
        'edgeRequestKeepAliveStatus' => 0,
        'httpProtocol'               => $httpVersion,
        'isEUCountry'                => '',
        'latitude'                   => '',
        'longitude'                  => '',
        'postalCode'                 => '',
        'region'                     => '',
        'regionCode'                 => '',
        'request_priority'           => [
            'weight'      => 0,
            'exclusive'   => 0,
            'group'       => 0,
            'groupWeight' => 0,
        ],
        'timezone'                 => '',
        'tlsCipher'                => '',
        'tlsExportedAuthenticator' => [
            'clientFinished'  => '',
            'clientHandshake' => '',
            'serverHandshake' => '',
            'serverFinished'  => '',
        ],
        'tlsVersion' => '',
    ];

    $userAgentStruct = [
        'name'    => '',
        'os'      => [
            'name'    => '',
            'full'    => '',
            'version' => '',
        ],
        'version' => '',
        'device'  => [
            'name' => '',
        ],
    ];

    $ecs = [
        'version' => '',
    ];

    $httpResponseCode = 0;

    return [
        'request_type'               => 'http_request',
        'language'                   => $acceptLanguage,
        'client_accepted_encoding'   => $acceptEncoding,
        'cloudflare_ray'             => $cloudflareRay,
        'do_not_track'               => $doNotTrack,
        'is_direct_traffic'          => $isDirectTraffic,
        'request_origination_type'   => '',
        'request_mode'               => '',
        'request_destination_type'   => '',
        'is_conditional_get'         => $isConditionalGet,
        'cookies'                    => $cookies,
        'http_request_scheme'        => $scheme,
        'client_request_method'      => $method,
        'datestamp'                  => gmdate(DATE_ATOM),
        'geoip'                      => $geoip,
        'http_response_code'         => $httpResponseCode,
        'reply_length_bytes'         => '',
        'http_request_version'       => $httpVersion,
        'user_agent'                 => $userAgentStruct,
        'client_user_agent'          => $userAgent,
        'ecs'                        => $ecs,
        'client_ip'                  => $clientIp,
        'client_url'                 => $url,
        'content_type'               => $contentType,
        'client_request_host_original' => $clientRequestHostOriginal,
        'cache_result'               => '',
        'client_request_host'        => $host,
        'querystring'                => $query,
        'cloudflareProperties'       => $cloudflareProperties,
    ];
}




//-------------------------
//-------------------------
//main
//-------------------------
//-------------------------

function wpsec_send_to_clearinghouse() {
    try {
        if (is_admin()) {
            return;
        }

        $api_key = get_option('wpsec_api_key');
        if (empty($api_key)) {
            error_log('[WPSEC] No API key configured. Skipping clearinghouse call.');

            if (defined('WPSEC_DEBUG') && WPSEC_DEBUG) {
                add_action('wp_footer', function () {
                    echo '<script>console.warn("[WPSEC] No API key configured... Skipping clearinghouse call.");</script>';
                });
            }

            //skip for now during testing, but UNCOMMENT once this is implemented
            // return;
        }

        $start_time = microtime(true);

        $payload = wp_json_encode(
            wpsec_build_worker_request(),
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        $response = wp_remote_post(CLEARINGHOUSE_ENDPOINT, [
            'headers'  => [
                'Content-Type'     => 'application/json',
                'X-WPSEC-Api-Key'  => $api_key,
                'X-WPSEC-Site-Url' => get_site_url(),
            ],
            'body'     => $payload,
            'timeout'  => 2,
            'blocking' => false,
        ]);

        $duration_ms = round((microtime(true) - $start_time) * 1000, 2);

        error_log(sprintf('[WPSEC] clearinghouse call overhead: %.2f ms (blocking=false)', $duration_ms));

        if (is_wp_error($response)) {
            error_log('[WPSEC] wp_remote_post error: ' . $response->get_error_message());
            $codeLabel = 'ERROR: ' . $response->get_error_message();
        } else {
            $code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            error_log(sprintf('[WPSEC] clearinghouse HTTP %d in %.2f ms', $code, $duration_ms));
            error_log('[WPSEC] clearinghouse response body: ' . substr($body, 0, 200));

            $codeLabel = 'HTTP ' . $code;
        }

        // send perf payload to tracker endpoint
        $performance_payload = wp_json_encode(
            ['ms_perf' => $duration_ms],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        wp_remote_post(PERFORMANCE_TRACKER_ENDPOINT, [
            'headers'  => [
                'Content-Type'     => 'application/json',
                'X-WPSEC-Api-Key'  => $api_key,
                'X-WPSEC-Site-Url' => get_site_url(),
            ],
            'body'     => $performance_payload,
            'timeout'  => 2,
            'blocking' => false,
        ]);

        if (defined('WPSEC_DEBUG') && WPSEC_DEBUG) {
            add_action('wp_footer', function () use ($duration_ms, $codeLabel) {
                printf(
                    '<script>console.log("[WPSEC] clearinghouse result: %s in %s ms");</script>',
                    esc_js($codeLabel),
                    esc_js($duration_ms)
                );
            });
        }
    } catch (\Exception $e) {
        error_log('[WPSEC] Unexpected exception: ' . $e->getMessage());
    } catch (\Error $e) {
        error_log('[WPSEC] Unexpected error: ' . $e->getMessage());
    }
}


//-------------------------
//-------------------------
//send log on each front-end request
//-------------------------
//-------------------------
add_action('init', 'wpsec_send_to_clearinghouse');