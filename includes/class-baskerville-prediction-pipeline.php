<?php
/**
 * Plugin Name: Baskerville Clearinghouse
 * Description: Sends request metadata to the Baskerville clearinghouse endpoint.
 * Version: 0.1.0
 * Author: eQualit.ie
 */

if (!defined('ABSPATH')) {
    exit;
}


//-------------------------------------------------------------
//-------------------------------------------------------------
//sets up log files
//NOTE: This is currently configured for per-request logs
//and clears after each (just for debugging)
//-------------------------------------------------------------
//-------------------------------------------------------------

function wpsec_log_reset() {
    $log_file = __DIR__ . '/wpsec-debug.txt';
    @file_put_contents($log_file, '');
}

function wpsec_log($message) {
    $log_file = __DIR__ . '/wpsec-debug.txt';
    $line = '[' . gmdate('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
    @file_put_contents($log_file, $line, FILE_APPEND);
}

function wpsec_show_log_if_requested() {
    if (!isset($_GET['wpsec_show_log'])) {
        return;
    }

    $log_file = __DIR__ . '/wpsec-debug.txt';

    header('Content-Type: text/plain; charset=utf-8');

    echo "LOG PATH: " . $log_file . "\n\n";

    if (file_exists($log_file)) {
        echo file_get_contents($log_file);
    } else {
        echo "log file does not exist\n";
    }

    exit;
}

wpsec_log_reset();
wpsec_show_log_if_requested();

wpsec_log('[main] main data collection plugin file loaded.');
require_once __DIR__ . '/class-baskerville-gatekeeper.php';
wpsec_log('[main] gatekeeper loaded.');

//as I was requested to implement, the logs go through cf edges to avoid waiting on 
// server to respond, edge will handle relaying it to the server since ML is async, 
// but since edges are closer to the wp origin in question its faster
define('CLEARINGHOUSE_ENDPOINT', 'https://baskerville.cc/wpsec/logs');


//-------------------------------------------------------------
//-------------------------------------------------------------
//data collection functions for logs to be sent to ml pipeline
//these functions satisfy the interfaces server side.
//NOTE: some fields are palceholders (for now as requested)
//-------------------------------------------------------------
//-------------------------------------------------------------


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




//-------------------------------------------------------------
//-------------------------------------------------------------
//handles gathering all required data and sending 
//it off to the server for ML processing
//-------------------------------------------------------------
//-------------------------------------------------------------

function wpsec_send_to_clearinghouse() {
    try {
        if (is_admin()) {
            return;
        }

        //lookup their API key (issued when signing up)
        $api_key = get_option('wpsec_api_key');
        if (empty($api_key)) {
            wpsec_log('[WPSEC MAIN] No API key configured. Skipping clearinghouse call.');
            //stop here for now since we don't yet issue the api key. But its here for when we
            //do and the server side already implements / expects to see it in order to process
            //any of these logs and perform any ml
            return;
        }

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

        if (is_wp_error($response)) {
            wpsec_log('[WPSEC MAIN] wp_remote_post error: ' . $response->get_error_message());
            $codeLabel = 'ERROR: ' . $response->get_error_message();
        } else {
            $code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            wpsec_log('[WPSEC MAIN] clearinghouse response body: ' . substr($body, 0, 200));

            $codeLabel = 'HTTP ' . $code;
        }

    } catch (\Exception $e) {
        wpsec_log('[WPSEC MAIN] Unexpected exception: ' . $e->getMessage());
    } catch (\Error $e) {
        wpsec_log('[WPSEC MAIN] Unexpected error: ' . $e->getMessage());
    }
}


//-------------------------------------------------------------
//-------------------------------------------------------------
//for every request to this origin, the plugin will invoke this
//function to gather all of the required data for the ml
//pipeline to injest and be able to predict.
// 
//tldr:
//sends log on each request made by users of wp origin
//to the baskerville ml pipelines
//-------------------------------------------------------------
//-------------------------------------------------------------
add_action('init', 'wpsec_send_to_clearinghouse');