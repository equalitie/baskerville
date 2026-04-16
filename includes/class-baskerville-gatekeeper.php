<?php

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('wpsec_log')) {
    function wpsec_log($message) {
        if (defined('BASKERVILLE_DEBUG') && BASKERVILLE_DEBUG) {
            error_log('[Baskerville Gatekeeper] ' . $message);
        }
    }
}

//--------------------------------------------------
//--------------------------------------------------
//constants
//--------------------------------------------------
//--------------------------------------------------

/*
    WHILE USER IS BEING CHALLENGED, THERE ARE 3 RELEVANT COOKIES THEY NEED TO CARRY:
    when the user submits their solution, it is sent as cookies in the form:
    __wpsec_sol_hash_ (the solution hash) as well as one or more cookies of the form:
    __wpsec_cc_x_x (__wpsec_cc_1_1, __wpsec_cc_1_2, __wpsec_cc_2_1, etc...) and 
    when a challenge is issued, the entropy we use to make this challenge unique to the user
    is in the form of the __wpsec_challenge_ cookie which hashes many things including IP address etc
    to make it unique to them
*/
define('USER_SOLUTION_HASH_COOKIE_NAME', '__wpsec_sol_hash_');
define('USER_SOLUTION_CLICK_CHAIN_COOKIE_PREFIX', '__wpsec_cc_');
define('USER_CAPTCHA_CHALLENGE_COOKIE_NAME', '__wpsec_challenge_');

/*
    WHEN THE USER HAS PASSED THE CAPTCHA, THERES ONE IMPORTANT COOKIE THEY NEED TO CARRY:
    when the user passes the captcha they are given the __wpsec_sol_ cookie 
    they must provide on all subsequent requests
*/
define('CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME', '__wpsec_solved_');

/*
    Endpoints
*/
define('CAPTCHA_SOLUTION_VERIFICATION_ENDPOINT', 'https://captcha.openports.dev/captcha/verify');
define('CAPTCHA_PREVIOUSLY_PASSED_TOKEN_VERIFICATION_ENDPOINT', 'https://captcha.openports.dev/token/verify');
define('CAPTCHA_REFRESH_ENDPOINT', 'https://captcha.openports.dev/captcha/refresh');
define('CAPTCHA_GENERATION_ENDPOINT', 'https://captcha.openports.dev/captcha/generate');






//--------------------------------------------------
//--------------------------------------------------
//helpers
//--------------------------------------------------
//--------------------------------------------------

/*
    helper for decision logic. Any decision logic goes here. 
    so if we are going to plug in baskerville, we would push 
    decisions and store them on the wp origin at which point 
    we would read them here. It really doesnt matter how we do 
    it what matters is that the function signature is satisfied 
    as it should always return true if challenge we can add other 
    decisions in a similar fashion by making individual functions for 
    rate limiting, banning etc checking, returning bool and extending the
    wpsec_enforce_captcha_policy() function
*/
function wpsec_should_challenge() {
    wpsec_log('[gatekeeper] checking challenge decision');

    $should_challenge = !empty($GLOBALS['baskerville_gatekeeper_challenge']);

    wpsec_log('[gatekeeper] challenge decision=' . ($should_challenge ? 'challenge' : 'allow'));
    return $should_challenge;
}

/*
    helper that enables us to relay info back to the client side.
    As described before, when the client side submits a solution, in order
    to avoid tampering with or adding additional endpoints on someone elses website
    we communicate state through cookies in headers. If we want to communicate with the 
    client side (to show them a message for example that their solution was incorrect
    or that they are being rate limited, we send back plain text responses that the 
    client side knows how to parse).
*/
function wpsec_send_plain_response($status_code, $message) {
    status_header((int) $status_code);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    header('Surrogate-Control: no-store');
    header('CDN-Cache-Control: no-store');
    echo (string) $message;
    exit;
}

/*
    helper to check for non relevant follow up requests which need
    not be validated / interferred with (ie to not break existing site/page
    functionality)
*/
function wpsec_is_asset_like_request() {
    $uri = $_SERVER['REQUEST_URI'] ?? '';

    if ($uri === '') {
        return false;
    }

    if (preg_match('/\.(ico|png|jpg|jpeg|gif|svg|webp|css|js|map|txt|woff|woff2|ttf|eot)$/i', $uri)) {
        return true;
    }

    return false;
}

/**
 * Clear only the per-attempt solution cookies (__wpsec_sol_hash_ and __wpsec_cc_*).
 * Unlike wpsec_clear_challenge_cookies(), this intentionally keeps __wpsec_challenge_
 * so the visitor can retry the same puzzle after a failed verification attempt.
 */
function wpsec_clear_solution_cookies() {
    foreach ($_COOKIE as $name => $value) {
        if (
            $name === USER_SOLUTION_HASH_COOKIE_NAME ||
            strpos($name, USER_SOLUTION_CLICK_CHAIN_COOKIE_PREFIX) === 0
        ) {
            setcookie($name, '', [
                'expires'  => time() - 3600,
                'path'     => '/',
                'domain'   => '',
                'secure'   => is_ssl(),
                'httponly' => false,
                'samesite' => 'Lax',
            ]);
            unset($_COOKIE[$name]);
        }
    }
}

/*
    helper to remove cookies that are relevant only to check
    that the users submission is correct. After that part of the flow
    we need to get rid of them to avoid confusion
*/
function wpsec_clear_challenge_cookies() {
    wpsec_log('[gatekeeper] clearing challenge cookies');

    foreach ($_COOKIE as $name => $value) {
        if (
            $name === USER_SOLUTION_HASH_COOKIE_NAME ||
            $name === USER_CAPTCHA_CHALLENGE_COOKIE_NAME ||
            strpos($name, USER_SOLUTION_CLICK_CHAIN_COOKIE_PREFIX) === 0
        ) {
            wpsec_log('[gatekeeper] clearing cookie ' . $name);

            setcookie($name, '', [
                'expires'  => time() - 3600,
                'path'     => '/',
                'domain'   => '',
                'secure'   => is_ssl(),
                'httponly' => false,
                'samesite' => 'Lax',
            ]);

            unset($_COOKIE[$name]);
        }
    }
}

/*
    helper to clear specific cookies.
    if the user previously passed a challenge and was provided
    a challenge passed token, that token will eventually expire
    (or if its replayed, forged, tampered with, we may invalidate it
    server side, etc..) ultimately we can have many reasons for why 
    we would need to remove this cookie.
*/
function wpsec_clear_pass_token_cookie() {
    wpsec_log('[gatekeeper] clearing pass token cookie');

    if (isset($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME])) {
        setcookie(CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        unset($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME]);
    }
}

/*
    since we communicate with the puzzle via headers, action are 
    checked via this helper function. 

    this helper also serves as an extension point actions the 
    puzzle wants to be able to take can. To extend you would need
    to update the client side, fetching from this function and making
    the call as needed to the appripriate server side endpoint

    right now since we need only support refresh, this is the headrer
    thats added anytime we need to refresh and we check it in the request path
    its presence tells us that the user isnt submitting a solution or anything but rather
    wishes to request a refreshed puzzle state
*/
function wpsec_get_requested_action() {
    $header = $_SERVER['HTTP_X_ACTION'] ?? '';
    return is_string($header) ? strtolower(trim($header)) : '';
}

/*
    The way the captcha works is that we do NOT expose our own paths
    since this could interfere with the users endpoints. So, since the captcha
    is may be injected on any given path, we rely on GET requests on that path
    without refreshing the page to submit the users solution to the puzzle. In
    particular we communicate solutions through cookies. 
    
    So we need to check for the existence of the solution cookies 
    to determine that this was a request that submitted a solution
*/
function wpsec_has_verification_cookies() {
    $has_solution = !empty($_COOKIE[USER_SOLUTION_HASH_COOKIE_NAME]);
    $has_cc = false;

    foreach ($_COOKIE as $name => $value) {
        if (strpos($name, USER_SOLUTION_CLICK_CHAIN_COOKIE_PREFIX) === 0) {
            $has_cc = true;
            break;
        }
    }

    wpsec_log('[gatekeeper] verification cookies present? sol=' . ($has_solution ? 'yes' : 'no') . ' cc=' . ($has_cc ? 'yes' : 'no'));

    return $has_solution && $has_cc;
}

/*
    The way the captcha works is that we do NOT expose our own paths
    since this could interfere with the users endpoints. So, since the captcha
    is may be injected on any given path, we rely on GET requests on that path
    without refreshing the page to submit the users solution to the puzzle. In
    particular we communicate solutions through cookies.

    So here we check to see that the cookie we return when the previously submitted
    a correct solution proving they completed the challenge, is present
*/
function wpsec_captcha_pass_token_cookie_is_present() {
     
    wpsec_log('[gatekeeper] starting pass token cookie verification flow');

    $pass_cookie = $_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME] ?? '';

    if ($pass_cookie === '') {
        wpsec_log('[gatekeeper] no pass token cookie present');
        return false;
    }

    wpsec_log('[gatekeeper] pass token cookie present');
    return true;
}




//--------------------------------------------------
//--------------------------------------------------
//request helpers
//--------------------------------------------------
//--------------------------------------------------

/*
    helper used to forward cookies we need upstream since the wordpress origin
    sits between the requester and our verification server
*/
function wpsec_forward_upstream_cookies($response) {
    $cookies = wp_remote_retrieve_cookies($response);

    wpsec_log('[gatekeeper] upstream cookie count=' . count($cookies));

    foreach ($cookies as $cookie) {
        if (!is_object($cookie)) {
            wpsec_log('[gatekeeper] skipping non-object upstream cookie');
            continue;
        }

        $name     = $cookie->name ?? '';
        $value    = $cookie->value ?? '';
        $path     = $cookie->path ?? '/';
        $secure   = isset($cookie->secure) ? (bool) $cookie->secure : is_ssl();
        $httponly = isset($cookie->httponly) ? (bool) $cookie->httponly : false;
        $expires  = isset($cookie->expires) ? (int) $cookie->expires : 0;

        if ($name === '') {
            wpsec_log('[gatekeeper] skipping upstream cookie with empty name');
            continue;
        }

        wpsec_log('[gatekeeper] forwarding upstream cookie ' . $name);

        setcookie($name, $value, [
            'expires'  => $expires,
            'path'     => $path ?: '/',
            'domain'   => '',
            'secure'   => $secure,
            'httponly' => $httponly,
            'samesite' => 'Lax',
        ]);

        $_COOKIE[$name] = $value;
    }
}

/*
    The server side was original designed with us as a reverse proxy in mind. So
    since we fronted the user and did not want to add our own endpoints, all interactions
    with the captcha involving the server side happen via cookies.
    
    So here, we build the headers needed to verify the that the solution cookie 
    that we found is legitamate (not tampered with or being replayed). 
    sent along with request to /token/verify endpoint
*/
function wpsec_build_cookie_header_for_token_verification() {
    $pairs = [];

    /*
        NOTE: currently the only relevant cookie is the solution pass since IP address is collected
        at the level of the request itself, however if we want to extend beyond only IP address
        enforcement, this is where we would also need to collect the name of the cookie we use
        to follow the requester
    */

    if (isset($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME])) {
        $pairs[] = CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME . '=' . $_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME];
    }

    $cookie_header = implode('; ', $pairs);
    return $cookie_header;
}

/*
    The server side was original designed with us as a reverse proxy in mind. So
    since we fronted the user and did not want to add our own endpoints, all interactions
    with the captcha involving the server side happen via cookies.
    
    So here we build the headers needed to verify the solution to the captcha itself 
    ie this include the __wpsec_sol_hash_, original __wpsec_challenge_ and all __wpsec_cc__x_x cookies
    sent along with request to /captcha/verify endpoint
*/

function wpsec_build_cookie_header_for_captcha_challenge_verification() {
    $pairs = [];

    if (isset($_COOKIE[USER_SOLUTION_HASH_COOKIE_NAME])) {
        $pairs[] = USER_SOLUTION_HASH_COOKIE_NAME . '=' . $_COOKIE[USER_SOLUTION_HASH_COOKIE_NAME];
    }

    wpsec_log('raw solution cookie from $_COOKIE=' . ($_COOKIE[USER_SOLUTION_HASH_COOKIE_NAME] ?? 'missing'));

    if (isset($_COOKIE[USER_CAPTCHA_CHALLENGE_COOKIE_NAME])) {
        $pairs[] = USER_CAPTCHA_CHALLENGE_COOKIE_NAME . '=' . $_COOKIE[USER_CAPTCHA_CHALLENGE_COOKIE_NAME];
    }
    wpsec_log('raw challenge cookie from $_COOKIE=' . ($_COOKIE[USER_CAPTCHA_CHALLENGE_COOKIE_NAME] ?? 'missing'));

    foreach ($_COOKIE as $name => $value) {
        if (strpos($name, USER_SOLUTION_CLICK_CHAIN_COOKIE_PREFIX) === 0) {
            $pairs[] = $name . '=' . $value;
            wpsec_log('wpsec click chain cookie from $_COOKIE ' . $name . '=' . $value);
        }
    }

    $cookie_header = implode('; ', $pairs);
    wpsec_log('verification Cookie header=' . $cookie_header);

    return $cookie_header;
}



//--------------------------------------------------
//--------------------------------------------------
//requests
//--------------------------------------------------
//--------------------------------------------------

/*
    When a user gets the captcha, they will solve the puzzle and click
    verify. On verify, that sends a GET to the endpoint they happen to be
    on but includes in the headers some cookies (namely the solution hash and
    click chain cookies). We need to relay those from the wordpress origin
    to the server to verify that this is indeed correct.

    issues request to the /captcha/verify endpoint
*/
function wpsec_verify_captcha_solution_via_upstream_cookies() {
    wpsec_log('[gatekeeper] starting verification flow');

    // Per-IP rate limit: protect upstream /captcha/verify from brute-force.
    // Fail with 429 — the caller already handles and relays this status.
    $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    if (
        $ip !== '' &&
        isset( $GLOBALS['baskerville_challenge'] ) &&
        $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper &&
        $GLOBALS['baskerville_challenge']->upstream_rate_limited( $ip, 'verify' )
    ) {
        wpsec_log( '[gatekeeper] upstream verify rate limit exceeded, returning 429' );
        return [ 'status_code' => 429, 'message' => 'rate limited', 'error' => 'rate_limited', 'retry_after' => 60 ];
    }

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    $cookie_header = wpsec_build_cookie_header_for_captcha_challenge_verification();

    wpsec_log('[gatekeeper] forwarding verification cookie header=' . $cookie_header);

    $response = wp_remote_get(CAPTCHA_SOLUTION_VERIFICATION_ENDPOINT, [
        'timeout'     => 10,
        'redirection' => 3,
        'headers'     => [
            'Cookie'              => $cookie_header,
            'Accept'              => 'application/json, text/plain, */*',
            'X-Client-IP'         => $_SERVER['REMOTE_ADDR'] ?? '',
            'X-Original-Host'     => $_SERVER['HTTP_HOST'] ?? '',
            'X-Original-URI'      => $_SERVER['REQUEST_URI'] ?? '',
            'X-Original-URL'      => $original_url,
            'X-Client-User-Agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
            'User-Agent'          => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
        ],
    ]);

    if (is_wp_error($response)) {
        wpsec_log('[gatekeeper] verification request failed: ' . $response->get_error_message());
        error_log('[Baskerville GK] verify upstream FAILED: ' . $response->get_error_message() . ' | IP=' . ($_SERVER['REMOTE_ADDR'] ?? ''));

        return [
            'message'       => $response->get_error_message(),
            'status_code'   => 0,
            'retry_after'   => '',
            'error'         => 'upstream_error',
        ];
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body        = (string) wp_remote_retrieve_body($response);
    $retry_after = (string) wp_remote_retrieve_header($response, 'retry-after');

    wpsec_log('[gatekeeper] verification status=' . $status_code);
    wpsec_log('[gatekeeper] verification retry-after=' . $retry_after);
    wpsec_log('[gatekeeper] verification body=' . substr($body, 0, 300));

    wpsec_forward_upstream_cookies($response);

    $json = json_decode($body, true);

    if (is_array($json)) {
        return [
            'message'       => (string) ($json['message'] ?? ''),
            'status_code'   => $status_code,
            'retry_after'   => $retry_after,
            'error'         => (string) ($json['error'] ?? ''),
        ];
    }

    //if the status is 403 && message is "invalid solution", they failed the challenge
    //if its 400, then its just an error with the submitted payload itself

    //when its 400, we will follow the flow of re-issueing a new challenge, ie nothing changes BUT
    //when its 403 && message is "invalid solution" we need to relay that back to the user so our response
    //becomes different. In other words, here, rather than just returning a bool, we ought to return the 
    //message and status

    return [
        'message'       => trim(wp_strip_all_tags($body)),
        'status_code'   => $status_code,
        'retry_after'   => $retry_after,
        'error'         => '',
    ];
}


/*
    After the user submitted their solution and it was relayed to the server
    if that solution was correct, the server would have responded back with a 
    challenge_passed cookie. This challenge passed cookie contains everything we
    need in order to be able to cryptographically prove that this unique puzzle
    was issued to them and that it was indeed solved (ie proof of work). This cookie
    is attached to every subsequent request the requester makes such that we can
    contact the server side to confirm that this is valid for example that its
    still within the time limit we assigned (not expired), not replayed, not forged,
    not copied etc

    issues request to the /token/verify endpoint
*/
function wpsec_verify_captcha_pass_token_cookie_is_valid() {
    // Per-IP rate limit: protect upstream /token/verify.
    // Fail open (return 200) so a rate-limited visitor is not permanently blocked.
    $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    if (
        $ip !== '' &&
        isset( $GLOBALS['baskerville_challenge'] ) &&
        $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper &&
        $GLOBALS['baskerville_challenge']->upstream_rate_limited( $ip, 'token' )
    ) {
        wpsec_log( '[gatekeeper] upstream token-verify rate limit exceeded, failing open' );
        return [ 'status_code' => 200, 'message' => 'rate limited, failing open' ];
    }

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    $cookie_header = wpsec_build_cookie_header_for_token_verification();

    wpsec_log('[gatekeeper] forwarding token verification cookie header=' . $cookie_header);

    $response = wp_remote_get(CAPTCHA_PREVIOUSLY_PASSED_TOKEN_VERIFICATION_ENDPOINT, [
        'timeout'     => 10,
        'redirection' => 3,
        'headers'     => [
            'Cookie'              => $cookie_header,
            'Accept'              => '*/*',
            'X-Client-IP'         => $_SERVER['REMOTE_ADDR'] ?? '',
            'X-Original-Host'     => $_SERVER['HTTP_HOST'] ?? '',
            'X-Original-URI'      => $_SERVER['REQUEST_URI'] ?? '',
            'X-Original-URL'      => $original_url,
            'X-Client-User-Agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
            'User-Agent'          => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
        ],
    ]);

    if (is_wp_error($response)) {
        wpsec_log('[gatekeeper] verification request failed: ' . $response->get_error_message());
        return [
            'message'       => $response->get_error_message(),
            'status_code'   => 0,
        ];
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body        = (string) wp_remote_retrieve_body($response);

    wpsec_log('[gatekeeper] verification status=' . $status_code);

    return [
        'message'       => trim(wp_strip_all_tags($body)),
        'status_code'   => $status_code,
    ];
}


/*
    anytime we wish to issue a challenge to the user, we need to gather
    their fingerprint and contact the /captcha/generate endpoint in order
    to be able to generate a captcha that is unique to them. We would take
    whatever the captcha generation server sends, and push that to the requester
    who is requesting something from the wp origin server
*/
function wpsec_issue_challenge() {
    wpsec_log('[gatekeeper] starting challenge issuance flow');

    // Per-IP rate limit: protect upstream /captcha/generate from flood.
    // Fail OPEN on limit exceeded — let the visitor through rather than blocking
    // a potentially legitimate user whose IP hit the ceiling (e.g. shared NAT).
    $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    if (
        $ip !== '' &&
        isset( $GLOBALS['baskerville_challenge'] ) &&
        $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper &&
        $GLOBALS['baskerville_challenge']->upstream_rate_limited( $ip, 'generate' )
    ) {
        wpsec_log( '[gatekeeper] upstream generate rate limit exceeded, failing open' );
        return; // let WordPress render the real page
    }

    wpsec_log('[gatekeeper] issuing challenge for uri=' . ($_SERVER['REQUEST_URI'] ?? ''));

    // Record gk_redir stat for the analytics precision chart.
    if (isset($GLOBALS['baskerville_challenge']) && $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper) {
        $GLOBALS['baskerville_challenge']->log_challenge_event('redir', '', $ip);
    }

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    wpsec_log('[gatekeeper] original URL=' . $original_url);

    $response = wp_remote_get(CAPTCHA_GENERATION_ENDPOINT, [
        'timeout'     => 10,
        'redirection' => 3,
        'headers'     => [
            'Accept'          => 'text/html',
            'X-Original-Host' => $_SERVER['HTTP_HOST'] ?? '',
            'X-Original-URI'  => $_SERVER['REQUEST_URI'] ?? '',
            'X-Original-URL'  => $original_url,
            'X-Client-IP'     => $_SERVER['REMOTE_ADDR'] ?? '',
            'User-Agent'      => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
        ],
    ]);

    if (is_wp_error($response)) {
        wpsec_log('[gatekeeper] challenge fetch failed: ' . $response->get_error_message() . ' — failing open');
        // Upstream unreachable — let the visitor through rather than blocking them with a broken page.
        wpsec_clear_challenge_cookies();
        return;
    }

    $status_code  = wp_remote_retrieve_response_code($response);
    $content_type = wp_remote_retrieve_header($response, 'content-type') ?: 'text/html; charset=utf-8';
    $body         = wp_remote_retrieve_body($response);

    wpsec_log('[gatekeeper] challenge fetch succeeded, status=' . $status_code);
    wpsec_log('[gatekeeper] challenge content-type=' . $content_type);
    wpsec_log('[gatekeeper] challenge body length=' . strlen($body));

    wpsec_forward_upstream_cookies($response);

    // Prevent any page-cache plugin from storing the challenge HTML.
    // WP Super Cache (both PHP and Expert/mod_rewrite modes), W3TC, WP Rocket etc.
    // all check DONOTCACHEPAGE before writing to their cache stores.
    if (!defined('DONOTCACHEPAGE')) {
        define('DONOTCACHEPAGE', true);
    }
    // Some plugins also check the global (W3TC, LiteSpeed Cache).
    $GLOBALS['DONOTCACHEPAGE'] = 1;

    nocache_headers(); // Sets Cache-Control, Pragma, Expires (browser).
    // Explicitly tell CDN/reverse-proxy layers not to store this response.
    // nocache_headers() covers the browser; these cover Varnish, Nginx, CDNs.
    header('Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    header('Surrogate-Control: no-store');   // Varnish / Fastly
    header('CDN-Cache-Control: no-store');   // Cloudflare and others
    header('Vary: Cookie');                  // treat each cookie variation as different cache key
    status_header(200);
    header('Content-Type: ' . $content_type);
    echo $body;
    exit;
}

/*
    during the puzzle, if the user clicks on the puzzle refresh button 
    the wordpress origin will relay a call to the captcha service server
    requesting a change of puzzle state via the /captcha/refresh endpoint. 
    The wp origin need only relay the new state to the user. 
*/
function wpsec_refresh_challenge_state() {
    wpsec_log('[gatekeeper] starting challenge refresh flow');

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    $response = wp_remote_get(CAPTCHA_REFRESH_ENDPOINT, [
        'timeout'     => 10,
        'redirection' => 3,
        'headers'     => [
            'Accept'          => 'application/json',
            'X-Original-Host' => $_SERVER['HTTP_HOST'] ?? '',
            'X-Original-URI'  => $_SERVER['REQUEST_URI'] ?? '',
            'X-Original-URL'  => $original_url,
            'X-Client-IP'     => $_SERVER['REMOTE_ADDR'] ?? '',
            'User-Agent'      => $_SERVER['HTTP_USER_AGENT'] ?? 'WordPress Gatekeeper',
        ],
    ]);

    if (is_wp_error($response)) {
        wpsec_log('[gatekeeper] challenge refresh failed: ' . $response->get_error_message());
        status_header(503);
        header('Content-Type: application/json; charset=utf-8');
        echo wp_json_encode([
            'error' => 'refresh_failed',
            'message' => 'Unable to refresh puzzle.',
        ]);
        exit;
    }

    $status_code  = (int) wp_remote_retrieve_response_code($response);
    $content_type = wp_remote_retrieve_header($response, 'content-type') ?: 'application/json; charset=utf-8';
    $body         = wp_remote_retrieve_body($response);

    wpsec_log('[gatekeeper] challenge refresh succeeded, status=' . $status_code);
    wpsec_log('[gatekeeper] challenge refresh body length=' . strlen($body));

    wpsec_forward_upstream_cookies($response);

    status_header($status_code ?: 200);
    header('Content-Type: ' . $content_type);
    header('Cache-Control: no-store, no-cache');
    echo $body;
    exit;
}




/**
 * Enforces the full CAPTCHA / challenge policy for every frontend request handled by WordPress.
 *
 * High-level purpose
 * ------------------
 * This function is the main gatekeeper for the CAPTCHA flow. It is attached to
 * WordPress' `template_redirect` hook, which means it runs on normal frontend
 * page requests before WordPress renders the theme/template.
 *
 * In practice, almost every ordinary browser request to the site will pass through
 * this function first. Its job is to decide which of the following should happen:
 *
 *  1. Allow the request through untouched.
 *  2. Verify an existing "passed CAPTCHA" token and allow the request if valid.
 *  3. Refresh the currently displayed CAPTCHA puzzle state.
 *  4. Verify a submitted CAPTCHA solution.
 *  5. Relay rate-limit or verification errors back to the challenge page.
 *  6. Issue a brand new challenge.
 *
 * This function is therefore the main request router for all CAPTCHA-related
 * behavior at the WordPress origin.
 *
 *
 * Core idea
 * ---------
 * The origin server is acting as the policy enforcement point.
 *
 * The browser never talks directly to the CAPTCHA service in the normal flow.
 * Instead:
 *
 *  - The browser sends requests to the WordPress origin.
 *  - This function inspects the request and the cookies the requester sent.
 *  - Depending on the state of the requester, the origin either:
 *      - lets the request continue normally,
 *      - calls an upstream CAPTCHA endpoint,
 *      - relays an upstream verification result,
 *      - or serves/refreshes the challenge.
 *
 * Request categories handled here
 * -------------------------------
 * This function evaluates requests in the following broad categories:
 *
 *  A. Requests that should never be challenged
 *     These are allowed immediately because challenging them would break WordPress
 *     behavior or cause unwanted side effects.
 *
 *  B. Requests from users who already carry a CAPTCHA pass token
 *     These requests are introspected against the upstream token verification
 *     endpoint. If the token is valid, the request is allowed.
 *
 *  C. Requests from users who should not currently be challenged
 *     The request is allowed and WordPress continues normal rendering.
 *
 *  D. Requests asking to refresh the puzzle state
 *     The existing challenge cookies are cleared and the origin fetches a fresh
 *     challenge state from the upstream refresh endpoint.
 *
 *  E. Requests that contain a CAPTCHA solution submission
 *     The origin forwards the submitted cookies to the upstream `/captcha/verify`
 *     endpoint and relays the result back to the browser.
 *
 *  F. Requests from users who are still challenged but have not submitted a valid
 *     solution yet
 *     The origin issues a fresh challenge page.
 *
 *
 * Detailed control flow
 * ---------------------
 *
 * Step 1: Log the incoming request
 * --------------------------------
 * The function begins by logging that the gatekeeper fired, along with the request
 * URI and request method. This is purely for observability and debugging.
 *
 *
 * Step 2: Early allowlist / bypass checks
 * ---------------------------------------
 * The function immediately allows certain request types through because challenging
 * them would either break WordPress or create inconsistent CAPTCHA state.
 *
 * The following are allowed immediately:
 *
 *  - WordPress admin requests (`is_admin()`)
 *  - WordPress REST API requests (`REST_REQUEST`)
 *  - WordPress AJAX requests (`wp_doing_ajax()`)
 *  - Logged-in privileged/admin users (`current_user_can('manage_options')`)
 *  - Asset-like requests such as CSS, JS, images, fonts, etc.
 *  - Favicon requests
 *
 *
 * Step 3: Check for an existing "passed CAPTCHA" token
 * ----------------------------------------------------
 * If the requester carries the pass-token cookie, this function treats that as:
 * "This requester claims they already solved a CAPTCHA previously."
 *
 * However, presence alone is not trusted.
 * The function therefore calls the upstream token introspection endpoint via:
 * wpsec_verify_captcha_pass_token_cookie_is_valid()
 *
 * That endpoint validates the token against requester properties such as IP and any
 * other properties baked into the token.
 *
 * Outcomes:
 *
 *  - If the upstream returns 204:
 *      The token is valid and the request is allowed immediately.
 *
 *  - Otherwise:
 *      The token is treated as invalid, expired, replayed, malformed, or otherwise
 *      untrustworthy. The local token cookie is cleared, and execution continues.
 *      The request will then fall through to the normal challenge decision logic.
 *
 * Important note:
 *
 * This means that every subsequent request carrying the pass token is actively
 * re-validated. The token is not trusted merely because it exists.
 *
 *
 * Step 4: Decide whether this requester should be challenged at all
 * -----------------------------------------------------------------
 * The function calls:
 * wpsec_should_challenge()
 *
 * This is the policy decision point. It answers:
 * "Does this requester currently belong to a class of users we want to challenge?"
 * If the answer is no, the request is allowed through and WordPress renders normally.
 * If the answer is yes, the function continues into the challenge-handling paths.
 *
 *
 * Step 5: Check whether the request is asking to refresh the puzzle state
 * -----------------------------------------------------------------------
 * The challenge UI can ask for a new puzzle state without performing a full page
 * navigation. That intent is communicated via a request header and extracted by:
 * wpsec_get_requested_action()
 *
 * If the requested action is `refresh`:
 *  - Existing challenge cookies are cleared.
 *  - A fresh puzzle state is fetched from the upstream refresh endpoint.
 *  - The new state is returned to the client as JSON.
 *
 * This path is specifically for refreshing the currently displayed CAPTCHA without
 * serving the entire full challenge page again.
 *
 *
 * Step 6: Check whether the request contains a CAPTCHA solution submission
 * ------------------------------------------------------------------------
 * If the request includes the expected CAPTCHA submission cookies, the function
 * treats it as an attempt to solve the currently active challenge.
 *
 * It then calls:
 * wpsec_verify_captcha_solution_via_upstream_cookies()
 *
 * That helper forwards the relevant cookies to the upstream `/captcha/verify`
 * endpoint. The upstream service verifies:
 *
 *  - the original challenge cookie,
 *  - the solution hash,
 *  - the click-chain cookies,
 *  - and any replay / integrity / timing / rate-limiting checks.
 *
 * The origin then examines the upstream response and branches as follows:
 *
 *  a) 403 + "invalid solution"
 *     The user solved the puzzle incorrectly.
 *     The origin relays a plain 403 back to the browser so the client-side CAPTCHA
 *     UI can show the appropriate message.
 *
 *  b) 429
 *     The requester is being rate limited.
 *     The origin relays:
 *       - HTTP 429
 *       - Retry-After header if provided
 *       - a JSON body containing machine-readable and human-readable fields
 *     The client-side UI can then show the rate-limit message and countdown.
 *
 *  c) 400
 *     The submission payload itself was malformed or incomplete.
 *     The origin clears challenge cookies and sends back a 404-ish refresh signal
 *     (`refresh challenge`) so the client can request a fresh puzzle state.
 *
 *  d) 200
 *     The CAPTCHA solution was correct.
 *     The upstream service has already set the pass-token cookie in its response,
 *     and that cookie has already been forwarded back to the browser by the origin.
 *     The origin then clears the temporary challenge/solution cookies and allows
 *     the request through.
 *
 *  e) Any other status
 *     The result is treated as unexpected. The origin clears challenge cookies and
 *     falls back to issuing a new challenge.
 *
 *
 * Error handling
 * --------------
 * The entire function is wrapped in a try/catch.
 * If an exception is thrown during policy enforcement, the error is logged.
 * This is intended to prevent silent failures during enforcement and make
 * troubleshooting easier.
 *
 *
 * Important invariants / design assumptions
 * -----------------------------------------
 * 1. This function is the single entry point for CAPTCHA enforcement on ordinary
 *    frontend requests.
 *
 * 2. The pass-token cookie is never trusted by presence alone. It must always be
 *    introspected via the upstream token verification endpoint.
 *
 * 3. Challenge issuance and challenge verification are both mediated by the
 *    WordPress origin, not by direct browser-to-CAPTCHA-service traffic.
 *
 * 4. Asset-like and favicon requests are intentionally bypassed to prevent a
 *    second challenge from being issued after the original challenge page has
 *    already embedded its own puzzle state.
 *
 * 5. A successful CAPTCHA verification results in:
 *      - the pass-token cookie being forwarded to the browser,
 *      - challenge/solution cookies being cleared,
 *      - and the original request being allowed to continue.
 *
 *
 * Summary of possible outcomes
 * ----------------------------
 * Every frontend request entering this function ends in one of these outcomes:
 *
 *  - Allowed immediately due to admin/API/asset bypass
 *  - Allowed because the pass token introspected successfully
 *  - Allowed because policy says requester should not be challenged
 *  - Handled as a refresh request and given fresh puzzle state JSON
 *  - Handled as a CAPTCHA verification attempt and given a verification result
 *  - Given a brand new challenge page
 *
 * tldr
 *
 * This function is the authoritative decision engine for whether the requester
 * sees the real page, sees a challenge, refreshes a challenge, verifies a
 * challenge, or is blocked/rate-limited during challenge verification.
 */
function wpsec_enforce_captcha_policy() {
    try {

        wpsec_log('[gatekeeper] template_redirect fired');
        wpsec_log('[gatekeeper] request uri=' . ($_SERVER['REQUEST_URI'] ?? ''));
        wpsec_log('[gatekeeper] request method=' . ($_SERVER['REQUEST_METHOD'] ?? ''));

        // Unconditional diagnostic — remove after bug is confirmed fixed.
        $diag_cookies = [];
        foreach ($_COOKIE as $n => $v) {
            if (strpos($n, '__wpsec_') === 0 || strpos($n, 'baskerville') === 0) {
                $diag_cookies[] = $n;
            }
        }
        error_log('[Baskerville GK] POLICY fired uri=' . ($_SERVER['REQUEST_URI'] ?? '') . ' challenge_global=' . (!empty($GLOBALS['baskerville_gatekeeper_challenge']) ? 'SET' : 'unset') . ' relevant_cookies=' . implode(',', $diag_cookies));

        // maybe_activate_test_mode() (priority 0) may have set this before us (priority 1)
        $is_test_mode = !empty($GLOBALS['baskerville_gatekeeper_test_mode']);

        // Respect master switch — if protection is off, clear any stale challenge cookies and allow
        $bsk_options = get_option('baskerville_settings', array());
        $master_enabled = !isset($bsk_options['master_protection_enabled']) || $bsk_options['master_protection_enabled'];
        if (!$master_enabled && !$is_test_mode) {
            wpsec_log('[gatekeeper] master switch OFF, clearing stale cookies and allowing');
            wpsec_clear_challenge_cookies();
            wpsec_clear_pass_token_cookie();
            return;
        }

        // Also bail immediately if the provider is no longer 'gatekeeper' (settings changed mid-session)
        $provider = isset($bsk_options['captcha_provider']) ? $bsk_options['captcha_provider'] : 'none';
        if ($provider !== 'gatekeeper' && !$is_test_mode) {
            wpsec_log('[gatekeeper] provider changed, clearing stale cookies and allowing');
            wpsec_clear_challenge_cookies();
            wpsec_clear_pass_token_cookie();
            return;
        }

        /*
            we start by checking you're not admin, hitting the admin page or anything
            relevant for wordpress correct functionality
        */
        if (is_admin()) {
            wpsec_log('[gatekeeper] admin request, allowing');
            return;
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            wpsec_log('[gatekeeper] REST request, allowing');
            return;
        }

        if (wp_doing_ajax()) {
            wpsec_log('[gatekeeper] AJAX request, allowing');
            return;
        }

        if (is_user_logged_in() && current_user_can('manage_options')) {
            if (!$is_test_mode) {
                wpsec_log('[gatekeeper] privileged logged-in user, allowing');
                return;
            }
            wpsec_log('[gatekeeper] admin test mode active, proceeding with challenge flow');
        }
    
        /*
            at this point we need to 
            make sure not a follow up secondary favicon request or something that could
            trigger us sending additional state bringing the state embedded in the 
            puzzle itself out of sync with the headers/cookies & clickchain genesis hash
        */
        if (wpsec_is_asset_like_request()) {
            wpsec_log('[gatekeeper] asset-like request, allowing');
            return;
        }
    
        if (($_SERVER['REQUEST_URI'] ?? '') === '/favicon.ico') {
            wpsec_log('[gatekeeper] favicon request, allowing');
            return;
        }
    
        /*
            at this point we can continue with regular flow challenge flow
            since this is a normal user, so we need to check if they're being challenged
            or have submitted a solution or have already passed etc
        */
    
        // Fast path: check our own local HMAC pass cookie.
        // This is set by set_local_pass() after successful upstream verification.
        // If valid, skip the upstream /token/verify round-trip entirely.
        if (isset($GLOBALS['baskerville_challenge']) && $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper) {
            $has_local = $GLOBALS['baskerville_challenge']->validate_local_pass();
            error_log('[Baskerville GK] local pass check: ' . ($has_local ? 'VALID' : 'absent') . ' cookie=' . (isset($_COOKIE[Baskerville_Gatekeeper::GK_PASS_COOKIE]) ? 'present' : 'missing'));
            if ($has_local) {
                wpsec_log('[gatekeeper] local pass cookie valid, allowing');
                return;
            }
        }

        //we check to see if the captcha challenge has previously been passed
        //by looking for the challenge passed cookie. If so, we go through validating it
        //to make sure its not forged, expired, replayed etc. If not we continue
        //to check whether this current requester ought to be challenged
        if (wpsec_captcha_pass_token_cookie_is_present()) {

            $token_validation_result = wpsec_verify_captcha_pass_token_cookie_is_valid();

            $message = $token_validation_result['message'] ?? '';
            $status_code = (int) ($token_validation_result['status_code'] ?? 0);

            wpsec_log('[gatekeeper] token verify status=' . $status_code . ' message=' . $message);

            // Accept both 200 and 204 — the endpoint may return either depending on server version.
            if ($status_code === 204 || $status_code === 200) {
                wpsec_log('[gatekeeper] valid pass cookie found, allowing');
                return;

            } else {
    
                //either the token is a fake, or replayed from someone else or 
                //it expired. It doesnt matter, their solution cookie is no longer valid
                //consequently, they arent allowed through anymore. NOTE: what this actually
                //means is that we need to check again if action is required (ie should_challenge())
                //will do its thing. if they are on that list, then they should get challenged again
                //otherwise its ok. That being said we need to remove that cookie from them
                wpsec_clear_pass_token_cookie();
    
                if ($status_code === 400) {
                    //most likely a 400, bad formatting, missing properties etc
    
                } else if ($status_code === 500) {
                    //something went wrong at the level of the captcha server
    
                } else if ($status_code === 403 && $message === 'token invalid') {
                    //detected tampering, do you as see fit here (ban, temporary block, rate limit etc)
    
                } else if ($status_code === 403 && $message === 'token tampering') {
                    //IP or other attribute doesnt line up with requester properties, could be replay etc
                    //do as you see fit (ban, temporary block, rate limit etc)
    
                }  else if ($status_code === 403 && $message === 'token expired') {
                    //token expired, so decide what to do here. Most likely just fall through to
                    //checking if wpsec_should_challenge()
    
                } else {
                    //catchall, log since this is an unexpected error code
                    //TODO: list out all properties and stuff useful for logging
                    //then fallthrough to wpsec_should_challenge check
                    wpsec_log('[gatekeeper] unexpected error occured!'); 
                }
            }
        }
    
        // Handle puzzle refresh (X-Action: refresh header sent by the challenge JS).
        // Must run BEFORE the should_challenge() gate because the JS's fetch() uses
        // Accept:*/* which causes the firewall to bail at is_public_html_request()
        // and leave baskerville_gatekeeper_challenge unset.
        $requested_action = wpsec_get_requested_action();
        wpsec_log('[gatekeeper] requested action=' . $requested_action);
        if ($requested_action === 'refresh') {
            wpsec_log('[gatekeeper] refresh action detected');
            wpsec_clear_challenge_cookies();
            wpsec_refresh_challenge_state();
        }

        // Process solution submission BEFORE the should_challenge() gate.
        //
        // Root cause: the firewall (plugins_loaded) contains an early-return guard
        // `if (!is_public_html_request()) return;` that fires on the challenge JS's
        // fetch() call because fetch() sends Accept:*/* rather than text/html.
        // This leaves baskerville_gatekeeper_challenge unset, making
        // wpsec_should_challenge() return false even while solution cookies are in
        // the request — so the user would be silently allowed through without any
        // verification taking place.
        //
        // Fix: check for solution cookies here, unconditionally. If the visitor has
        // submitted a solution it must always be verified, regardless of whether the
        // firewall challenge-flag was set.
        if (wpsec_has_verification_cookies()) {
            $verification_result = wpsec_verify_captcha_solution_via_upstream_cookies();
            $message = $verification_result['message'] ?? '';
            $status_code = (int) ($verification_result['status_code'] ?? 0);

            // Unconditional log — visible in error_log regardless of WP_DEBUG.
            // Remove after the verification loop is fixed.
            error_log('[Baskerville GK] verify upstream status=' . $status_code . ' message=' . substr($message, 0, 80));

            wpsec_log('[gatekeeper] verification result status=' . $status_code . ' message=' . $message);
    
            if ($status_code === 403 && $message === 'invalid solution') {
                // Wrong solution. Clear all challenge/solution cookies and serve a
                // fresh challenge instead of sending a plain-text 403 "invalid solution"
                // response.
                //
                // Why not send wpsec_send_plain_response(403, …) here:
                //   When a CDN (e.g. eQpress) intercepts the verification fetch() and
                //   serves a cached 200 response, the browser never receives our 403 and
                //   the solution cookies are never cleared. On the next regular page
                //   navigation PHP sees stale solution cookies, re-runs verification,
                //   gets 403 again, and sends plain text "invalid solution" — the browser
                //   renders a blank white page with that text.
                //
                // By clearing cookies + re-issuing the challenge:
                //   - The challenge JS's fetch() gets 200 HTML → handleRedirect() → reload.
                //     On the reload the solution cookies are gone → fresh challenge is shown.
                //   - Any later regular navigation with stale cookies also ends up at a
                //     clean challenge page rather than a blank error page.
                //   - Security is unaffected: the user must still solve the puzzle correctly.
                // Count this failure and ban the IP if the threshold is reached.
                $fail_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
                $just_banned = (
                    $fail_ip !== '' &&
                    isset($GLOBALS['baskerville_challenge']) &&
                    $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper &&
                    $GLOBALS['baskerville_challenge']->record_failed_attempt($fail_ip)
                );

                if ($just_banned) {
                    wpsec_log('[gatekeeper] IP banned after repeated challenge failures: ' . $fail_ip);
                    wpsec_clear_challenge_cookies();
                    wpsec_send_plain_response(403, 'Forbidden');
                    return;
                }

                wpsec_log('[gatekeeper] invalid solution — clearing cookies and re-issuing fresh challenge');
                wpsec_clear_challenge_cookies();
                wpsec_issue_challenge();
                return;
    
            } else if ($status_code === 429) {
                //relay back 429 + message (which would be "x seconds") and is handled by
                //client side to display that they are being rate limited
                wpsec_log('[gatekeeper] relaying rate limit back to client');
            
                if (!empty($verification_result['retry_after'])) {
                    header('Retry-After: ' . $verification_result['retry_after']);
                }
            
                header('Content-Type: application/json; charset=utf-8');
                status_header(429);
                echo wp_json_encode([
                    'error' => $verification_result['error'] ?: 'rate_limited',
                    'message' => $message !== '' ? $message : 'Too many requests.',
                    'retry_after_seconds' => is_numeric($verification_result['retry_after']) ? (int) $verification_result['retry_after'] : null,
                ]);
                exit;
    
            } else if ($status_code === 400) {
                // Upstream could not parse the solution cookies (bad format / tampering).
                // Send HTTP 400 back so the JS shows "Incorrect solution. Please try again"
                // (case 6 in the client state machine).
                //
                // IMPORTANT: do NOT send 404 here. The challenge JS treats 404 as a
                // success signal (case 5 → handleRedirect) which causes an infinite
                // reload loop when there is no pass cookie yet.
                //
                // Keep __wpsec_challenge_ so the user can retry the same puzzle;
                // only clear the per-attempt solution cookies.
                wpsec_log('[gatekeeper] bad verification payload (400), clearing solution cookies');
                wpsec_clear_solution_cookies();
                wpsec_send_plain_response(400, 'invalid solution');
    
            } else if ($status_code === 200 || $status_code === 204) {
                //their solution was correct, the wordpress origin will receive
                //a "challenge passed" solution cookie in the header. Here we need
                //to remove them from the list to challenge and subsequently we
                //need to delete all other cookies they might have AND attach this
                //new cookie that the captcha service server sends back to the wordpress
                //origin server
                wpsec_log('[gatekeeper] verification succeeded (status=' . $status_code . '), setting local pass and clearing challenge cookies');

                // Set our own HMAC-signed local pass cookie so the firewall will
                // recognise this visitor on the next request regardless of whether
                // the upstream also forwarded __wpsec_solved_.
                if (isset($GLOBALS['baskerville_challenge']) && $GLOBALS['baskerville_challenge'] instanceof Baskerville_Gatekeeper) {
                    $GLOBALS['baskerville_challenge']->set_local_pass();
                    $GLOBALS['baskerville_challenge']->log_challenge_event('pass');
                    wpsec_log('[gatekeeper] local pass cookie set (baskerville_gk_pass)');
                }

                // Clear leftover challenge/solution cookies.
                wpsec_clear_challenge_cookies();

                // Log whether __wpsec_solved_ was also forwarded by upstream (informational only).
                if (isset($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME])) {
                    wpsec_log('[gatekeeper] upstream pass cookie also forwarded');
                } else {
                    wpsec_log('[gatekeeper] note: upstream pass cookie absent; local pass handles access');
                }

                // If this was an admin test session, end it now
                if (!empty($GLOBALS['baskerville_gatekeeper_test_mode'])) {
                    $user_id = get_current_user_id();
                    if ($user_id) {
                        delete_user_meta($user_id, 'baskerville_gk_test');
                        wpsec_log('[gatekeeper] test mode ended for user ' . $user_id);
                    }
                }

                // Send a compact, explicitly non-cacheable 200 response and exit.
                //
                // Why NOT return here (letting WordPress render the full page):
                //   The challenge JS calls fetch() with credentials:"include". If we
                //   return, WordPress sends a full HTML page with Set-Cookie: baskerville_gk_pass.
                //   A CDN (e.g. eQpress/Deflect) may cache this response INCLUDING the
                //   Set-Cookie header. The next visitor whose verification fetch() is served
                //   from that cache would receive the previous user's pass cookie, store it,
                //   see HTTP 200, call handleRedirect() → reload → validate_local_pass() passes
                //   (HMAC not IP-bound) → visitor gets through WITHOUT solving the puzzle.
                //
                // By sending a tiny JSON body + no-store headers and exiting:
                //   - CDNs are explicitly told not to cache (no-store headers on a small response)
                //   - The JS only needs status 200 to call handleRedirect() → page reload
                //   - On the reload, baskerville_gk_pass is present in the browser cookie jar
                //     → has_valid_pass() = true → no challenge → user sees the real page
                //   - The Set-Cookie header is still sent (cookies are queued before exit)
                wpsec_log('[gatekeeper] sending no-store 200 ack — pass cookie in Set-Cookie, JS will reload');
                nocache_headers();
                header('Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
                header('Surrogate-Control: no-store');
                header('CDN-Cache-Control: no-store');
                header('Vary: Cookie');
                status_header(200);
                header('Content-Type: application/json; charset=utf-8');
                echo '{"ok":true}';
                exit;
    
            } else if ($status_code === 0) {
                // Upstream unreachable — fail open to prevent infinite loop.
                // Clear stale challenge cookies and let the visitor through.
                wpsec_log('[gatekeeper] upstream unreachable (status=0), clearing cookies and allowing');
                wpsec_clear_challenge_cookies();
                return;

            } else {
                // Unexpected status from /captcha/verify.
                // Do NOT call wpsec_issue_challenge() here — that sends HTTP 200, which
                // the challenge JS treats as success → handleRedirect → reload → no pass
                // cookie → challenge again → infinite loop.
                // Instead, send HTTP 500 so the JS shows "Incorrect solution. Please try again"
                // and lets the user retry without a reload loop.
                wpsec_log('[gatekeeper] unexpected verification result (status=' . $status_code . '), sending 500 to avoid reload loop');
                error_log('[Baskerville GK] unexpected /captcha/verify status=' . $status_code . ' message=' . substr($message, 0, 80));
                wpsec_clear_solution_cookies();
                wpsec_send_plain_response(500, 'verification error');
            }
        }
    

        // No solution cookies. Only issue a fresh challenge if the firewall flagged
        // this visitor (under_attack mode, borderline score, etc.). Visitors who are
        // not meant to be challenged should see the normal page.
        if (!wpsec_should_challenge()) {
            wpsec_log('[gatekeeper] should not challenge, allowing normal render');
            return;
        }

        wpsec_log('[gatekeeper] no valid verification cookies, issuing challenge');
        wpsec_issue_challenge();

        return;


    } catch (\Exception $e) { //try/catch exception
        wpsec_log('[gatekeeper] Unexpected exception: ' . $e->getMessage());
    } catch (\Error $e) { //fatal php error
        wpsec_log('[gatekeeper] Unexpected error: ' . $e->getMessage()); 
    }
}


/**
 * Baskerville Gatekeeper — challenge provider class.
 *
 * Implements the same firewall interface as Baskerville_Turnstile so that the
 * firewall can use either provider transparently via $GLOBALS['baskerville_challenge'].
 *
 * Key difference from Turnstile: redirect_to_challenge() does NOT perform an
 * HTTP redirect. It sets $GLOBALS['baskerville_gatekeeper_challenge'] = true and
 * returns, allowing wpsec_enforce_captcha_policy() on template_redirect to serve
 * the challenge inline at the original URL.
 */
class Baskerville_Gatekeeper {

    /** Local pass cookie set by WordPress after successful upstream verification. */
    const GK_PASS_COOKIE = 'baskerville_gk_pass';
    /** TTL for local pass in seconds (24 h). */
    const GK_PASS_TTL = 86400;

    /** Max wrong solutions before an IP is banned (default; overridden by gk_fail_max option). */
    const GK_FAIL_MAX    = 3;
    /** Window in seconds over which failures are counted (1 h). */
    const GK_FAIL_WINDOW = 3600;
    /** How long a challenge-failure ban lasts in seconds (default 1 h; overridden by gk_ban_ttl_sec option). */
    const GK_BAN_TTL     = 3600;

    private $enabled;
    private $challenge_borderline;
    private $borderline_min;
    private $borderline_max;
    private $under_attack;

    /** @var Baskerville_Core */
    private $core;

    /** @var Baskerville_Stats */
    private $stats;

    public function __construct($core = null, $stats = null) {
        $options = get_option('baskerville_settings', array());
        $provider = isset($options['captcha_provider']) ? $options['captcha_provider'] : 'none';
        $this->enabled            = ($provider === 'gatekeeper');
        $this->challenge_borderline = isset($options['turnstile_challenge_borderline']) ? (bool) $options['turnstile_challenge_borderline'] : false;
        $this->borderline_min     = isset($options['turnstile_borderline_min']) ? (int) $options['turnstile_borderline_min'] : 40;
        $this->borderline_max     = isset($options['turnstile_borderline_max']) ? (int) $options['turnstile_borderline_max'] : 70;
        $this->under_attack       = isset($options['turnstile_under_attack']) ? (bool) $options['turnstile_under_attack'] : false;
        $this->core               = $core;
        $this->stats              = $stats;
    }

    public function is_enabled() {
        return $this->enabled;
    }

    /**
     * Per-IP rate limiter for upstream calls.
     *
     * Limits how often a single visitor IP can trigger calls to captcha.openports.dev.
     * Uses the same file-cache window counter as the firewall burst protection.
     *
     * Limits (per 60-second window):
     *   generate — 6  (challenge page loads / refreshes)
     *   verify   — 10 (solution submission attempts)
     *   token    — 6  (pass-token re-verification)
     *
     * Returns true when the IP has exceeded the limit (caller should fail open or 429).
     */
    public function upstream_rate_limited( string $ip, string $action ): bool {
        if ( ! $this->core || $ip === '' ) {
            return false;
        }

        $limits = [
            'generate' => 6,
            'verify'   => 10,
            'token'    => 6,
        ];

        $max = $limits[ $action ] ?? 6;
        $cnt = $this->core->fc_inc_in_window( "gk_{$action}:{$ip}", 60 );

        if ( $cnt > $max ) {
            wpsec_log( "[gatekeeper] rate limit hit action={$action} ip={$ip} cnt={$cnt}" );
            return true;
        }

        return false;
    }

    /**
     * Record a failed challenge attempt for an IP.
     *
     * Increments a sliding-window counter (GK_FAIL_WINDOW seconds).
     * When the count reaches GK_FAIL_MAX the IP is written into the shared
     * ban cache (same key/format used by Baskerville_Firewall::set_ban) so
     * the firewall will block it on every subsequent request.
     *
     * Returns true if the IP was just banned (caller should respond with 403).
     */
    public function record_failed_attempt(string $ip): bool {
        if (!$this->core || $ip === '') {
            return false;
        }

        // Read configurable thresholds from baskerville_settings (fall back to constants).
        $opts     = get_option('baskerville_settings', array());
        $fail_max = isset($opts['gk_fail_max']) ? (int) $opts['gk_fail_max'] : self::GK_FAIL_MAX;
        $ban_ttl  = isset($opts['gk_ban_ttl_sec']) ? (int) $opts['gk_ban_ttl_sec'] : self::GK_BAN_TTL;

        $cnt = $this->core->fc_inc_in_window("gk_fail:{$ip}", self::GK_FAIL_WINDOW);
        wpsec_log("[gatekeeper] challenge fail count ip={$ip} cnt={$cnt}/{$fail_max}");

        // Write gk_fail stat to DB for analytics.
        $this->log_challenge_event('fail', 'gk-challenge-fail', $ip);

        if ($cnt >= $fail_max) {
            $payload = [
                'reason' => 'gk-challenge-fail',
                'until'  => time() + $ban_ttl,
                'score'  => 100,
                'cls'    => 'bot',
            ];
            $this->core->fc_set("ban:{$ip}", $payload, $ban_ttl);
            wpsec_log("[gatekeeper] IP BANNED after {$cnt} failed challenges: ip={$ip}");
            return true;
        }

        return false;
    }

    /**
     * Write a gk_redir / gk_pass / gk_fail event to the stats table.
     * Mirrors Baskerville_Turnstile::log_challenge_event() but uses gk_ prefix.
     *
     * @param string $result  'redir' | 'pass' | 'fail'
     * @param string $reason  Optional reason string (for fail events)
     * @param string $ip      Visitor IP (defaults to REMOTE_ADDR)
     */
    public function log_challenge_event(string $result, string $reason = '', string $ip = '') {
        global $wpdb;

        if ($ip === '') {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        }
        $baskerville_id = isset($_COOKIE['baskerville_id']) ? sanitize_text_field(wp_unslash($_COOKIE['baskerville_id'])) : '';
        $baskerville_id = substr($baskerville_id, 0, 100);
        $user_agent     = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        $event_type = 'gk_' . $result; // gk_redir, gk_pass, gk_fail

        $table_name = $wpdb->prefix . 'baskerville_stats';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table_name,
            array(
                'visit_key'             => wp_generate_uuid4(),
                'ip'                    => $ip,
                'baskerville_id'        => $baskerville_id,
                'timestamp_utc'         => current_time('mysql', true),
                'event_type'            => $event_type,
                'block_reason'          => $reason,
                'user_agent'            => $user_agent,
                'score'                 => 0,
                'classification'        => 'gatekeeper',
                'had_fp'                => !empty($baskerville_id) ? 1 : 0,
                'evaluation_json'       => '{}',
                'score_reasons'         => '',
                'classification_reason' => 'gk_challenge',
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s', '%s')
        );
    }

    public function should_challenge($score, $baskerville_id) {
        if (!$this->enabled) {
            return false;
        }
        if ($this->has_valid_pass()) {
            return false;
        }
        if ($this->under_attack) {
            return true;
        }
        if (!$this->challenge_borderline) {
            return false;
        }
        return $score >= $this->borderline_min && $score <= $this->borderline_max;
    }

    /**
     * Set a local HMAC-signed pass cookie so the firewall recognises a verified visitor.
     * Called after the upstream /captcha/verify returns 200.
     * This is the primary pass mechanism — it does not depend on the upstream setting
     * __wpsec_solved_ (which can silently fail due to proxy/cookie-forwarding issues).
     *
     * The cookie is paired with a server-side file-cache entry keyed by IP+timestamp.
     * validate_local_pass() requires BOTH to be present. This prevents a CDN from
     * replaying a cached Set-Cookie header (from a previous user's successful solve) to
     * a different visitor: the cache entry only exists for the IP that actually solved.
     */
    public function set_local_pass() {
        $timestamp = time();
        $ip        = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        $secret    = wp_salt('auth');
        $hmac      = hash_hmac('sha256', (string) $timestamp, $secret);
        $value     = $timestamp . '.' . $hmac;

        setcookie(self::GK_PASS_COOKIE, $value, [
            'expires'  => $timestamp + self::GK_PASS_TTL,
            'path'     => '/',
            'domain'   => '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE[self::GK_PASS_COOKIE] = $value;

        // Write IP-bound server-side record. validate_local_pass() checks this
        // in addition to the HMAC so CDN-replayed cookies from other IPs are rejected.
        if ($this->core && $ip !== '') {
            $this->core->fc_set("gk_lp:{$ip}:{$timestamp}", 1, self::GK_PASS_TTL);
        }
    }

    /**
     * Validate the local HMAC pass cookie set by set_local_pass().
     *
     * Requires two things:
     *   1. A valid HMAC on the cookie value (proves it was issued by this server).
     *   2. A matching server-side cache entry keyed by IP + timestamp (proves the
     *      cookie was originally issued for *this* IP, not replayed from another
     *      visitor via a CDN-cached Set-Cookie header).
     */
    public function validate_local_pass() {
        $cookie = isset($_COOKIE[self::GK_PASS_COOKIE]) ? (string) $_COOKIE[self::GK_PASS_COOKIE] : '';
        if ($cookie === '') {
            return false;
        }
        $dot = strpos($cookie, '.');
        if ($dot === false) {
            return false;
        }
        $timestamp = (int) substr($cookie, 0, $dot);
        $hmac      = (string) substr($cookie, $dot + 1);

        if ($timestamp <= 0 || time() > $timestamp + self::GK_PASS_TTL) {
            return false;
        }
        $secret   = wp_salt('auth');
        $expected = hash_hmac('sha256', (string) $timestamp, $secret);
        if (!hash_equals($expected, $hmac)) {
            return false;
        }

        // Require the server-side IP-bound record to exist.
        // Without this check a CDN could replay a cached baskerville_gk_pass Set-Cookie
        // header (from another visitor's successful solve) and bypass the challenge.
        if ($this->core) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
            if ($ip !== '' && !$this->core->fc_get("gk_lp:{$ip}:{$timestamp}")) {
                error_log('[Baskerville GK] validate_local_pass: HMAC ok but NO server record — ip=' . $ip . ' ts=' . $timestamp . ' (CDN replay or expired cache)');
                return false;
            }
            error_log('[Baskerville GK] validate_local_pass: HMAC + server record OK — ip=' . $ip . ' ts=' . $timestamp);
        }

        return true;
    }

    /**
     * Lightweight pass check used by the firewall at plugins_loaded.
     * Checks the local pass first (no upstream call), then falls back to
     * the upstream-issued __wpsec_solved_ token and the server-side cache.
     */
    public function has_valid_pass() {
        // Local HMAC pass — set by set_local_pass() after successful upstream verification.
        // validate_local_pass() now also checks a server-side IP-bound cache entry so
        // CDN-replayed cookies from other visitors are rejected.
        if ($this->validate_local_pass()) {
            error_log('[Baskerville GK] has_valid_pass: LOCAL PASS valid (baskerville_gk_pass)');
            return true;
        }
        // Upstream pass token forwarded from captcha.openports.dev.
        if ($this->has_pass_cookie()) {
            error_log('[Baskerville GK] has_valid_pass: UPSTREAM COOKIE present (__wpsec_solved_=' . substr((string)($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME] ?? ''), 0, 30) . ')');
            return true;
        }
        error_log('[Baskerville GK] has_valid_pass: FALSE (no valid pass)');
        return false;
    }

    public function has_pass_cookie() {
        return !empty($_COOKIE[CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME]);
    }

    /**
     * Sets a flag for wpsec_enforce_captcha_policy() to pick up at template_redirect.
     * Does NOT perform an HTTP redirect — challenge is served inline by the gatekeeper.
     */
    public function redirect_to_challenge() {
        $GLOBALS['baskerville_gatekeeper_challenge'] = true;

        // Tell page-cache plugins not to store this response.
        // Defined here (plugins_loaded) so it is set before any caching plugin
        // hooks into shutdown or ob_start to write its cache file.
        if (!defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);
        }
        $GLOBALS['DONOTCACHEPAGE'] = 1;
    }

    /**
     * Register the template_redirect hook that serves the challenge inline.
     * Called from plugins_loaded after the firewall is initialised.
     */
    public function init() {
        add_action('template_redirect', 'wpsec_enforce_captcha_policy', 1);
        add_action('template_redirect', array($this, 'maybe_activate_test_mode'), 0);
        add_action('wp_ajax_baskerville_gk_test_start', array($this, 'ajax_test_start'));
        add_action('wp_ajax_baskerville_gk_test_stop',  array($this, 'ajax_test_stop'));

        // Tell WP Super Cache (PHP mode) to bypass its cache for visitors who
        // carry any of our cookies.  Super Cache stores a list of "no-cache"
        // cookie names; if any of them is present in the request the cached
        // file is not served and WordPress runs normally.
        $this->register_supercache_bypass_cookies();
    }

    /**
     * Register Baskerville cookies with WP Super Cache so that users who have
     * already solved the challenge (or are mid-challenge) are never served a
     * stale cached version of the challenge page.
     *
     * This works for WP Super Cache PHP/Simple mode.  Expert (mod_rewrite) mode
     * is handled by defining DONOTCACHEPAGE before writing the challenge response,
     * which prevents the challenge HTML from ever entering the file cache.
     */
    private function register_supercache_bypass_cookies() {
        // WP Super Cache: filter to append cookie names.
        add_filter('wpsc_cookie_names', function( $cookies ) {
            $ours = array(
                self::GK_PASS_COOKIE,                  // baskerville_gk_pass
                CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME, // __wpsec_solved_
                USER_CAPTCHA_CHALLENGE_COOKIE_NAME,    // __wpsec_challenge_
                'baskerville_id',
            );
            return array_unique( array_merge( (array) $cookies, $ours ) );
        });

        // WP Super Cache also checks the global $cache_rejected_cookies array.
        add_action('wp', function() {
            global $cache_rejected_cookies;
            if (!is_array($cache_rejected_cookies)) {
                $cache_rejected_cookies = array();
            }
            $ours = array(
                self::GK_PASS_COOKIE,
                CAPTCHA_PREVIOUSLY_PASSED_COOKIE_NAME,
                USER_CAPTCHA_CHALLENGE_COOKIE_NAME,
                'baskerville_id',
            );
            $cache_rejected_cookies = array_unique( array_merge( $cache_rejected_cookies, $ours ) );
        });
    }

    /**
     * Runs at template_redirect priority 0 (before wpsec_enforce_captcha_policy).
     * If the current logged-in admin has an active test session, sets the challenge
     * globals so the admin bypass in wpsec_enforce_captcha_policy() is skipped.
     */
    public function maybe_activate_test_mode() {
        if (!is_user_logged_in() || !current_user_can('manage_options')) {
            return;
        }
        $user_id = get_current_user_id();
        $expiry  = (int) get_user_meta($user_id, 'baskerville_gk_test', true);
        if ($expiry <= 0 || time() > $expiry) {
            return;
        }
        $GLOBALS['baskerville_gatekeeper_challenge'] = true;
        $GLOBALS['baskerville_gatekeeper_test_mode'] = true;
        wpsec_log('[gatekeeper] test mode active for user ' . $user_id . ', expires ' . date('H:i:s', $expiry));
    }

    /** AJAX: start test mode for the current admin user. */
    public function ajax_test_start() {
        check_ajax_referer('baskerville_gk_test_start', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized', 403);
        }
        $user_id = get_current_user_id();
        $expiry  = time() + 10 * MINUTE_IN_SECONDS;
        update_user_meta($user_id, 'baskerville_gk_test', $expiry);
        wp_send_json_success(array(
            'url'    => home_url('/'),
            'expiry' => $expiry,
        ));
    }

    /** AJAX: stop test mode for the current admin user. */
    public function ajax_test_stop() {
        check_ajax_referer('baskerville_gk_test_stop', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized', 403);
        }
        delete_user_meta(get_current_user_id(), 'baskerville_gk_test');
        wp_send_json_success();
    }
}