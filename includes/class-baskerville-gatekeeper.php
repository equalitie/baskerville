<?php

if (!defined('ABSPATH')) {
    exit;
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

    //TODO
    $should_challenge = true;

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
    header('Cache-Control: no-store, no-cache');
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

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    $cookie_header = wpsec_build_cookie_header_for_captcha_challenge_verification();

    wpsec_log('[gatekeeper] forwarding verification cookie header=' . $cookie_header);

    $response = wp_remote_get('https://captcha.openports.dev/captcha/verify', [
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
    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    $cookie_header = wpsec_build_cookie_header_for_token_verification();

    wpsec_log('[gatekeeper] forwarding token verification cookie header=' . $cookie_header);

    $response = wp_remote_get('https://captcha.openports.dev/token/verify', [
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

    wpsec_log('[gatekeeper] issuing challenge for uri=' . ($_SERVER['REQUEST_URI'] ?? ''));

    $original_url = (is_ssl() ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? '')
        . ($_SERVER['REQUEST_URI'] ?? '');

    wpsec_log('[gatekeeper] original URL=' . $original_url);

    $response = wp_remote_get('https://captcha.openports.dev/captcha/generate', [
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
        wpsec_log('[gatekeeper] challenge fetch failed: ' . $response->get_error_message());

        status_header(503);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><body><h1>Challenge unavailable</h1></body></html>';
        exit;
    }

    $status_code  = wp_remote_retrieve_response_code($response);
    $content_type = wp_remote_retrieve_header($response, 'content-type') ?: 'text/html; charset=utf-8';
    $body         = wp_remote_retrieve_body($response);

    wpsec_log('[gatekeeper] challenge fetch succeeded, status=' . $status_code);
    wpsec_log('[gatekeeper] challenge content-type=' . $content_type);
    wpsec_log('[gatekeeper] challenge body length=' . strlen($body));

    wpsec_forward_upstream_cookies($response);

    status_header(200);
    header('Content-Type: ' . $content_type);
    header('Cache-Control: no-store, no-cache');
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

    $response = wp_remote_get('https://captcha.openports.dev/captcha/refresh', [
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
            wpsec_log('[gatekeeper] privileged logged-in user, allowing');
            return;
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
    
        //we check to see if the captcha challenge has previously been passed
        //by looking for the challenge passed cookie. If so, we go through validating it
        //to make sure its not forged, expired, replayed etc. If not we continue
        //to check whether this current requester ought to be challenged
        if (wpsec_captcha_pass_token_cookie_is_present()) {
    
            $token_validation_result = wpsec_verify_captcha_pass_token_cookie_is_valid();
    
            $message = $token_validation_result['message'] ?? '';
            $status_code = (int) ($token_validation_result['status_code'] ?? 0);
    
            if ($status_code === 204) {
                wpsec_log('[gatekeeper] valid pass cookie found, allowing');
                //make sure we always relay their valid cookie back to them so that they can continue
                //to browser undisturbed since their solution is legitamate
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
    
        //if the user didnt have a challenge pass BUT also is not meant to be challenged
        //then allow them through normally
        if (!wpsec_should_challenge()) {
            wpsec_log('[gatekeeper] should not challenge, allowing normal render');
            return;
        }

        /*
            at this point we know that we are dealing with a user who needs to be challenged
            but it could also be that we are in the middle of a challenge
        */
    
        //check if its a refresh
        $requested_action = wpsec_get_requested_action();
        wpsec_log('[gatekeeper] requested action=' . $requested_action);
        if ($requested_action === 'refresh') {
            wpsec_log('[gatekeeper] refresh action detected');
            wpsec_clear_challenge_cookies();
            wpsec_refresh_challenge_state();
        }
    
        //check if it has solution
        if (wpsec_has_verification_cookies()) {
            $verification_result = wpsec_verify_captcha_solution_via_upstream_cookies();
            $message = $verification_result['message'] ?? '';
            $status_code = (int) ($verification_result['status_code'] ?? 0);
    
            wpsec_log('[gatekeeper] verification result status=' . $status_code . ' message=' . $message);
    
            if ($status_code === 403 && $message === 'invalid solution') {
                //relay back the 403 + message such that the puzzle displays the correct
                //message to the user
                wpsec_log('[gatekeeper] relaying invalid solution back to client');
                wpsec_send_plain_response(403, 'invalid solution');
    
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
                //re-issue the challenge but NOT here, instead respond BACK to the user
                //with 404 such that client side triggers refresh and gets challenged again
                //however, we need to first clear all of their existing cookies
                wpsec_log('[gatekeeper] bad verification payload, clearing cookies and telling client to refresh');
                wpsec_clear_challenge_cookies();
                wpsec_send_plain_response(404, 'refresh challenge');
    
            } else if ($status_code === 200) {
                //their solution was correct, the wordpress origin will receive
                //a "challenge passed" solution cookie in the header. Here we need
                //to remove them from the list to challenge and subsequently we 
                //need to delete all other cookies they might have AND attach this 
                //new cookie that the captcha service server sends back to the wordpress 
                //origin server
                wpsec_log('[gatekeeper] verification succeeded, clearing leftover challenge cookies and allowing');
    
                // so for example, we could implement a function that would mark them as having already
                // passed and remove them from the list of people to be challenged and not be interferred with
                // later unless the ML pipeline pushes up another challenge or something.
                // so as a placeholder here to remove from local challenge list / cache / rule store i left
                //this just for it to be clear
                // wpsec_mark_visitor_as_passed();
    
                // upstream pass cookie has already been forwarded in wpsec_verify_captcha_solution_via_upstream_cookies()
                // now clear any leftover challenge/solution cookies from this host-side state
                wpsec_clear_challenge_cookies();
    
                wpsec_log('[gatekeeper] verification succeeded, allowing normal render');
                return;
    
            } else {
                //something went wrong, this is unexpected, log it in some persistent error
                //log and fallback on re-issueing the challenge
                wpsec_log('[gatekeeper] unexpected verification result, clearing cookies and reissuing challenge');
                wpsec_clear_challenge_cookies();
                wpsec_issue_challenge();
            }
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


//-------------------------------------------------------------
//-------------------------------------------------------------
//calls main function to enforce captcha enforcement policy
//-------------------------------------------------------------
//-------------------------------------------------------------
add_action('template_redirect', 'wpsec_enforce_captcha_policy');