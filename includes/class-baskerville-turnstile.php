<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Cloudflare Turnstile integration for Baskerville
 * Adds Turnstile challenge to login, registration, comment forms,
 * and provides challenge page for borderline bot scores
 */
class Baskerville_Turnstile {

	private $site_key;
	private $secret_key;
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
		$this->enabled = isset($options['turnstile_enabled']) ? (bool) $options['turnstile_enabled'] : false;
		$this->site_key = isset($options['turnstile_site_key']) ? $options['turnstile_site_key'] : '';
		$this->secret_key = isset($options['turnstile_secret_key']) ? $options['turnstile_secret_key'] : '';
		$this->challenge_borderline = isset($options['turnstile_challenge_borderline']) ? (bool) $options['turnstile_challenge_borderline'] : false;
		$this->borderline_min = isset($options['turnstile_borderline_min']) ? (int) $options['turnstile_borderline_min'] : 40;
		$this->borderline_max = isset($options['turnstile_borderline_max']) ? (int) $options['turnstile_borderline_max'] : 70;
		$this->under_attack = isset($options['turnstile_under_attack']) ? (bool) $options['turnstile_under_attack'] : false;
		$this->core = $core;
		$this->stats = $stats;
	}

	/**
	 * Check if Turnstile is fully enabled and configured
	 */
	public function is_enabled() {
		return $this->enabled && !empty($this->site_key) && !empty($this->secret_key);
	}

	/**
	 * Initialize hooks if Turnstile is enabled and configured
	 */
	public function init() {
		// Always register routes (needed for challenge page)
		add_action('init', array($this, 'register_routes'));
		add_filter('query_vars', array($this, 'add_query_vars'));
		add_action('template_redirect', array($this, 'handle_routes'), 1);

		if (!$this->enabled || empty($this->site_key) || empty($this->secret_key)) {
			return;
		}

		// Login form
		add_action('login_form', array($this, 'render_turnstile_widget'));
		add_action('login_enqueue_scripts', array($this, 'enqueue_turnstile_script'));
		add_filter('authenticate', array($this, 'verify_login'), 999, 3);

		// Registration form
		add_action('register_form', array($this, 'render_turnstile_widget'));
		add_filter('registration_errors', array($this, 'verify_registration'), 10, 3);

		// Comment form
		add_action('comment_form_after_fields', array($this, 'render_turnstile_widget'));
		add_action('comment_form_logged_in_after', array($this, 'render_turnstile_widget'));
		add_filter('preprocess_comment', array($this, 'verify_comment'));

		// Enqueue script on frontend for comments
		add_action('wp_enqueue_scripts', array($this, 'maybe_enqueue_frontend_script'));
	}

	/**
	 * Add query vars
	 */
	public function add_query_vars($vars) {
		$vars[] = 'baskerville_challenge';
		$vars[] = 'baskerville_verify';
		return $vars;
	}

	/**
	 * Register challenge and verify routes
	 */
	public function register_routes() {
		add_rewrite_rule(
			'^baskerville-challenge/?$',
			'index.php?baskerville_challenge=1',
			'top'
		);
		add_rewrite_rule(
			'^baskerville-verify/?$',
			'index.php?baskerville_verify=1',
			'top'
		);

		// Auto-flush rewrite rules once if our rules are missing (version-based check)
		$flush_version = '1.0';
		if (get_option('baskerville_turnstile_flush_version') !== $flush_version) {
			flush_rewrite_rules();
			update_option('baskerville_turnstile_flush_version', $flush_version);
		}
	}

	/**
	 * Handle challenge and verify routes
	 */
	public function handle_routes() {
		$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

		// Support ALL methods: rewrite rules, query params, AND direct URL path matching
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$is_challenge = get_query_var('baskerville_challenge')
			|| isset($_GET['baskerville_challenge'])
			|| preg_match('#/baskerville-challenge/?(\?|$)#', $request_uri);

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		$is_verify = get_query_var('baskerville_verify')
			|| isset($_GET['baskerville_verify'])
			|| isset($_POST['baskerville_verify'])
			|| preg_match('#/baskerville-verify/?(\?|$)#', $request_uri);

		if ($is_challenge) {
			$this->render_challenge_page();
			exit;
		}

		if ($is_verify) {
			$this->handle_verify();
			exit;
		}

	}

	/**
	 * Check if visitor should be challenged (called from firewall)
	 * @param int $score Bot score
	 * @param string $baskerville_id Cookie ID
	 * @return bool
	 */
	public function should_challenge($score, $baskerville_id) {
		// Must be enabled and configured
		if (!$this->enabled || empty($this->site_key) || empty($this->secret_key)) {
			return false;
		}

		// Check if already passed challenge
		if ($this->has_pass_cookie()) {
			return false;
		}

		// Under Attack Mode: challenge everyone (even without cookie)
		if ($this->under_attack) {
			return true;
		}

		// Normal mode: need borderline challenge enabled and cookie
		if (!$this->challenge_borderline) {
			return false;
		}

		// Must have cookie for borderline check
		if (empty($baskerville_id)) {
			return false;
		}

		// Check if score is in borderline range
		return $score >= $this->borderline_min && $score <= $this->borderline_max;
	}

	/**
	 * Check if visitor has valid pass cookie
	 */
	public function has_pass_cookie() {
		if (!isset($_COOKIE['baskerville_pass'])) {
			return false;
		}

		$pass_data = sanitize_text_field(wp_unslash($_COOKIE['baskerville_pass']));

		// Cookie format: timestamp.hash (using dot to avoid URL encoding issues with colon)
		$parts = explode('.', $pass_data);
		if (count($parts) !== 2) {
			// Legacy format support: timestamp:hash (may have URL encoding issues)
			$parts = explode(':', $pass_data);
			if (count($parts) !== 2) {
				return false;
			}
		}

		$timestamp = (int) $parts[0];
		$hash = $parts[1];

		// Check if expired (24 hours)
		if (time() - $timestamp > 86400) {
			return false;
		}

		// Verify hash
		$expected_hash = $this->generate_pass_hash($timestamp);
		return hash_equals($expected_hash, $hash);
	}

	/**
	 * Generate pass cookie hash
	 * Note: We don't include full IP in hash because sites behind Deflect/CDN
	 * may see different REMOTE_ADDR values from different edge servers.
	 * The baskerville_id cookie already contains IP validation.
	 */
	private function generate_pass_hash($timestamp) {
		$secret = get_option('baskerville_cookie_secret', 'default_secret');
		$baskerville_id = isset($_COOKIE['baskerville_id']) ? sanitize_text_field(wp_unslash($_COOKIE['baskerville_id'])) : '';

		// Use only timestamp + baskerville_id for hash (baskerville_id already has IP binding)
		return hash_hmac('sha256', $timestamp . $baskerville_id, $secret);
	}

	/**
	 * Set pass cookie after successful challenge
	 */
	private function set_pass_cookie() {
		$timestamp = time();
		$hash = $this->generate_pass_hash($timestamp);
		$value = $timestamp . '.' . $hash;

		setcookie(
			'baskerville_pass',
			$value,
			array(
				'expires' => time() + 86400, // 24 hours
				'path' => '/',
				'secure' => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		// Inject into $_COOKIE for current request
		$_COOKIE['baskerville_pass'] = $value;
	}

	/**
	 * Redirect to challenge page
	 * @param string $return_url URL to return after challenge
	 */
	public function redirect_to_challenge($return_url = null) {
		if ($return_url === null) {
			$return_url = (is_ssl() ? 'https://' : 'http://') .
				(isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '') .
				(isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/');
		}

		$challenge_url = home_url('/') . '?baskerville_challenge=1&return=' . rawurlencode($return_url);

		// Log challenge redirect
		$this->log_challenge_event('redirect', null);

		// Prevent CDN/EQpress caching of redirects - must be before any output
		if (!headers_sent()) {
			header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
			header('Pragma: no-cache');
			header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
			header('X-Baskerville-Redirect: challenge');
		}
		nocache_headers();

		wp_safe_redirect($challenge_url);
		exit;
	}

	/**
	 * Render challenge page
	 */
	private function render_challenge_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$return_url = isset($_GET['return']) ? esc_url_raw(wp_unslash($_GET['return'])) : home_url('/');

		// Validate return URL is same domain
		$return_host = wp_parse_url($return_url, PHP_URL_HOST);
		$site_host = wp_parse_url(home_url(), PHP_URL_HOST);
		if ($return_host !== $site_host) {
			$return_url = home_url('/');
		}

		$site_name = get_bloginfo('name');
		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo('charset'); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<meta name="robots" content="noindex, nofollow">
			<title><?php echo esc_html__('Security Check', 'baskerville') . ' - ' . esc_html($site_name); ?></title>
			<?php
			wp_register_script( 'cloudflare-turnstile-challenge', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), '1.0', false ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- Cloudflare Turnstile API must be loaded from Cloudflare servers
			wp_print_scripts( 'cloudflare-turnstile-challenge' );
			?>
			<style>
				* { box-sizing: border-box; margin: 0; padding: 0; }
				body {
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
					background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
					min-height: 100vh;
					display: flex;
					align-items: center;
					justify-content: center;
					padding: 20px;
				}
				.challenge-container {
					background: white;
					border-radius: 12px;
					box-shadow: 0 20px 60px rgba(0,0,0,0.3);
					padding: 40px;
					max-width: 420px;
					width: 100%;
					text-align: center;
				}
				.challenge-icon {
					width: 64px;
					height: 64px;
					background: #f0f0f0;
					border-radius: 50%;
					display: flex;
					align-items: center;
					justify-content: center;
					margin: 0 auto 20px;
					font-size: 32px;
				}
				h1 {
					color: #333;
					font-size: 24px;
					margin-bottom: 10px;
				}
				p {
					color: #666;
					font-size: 14px;
					line-height: 1.6;
					margin-bottom: 25px;
				}
				.turnstile-wrapper {
					display: flex;
					justify-content: center;
					margin: 20px 0;
				}
				.site-name {
					color: #999;
					font-size: 12px;
					margin-top: 20px;
				}
				.error-message {
					background: #fee;
					border: 1px solid #fcc;
					color: #c00;
					padding: 10px;
					border-radius: 6px;
					margin-bottom: 15px;
					display: none;
				}
				.loading {
					color: #999;
					font-size: 14px;
				}
				.cf-turnstile iframe {
					width: 100% !important;
				}
			</style>
		</head>
		<body>
			<div class="challenge-container">
				<div class="challenge-icon">🛡️</div>
				<h1><?php esc_html_e('Security Check', 'baskerville'); ?></h1>
				<p><?php esc_html_e('Please complete this security check to continue to the website. This helps us prevent automated access.', 'baskerville'); ?></p>

				<div id="error-message" class="error-message"></div>

				<form method="POST" action="<?php echo esc_url(home_url('/?baskerville_verify=1')); ?>" id="challenge-form">
					<input type="hidden" name="return" value="<?php echo esc_attr($return_url); ?>">
					<?php wp_nonce_field('baskerville_challenge', 'baskerville_nonce'); ?>

					<div class="turnstile-wrapper">
						<div class="cf-turnstile"
							 data-sitekey="<?php echo esc_attr($this->site_key); ?>"
							 data-callback="onTurnstileSuccess"
							 data-error-callback="onTurnstileError"
							 data-theme="light">
						</div>
					</div>
				</form>

				<p class="site-name"><?php echo esc_html($site_name); ?></p>
			</div>

			<script>
				function onTurnstileSuccess(token) {
					console.log('Turnstile success, submitting form');
					var form = document.getElementById('challenge-form');
					if (form) {
						form.submit();
					} else {
						console.error('Form not found!');
					}
				}

				function onTurnstileError(error) {
					console.error('Turnstile error:', error);
					var errorDiv = document.getElementById('error-message');
					errorDiv.textContent = '<?php echo esc_js(__('Verification failed. Please refresh and try again.', 'baskerville')); ?>';
					errorDiv.style.display = 'block';
				}
			</script>
		</body>
		</html>
		<?php
	}

	/**
	 * Handle verify endpoint
	 */
	private function handle_verify() {
		// Verify nonce
		if (!isset($_POST['baskerville_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['baskerville_nonce'])), 'baskerville_challenge')) {
			$this->log_challenge_event('fail', 'invalid_nonce');
			wp_die(esc_html__('Security check failed. Please try again.', 'baskerville'), esc_html__('Error', 'baskerville'), array('response' => 403));
		}

		// Get token
		$token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';

		if (empty($token)) {
			$this->log_challenge_event('fail', 'missing_token');
			wp_die(esc_html__('Please complete the security check.', 'baskerville'), esc_html__('Error', 'baskerville'), array('response' => 403));
		}

		// Verify with Cloudflare
		$result = $this->verify_token($token);

		// Get return URL
		$return_url = isset($_POST['return']) ? esc_url_raw(wp_unslash($_POST['return'])) : home_url('/');

		// Validate return URL
		$return_host = wp_parse_url($return_url, PHP_URL_HOST);
		$site_host = wp_parse_url(home_url(), PHP_URL_HOST);
		if ($return_host !== $site_host) {
			$return_url = home_url('/');
		}

		if (is_wp_error($result)) {
			// Log failure
			$this->log_challenge_event('fail', $result->get_error_code());

			// Show error and redirect back to challenge
			wp_die(
				esc_html($result->get_error_message()) . '<br><br><a href="' . esc_url(home_url('/?baskerville_challenge=1&return=' . rawurlencode($return_url))) . '">' . esc_html__('Try again', 'baskerville') . '</a>',
				esc_html__('Verification Failed', 'baskerville'),
				array('response' => 403)
			);
		}

		// Success! Set pass cookie and redirect
		$this->set_pass_cookie();
		$this->log_challenge_event('pass', null);

		wp_safe_redirect($return_url);
		exit;
	}

	/**
	 * Log challenge event to database
	 * @param string $result 'redirect', 'pass', 'fail'
	 * @param string|null $reason Failure reason if applicable
	 */
	private function log_challenge_event($result, $reason) {
		global $wpdb;

		$ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
		$baskerville_id = isset($_COOKIE['baskerville_id']) ? sanitize_text_field(wp_unslash($_COOKIE['baskerville_id'])) : '';
		$user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

		// Truncate baskerville_id to fit varchar(100)
		$baskerville_id = substr($baskerville_id, 0, 100);

		// Short event type to fit varchar(16): ts_redir, ts_pass, ts_fail
		$short_result = $result;
		if ($result === 'redirect') {
			$short_result = 'redir';
		}
		$event_type = 'ts_' . $short_result; // ts_redir, ts_pass, ts_fail

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
				'classification'        => 'turnstile',
				'had_fp'                => !empty($baskerville_id) ? 1 : 0,
				'evaluation_json'       => '{}',
				'score_reasons'         => '',
				'classification_reason' => 'turnstile_challenge',
			),
			array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s', '%s')
		);

	}

	/**
	 * Render Turnstile widget for forms
	 */
	public function render_turnstile_widget() {
		?>
		<div class="cf-turnstile"
			 data-sitekey="<?php echo esc_attr($this->site_key); ?>"
			 data-theme="light">
		</div>
		<noscript>
			<p class="baskerville-noscript-warning"><?php esc_html_e('Please enable JavaScript to complete the security check.', 'baskerville'); ?></p>
		</noscript>
		<?php
	}

	/**
	 * Enqueue Turnstile script on login page
	 */
	public function enqueue_turnstile_script() {
		wp_enqueue_script( 'cloudflare-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), '1.0', true ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- Cloudflare Turnstile API must be loaded from Cloudflare servers
	}

	/**
	 * Enqueue script on frontend if on a page with comments
	 */
	public function maybe_enqueue_frontend_script() {
		if (is_singular() && comments_open()) {
			wp_enqueue_script( 'cloudflare-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), '1.0', true ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- Cloudflare Turnstile API must be loaded from Cloudflare servers
		}
	}

	/**
	 * Verify Turnstile response
	 * @param string $token The cf-turnstile-response token
	 * @return bool|WP_Error
	 */
	private function verify_token($token) {
		if (empty($token)) {
			return new WP_Error('turnstile_missing', __('Please complete the security check.', 'baskerville'));
		}

		$response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', array(
			'body' => array(
				'secret' => $this->secret_key,
				'response' => $token,
				'remoteip' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '',
			),
			'timeout' => 10,
		));

		if (is_wp_error($response)) {
			// On network error, allow through (fail open)
			return true;
		}

		$body = json_decode(wp_remote_retrieve_body($response), true);

		if (empty($body['success'])) {
			$error_codes = isset($body['error-codes']) ? implode(', ', $body['error-codes']) : 'unknown';
			return new WP_Error('turnstile_failed', __('Security check failed. Please try again.', 'baskerville'), $error_codes);
		}

		return true;
	}

	/**
	 * Verify login form
	 */
	public function verify_login($user, $username, $password) {
		// Skip if already an error or no username provided
		if (is_wp_error($user) || empty($username)) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';

		$result = $this->verify_token($token);

		if (is_wp_error($result)) {
			return $result;
		}

		return $user;
	}

	/**
	 * Verify registration form
	 */
	public function verify_registration($errors, $sanitized_user_login, $user_email) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';

		$result = $this->verify_token($token);

		if (is_wp_error($result)) {
			$errors->add('turnstile_error', $result->get_error_message());
		}

		return $errors;
	}

	/**
	 * Verify comment form
	 */
	public function verify_comment($commentdata) {
		// Skip for logged in admins
		if (current_user_can('manage_options')) {
			return $commentdata;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';

		$result = $this->verify_token($token);

		if (is_wp_error($result)) {
			wp_die(
				esc_html($result->get_error_message()),
				esc_html__('Comment Submission Failed', 'baskerville'),
				array('back_link' => true)
			);
		}

		return $commentdata;
	}

	/**
	 * Get challenge statistics for admin
	 * @return array
	 */
	public function get_challenge_stats() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$stats = $wpdb->get_results(
			"SELECT
				event_type,
				COUNT(*) as count
			FROM {$wpdb->prefix}baskerville_stats
			WHERE event_type LIKE 'ts_%'
			AND timestamp_utc > DATE_SUB(NOW(), INTERVAL 7 DAY)
			GROUP BY event_type",
			ARRAY_A
		);

		$result = array(
			'redirects' => 0,
			'passes' => 0,
			'fails' => 0,
		);

		foreach ($stats as $row) {
			// Event types are: ts_redir, ts_pass, ts_fail
			if ($row['event_type'] === 'ts_redir') {
				$result['redirects'] = (int) $row['count'];
			} elseif ($row['event_type'] === 'ts_pass') {
				$result['passes'] = (int) $row['count'];
			} elseif ($row['event_type'] === 'ts_fail') {
				$result['fails'] = (int) $row['count'];
			}
		}

		// Calculate pass rate (precision = 1 - pass_rate shows how many were actually bots)
		$total_completed = $result['passes'] + $result['fails'];
		$result['pass_rate'] = $total_completed > 0 ? round($result['passes'] / $total_completed * 100, 1) : 0;
		$result['precision'] = $total_completed > 0 ? round($result['fails'] / $total_completed * 100, 1) : 0;

		return $result;
	}

}
