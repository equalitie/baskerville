<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Altcha PoW challenge integration for Baskerville
 *
 * Self-hosted, privacy-friendly proof-of-work challenge (MIT licensed).
 * No external API calls — verification is done locally in PHP.
 * Widget JS is bundled locally in assets/js/altcha.min.js.
 *
 * Protocol:
 *   1. Server generates: salt + secret_number → challenge = SHA-256(salt+number), signature = HMAC(challenge)
 *   2. Client JS widget computes PoW and posts base64-encoded JSON back
 *   3. Server verifies: SHA-256(salt+number)==challenge AND HMAC matches
 */
class Baskerville_Altcha {

	private $enabled;
	private $challenge_borderline;
	private $borderline_min;
	private $borderline_max;
	private $under_attack;
	private $max_number;
	private $hmac_key;

	/** @var Baskerville_Core */
	private $core;

	/** @var Baskerville_Stats */
	private $stats;

	public function __construct($core = null, $stats = null) {
		$options = get_option('baskerville_settings', array());

		$master_enabled             = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
		$this->enabled              = $master_enabled && (!isset($options['altcha_enabled']) || $options['altcha_enabled']);
		// These settings are shared between Altcha and Turnstile providers — stored under
		// 'turnstile_*' keys in the DB for historical reasons (Turnstile was the first provider).
		// Both providers read the same keys so admin settings apply regardless of active provider.
		$this->challenge_borderline = isset($options['turnstile_challenge_borderline']) ? (bool) $options['turnstile_challenge_borderline'] : false;
		$this->borderline_min       = isset($options['turnstile_borderline_min']) ? (int) $options['turnstile_borderline_min'] : 40;
		$this->borderline_max       = isset($options['turnstile_borderline_max']) ? (int) $options['turnstile_borderline_max'] : 70;
		$this->under_attack         = isset($options['turnstile_under_attack']) ? (bool) $options['turnstile_under_attack'] : false;
		$this->max_number           = isset($options['altcha_max_number']) ? (int) $options['altcha_max_number'] : 100000;
		$this->core                 = $core;
		$this->stats                = $stats;

		// HMAC key is generated once during plugin activation (class-baskerville-installer.php).
		// Fallback here handles edge cases (e.g. manual plugin file copy without activation).
		$this->hmac_key = (string) get_option('baskerville_altcha_hmac_key', '');
		if (empty($this->hmac_key)) {
			$this->hmac_key = bin2hex(random_bytes(32));
			// Use add_option to avoid race condition: if two PHP workers run simultaneously,
			// only the first insert wins; the second is ignored. Then re-read the winner.
			add_option('baskerville_altcha_hmac_key', $this->hmac_key, '', 'no');
			$this->hmac_key = (string) get_option('baskerville_altcha_hmac_key', $this->hmac_key);
		}
	}

	public function is_enabled() {
		return $this->enabled;
	}

	public function init() {
		add_action('init', array($this, 'register_routes'));
		add_filter('query_vars', array($this, 'add_query_vars'));
		add_action('template_redirect', array($this, 'handle_routes'), 1);

		// altcha.min.js is an ES module — must be loaded with type="module" or it fails silently
		add_filter('script_loader_tag', array($this, 'add_module_type'), 10, 2);

		if (!$this->enabled) {
			return;
		}

		add_action('login_form', array($this, 'render_altcha_widget'));
		add_action('login_enqueue_scripts', array($this, 'enqueue_altcha_script'));
		add_filter('authenticate', array($this, 'verify_login'), 999, 3);

		add_action('register_form', array($this, 'render_altcha_widget'));
		add_filter('registration_errors', array($this, 'verify_registration'), 10, 3);

		add_action('comment_form_after_fields', array($this, 'render_altcha_widget'));
		add_action('comment_form_logged_in_after', array($this, 'render_altcha_widget'));
		add_filter('preprocess_comment', array($this, 'verify_comment'));

		add_action('wp_enqueue_scripts', array($this, 'maybe_enqueue_frontend_script'));
	}

	public function add_query_vars($vars) {
		$vars[] = 'baskerville_challenge';
		$vars[] = 'baskerville_verify';
		$vars[] = 'baskerville_altcha_challenge';
		return $vars;
	}

	public function register_routes() {
		add_rewrite_rule('^baskerville-challenge/?$',        'index.php?baskerville_challenge=1',        'top');
		add_rewrite_rule('^baskerville-verify/?$',           'index.php?baskerville_verify=1',           'top');
		add_rewrite_rule('^baskerville-altcha-challenge/?$', 'index.php?baskerville_altcha_challenge=1', 'top');

		$flush_version = '1.1';
		if (get_option('baskerville_altcha_flush_version') !== $flush_version) {
			flush_rewrite_rules();
			update_option('baskerville_altcha_flush_version', $flush_version);
		}
	}

	public function handle_routes() {
		$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

		$is_challenge = get_query_var('baskerville_challenge')
			|| filter_has_var(INPUT_GET, 'baskerville_challenge')
			|| preg_match('#/baskerville-challenge/?(\?|$)#', $request_uri);

		$is_verify = get_query_var('baskerville_verify')
			|| filter_has_var(INPUT_GET, 'baskerville_verify')
			|| filter_has_var(INPUT_POST, 'baskerville_verify')
			|| preg_match('#/baskerville-verify/?(\?|$)#', $request_uri);

		$is_altcha_json = get_query_var('baskerville_altcha_challenge')
			|| filter_has_var(INPUT_GET, 'baskerville_altcha_challenge')
			|| preg_match('#/baskerville-altcha-challenge/?(\?|$)#', $request_uri);

		if ($is_altcha_json) {
			$this->send_challenge_json();
			exit;
		}

		if ($is_challenge) {
			$this->render_challenge_page();
			exit;
		}

		if ($is_verify) {
			$this->handle_verify();
			exit;
		}
	}

	// ── Challenge generation ────────────────────────────────────────────────

	private function generate_challenge_data() {
		$salt          = bin2hex(random_bytes(12));
		$secret_number = random_int(1, $this->max_number);
		$challenge     = hash('sha256', $salt . $secret_number);
		$signature     = hash_hmac('sha256', $challenge, $this->hmac_key);

		return array(
			'algorithm' => 'SHA-256',
			'challenge' => $challenge,
			'maxnumber' => $this->max_number,
			'salt'      => $salt,
			'signature' => $signature,
		);
	}

	/** GET /baskerville-altcha-challenge — widget fetches this */
	public function send_challenge_json() {
		if (!headers_sent()) {
			header('Content-Type: application/json; charset=utf-8');
			// Prevent CDN (Deflect) from caching challenges — stale challenges allow replay attacks
			nocache_headers();
			header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
		}
		echo wp_json_encode($this->generate_challenge_data());
		exit;
	}

	// ── Payload verification ────────────────────────────────────────────────

	private function verify_altcha_payload($altcha_b64) {
		if (empty($altcha_b64)) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$json = base64_decode($altcha_b64, true);
		if (!$json) {
			return false;
		}

		$payload = json_decode($json, true);
		if (!is_array($payload)) {
			return false;
		}

		$algorithm = $payload['algorithm'] ?? '';
		$challenge  = $payload['challenge'] ?? '';
		$number     = isset($payload['number']) ? (int) $payload['number'] : -1;
		$salt       = $payload['salt'] ?? '';
		$signature  = $payload['signature'] ?? '';

		if ($algorithm !== 'SHA-256' || empty($challenge) || $number < 0 || empty($salt) || empty($signature)) {
			return false;
		}

		// Verify PoW: SHA-256(salt + number) must equal challenge
		$computed = hash('sha256', $salt . $number);
		if (!hash_equals($computed, $challenge)) {
			return false;
		}

		// Verify server-issued signature (prevents forged challenges)
		$expected = hash_hmac('sha256', $challenge, $this->hmac_key);
		return hash_equals($expected, $signature);
	}

	// ── Challenge decision (same interface as Baskerville_Turnstile) ────────

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

		if (!$this->challenge_borderline || empty($baskerville_id)) {
			return false;
		}

		return $score >= $this->borderline_min && $score <= $this->borderline_max;
	}

	// ── Pass cookie (identical logic to Turnstile for CDN compatibility) ────

	public function has_valid_pass() {
		if ($this->has_pass_cookie()) {
			return true;
		}

		if ($this->core) {
			$ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
			if (!empty($ip)) {
				$cached_ts = $this->core->fc_get("turnstile_pass:{$ip}");
				if ($cached_ts) {
					// Respect admin-triggered invalidation
					$invalidated_at = (int) get_option('baskerville_pass_invalidated_at', 0);
					if ($invalidated_at === 0 || (int) $cached_ts >= $invalidated_at) {
						return true;
					}
				}
			}
		}

		return false;
	}

	private function has_pass_cookie() {
		if (!isset($_COOKIE['baskerville_pass'])) {
			return false;
		}

		$pass_data = sanitize_text_field(wp_unslash($_COOKIE['baskerville_pass']));
		$parts     = explode('.', $pass_data);
		if (count($parts) !== 2) {
			$parts = explode(':', $pass_data);
			if (count($parts) !== 2) {
				return false;
			}
		}

		$timestamp = (int) $parts[0];
		$hash      = $parts[1];

		if (time() - $timestamp > 86400) {
			return false;
		}

		// Reject cookies issued before admin cleared the pass cache
		$invalidated_at = (int) get_option('baskerville_pass_invalidated_at', 0);
		if ($invalidated_at > 0 && $timestamp < $invalidated_at) {
			return false;
		}

		return hash_equals($this->generate_pass_hash($timestamp), $hash);
	}

	private function generate_pass_hash($timestamp) {
		$secret = get_option('baskerville_cookie_secret', 'default_secret');
		return hash_hmac('sha256', 'baskerville_pass.' . $timestamp, $secret);
	}

	private function set_pass_cookie() {
		$timestamp = time();
		$hash      = $this->generate_pass_hash($timestamp);
		$value     = $timestamp . '.' . $hash;

		setcookie('baskerville_pass', $value, array(
			'expires'  => time() + 86400,
			'path'     => '/',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		));

		$_COOKIE['baskerville_pass'] = $value;

		if ($this->core) {
			$ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
			if (!empty($ip)) {
				$this->core->fc_set("turnstile_pass:{$ip}", $timestamp, 86400);
			}
		}
	}

	// ── Redirect ─────────────────────────────────────────────────────────────

	public function redirect_to_challenge($return_url = null) {
		if ($return_url === null) {
			$return_url = (is_ssl() ? 'https://' : 'http://') .
				(isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '') .
				(isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/');
		}

		$this->log_challenge_event('redirect', null);

		$challenge_url = home_url('/') . '?baskerville_challenge=1&return=' . rawurlencode($return_url);

		if (!headers_sent()) {
			header('Vary: Cookie');
			header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
			header('Pragma: no-cache');
			header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
			header('X-Baskerville-Redirect: challenge');
			header('X-Accel-Expires: 0');
		}
		nocache_headers();

		wp_safe_redirect($challenge_url);
		exit;
	}

	// ── Challenge page ────────────────────────────────────────────────────────

	private function render_challenge_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$return_url = isset($_GET['return']) ? esc_url_raw(wp_unslash($_GET['return'])) : home_url('/');

		$return_host = wp_parse_url($return_url, PHP_URL_HOST);
		$site_host   = wp_parse_url(home_url(), PHP_URL_HOST);
		if ($return_host !== $site_host) {
			$return_url = home_url('/');
		}

		if (!headers_sent()) {
			header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
			header('Pragma: no-cache');
			header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
		}
		nocache_headers();

		$site_name          = get_bloginfo('name');
		$altcha_url         = home_url('/') . '?baskerville_altcha_challenge=1';
		$verify_url         = esc_url(home_url('/?baskerville_verify=1'));
		$return_url_escaped = esc_attr($return_url);
		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo('charset'); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<meta name="robots" content="noindex, nofollow">
			<title><?php echo esc_html__('Security Check', 'baskerville-ai-security') . ' - ' . esc_html($site_name); ?></title>
			<?php
			// type="module" is added by add_module_type() filter on the 'altcha-widget' handle
			wp_register_script('altcha-widget', plugins_url('assets/js/altcha.min.js', BASKERVILLE_PLUGIN_FILE), array(), BASKERVILLE_VERSION, false);
			wp_print_scripts('altcha-widget');
			wp_register_style('baskerville-challenge', plugins_url('assets/css/challenge.css', BASKERVILLE_PLUGIN_FILE), array(), BASKERVILLE_VERSION);
			wp_print_styles('baskerville-challenge');
			?>
		</head>
		<body>
			<div class="challenge-container">
				<div class="challenge-icon">🛡️</div>
				<h1><?php esc_html_e('Security Check', 'baskerville-ai-security'); ?></h1>
				<p><?php esc_html_e('Please complete this security check to continue to the website. This helps us prevent automated access.', 'baskerville-ai-security'); ?></p>

				<div id="error-message" class="error-message"></div>

				<form method="POST" action="<?php echo esc_url($verify_url); ?>" id="challenge-form">
					<input type="hidden" name="return" value="<?php echo $return_url_escaped; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already escaped above ?>">
					<?php wp_nonce_field('baskerville_challenge', 'baskerville_nonce'); ?>

					<div class="altcha-wrapper">
						<altcha-widget
							challengeurl="<?php echo esc_url($altcha_url); ?>"
							name="altcha"
							auto="onload"
						></altcha-widget>
					</div>
				</form>

				<p class="site-name"><?php echo esc_html($site_name); ?></p>
			</div>

			<script>
			(function() {
				var w = document.querySelector('altcha-widget');
				if (!w) return;

				function submitVerification(payload) {
					var form = document.getElementById('challenge-form');
					if (!form) return;
					var fd = new FormData(form);
					// payload is the base64 proof-of-work string from the Altcha widget.
					// We set it explicitly because form-associated custom element values
					// are not reliably included in FormData across all browsers.
					if (payload) {
						fd.set('altcha', payload);
					}
					fetch(form.action, {
						method: 'POST',
						body: fd,
						credentials: 'same-origin',
						headers: { 'X-Requested-With': 'XMLHttpRequest' }
					}).then(function(r) {
						if (r.ok) {
							window.location.replace(<?php echo wp_json_encode(esc_url_raw($return_url)); ?>);
						} else {
							var el = document.getElementById('error-message');
							el.textContent = <?php echo wp_json_encode(__('Verification failed. Please refresh and try again.', 'baskerville-ai-security')); ?>;
							el.style.display = 'block';
						}
					}).catch(function() { form.submit(); });
				}

				w.addEventListener('statechange', function(ev) {
					if (!ev.detail || ev.detail.state !== 'verified') return;
					submitVerification(ev.detail.payload);
				});

				// If the module was cached and fired statechange before our listener was
				// attached, check if the widget is already in verified state.
				if (w.state === 'verified') {
					submitVerification(w.value || '');
				}
			})();
			</script>
		</body>
		</html>
		<?php
	}

	// ── Verify endpoint ───────────────────────────────────────────────────────

	private function handle_verify() {
		if (!isset($_POST['baskerville_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['baskerville_nonce'])), 'baskerville_challenge')) {
			$this->log_challenge_event('fail', 'invalid_nonce');
			wp_die(
				esc_html__('Security check failed. Please try again.', 'baskerville-ai-security'),
				esc_html__('Error', 'baskerville-ai-security'),
				array('response' => 403)
			);
		}

		$altcha = isset($_POST['altcha']) ? sanitize_text_field(wp_unslash($_POST['altcha'])) : '';

		if (!$this->verify_altcha_payload($altcha)) {
			$this->log_challenge_event('fail', 'invalid_payload');
			$return_url_raw = isset($_POST['return']) ? esc_url_raw(wp_unslash($_POST['return'])) : home_url('/');
			wp_die(
				esc_html__('Security check failed. Please try again.', 'baskerville-ai-security')
				. '<br><br><a href="' . esc_url(home_url('/?baskerville_challenge=1&return=' . rawurlencode($return_url_raw))) . '">'
				. esc_html__('Try again', 'baskerville-ai-security') . '</a>',
				esc_html__('Verification Failed', 'baskerville-ai-security'),
				array('response' => 403)
			);
		}

		$return_url  = isset($_POST['return']) ? esc_url_raw(wp_unslash($_POST['return'])) : home_url('/');
		$return_host = wp_parse_url($return_url, PHP_URL_HOST);
		$site_host   = wp_parse_url(home_url(), PHP_URL_HOST);
		if ($return_host !== $site_host) {
			$return_url = home_url('/');
		}

		$this->set_pass_cookie();
		$this->log_challenge_event('pass', null);

		if (!headers_sent()) {
			header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
			header('Pragma: no-cache');
			header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
		}
		nocache_headers();

		while (ob_get_level()) {
			ob_end_clean();
		}

		$safe_url = esc_url($return_url);
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<meta http-equiv="refresh" content="0;url=<?php echo esc_attr($safe_url); ?>">
		</head>
		<body>
			<?php
			wp_register_script('baskerville-redirect', false, array(), BASKERVILLE_VERSION, false); // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
			wp_add_inline_script('baskerville-redirect', 'window.location.replace(' . wp_json_encode($safe_url) . ');');
			wp_print_scripts('baskerville-redirect');
			?>
		</body>
		</html>
		<?php
		exit;
	}

	// ── Form widgets ──────────────────────────────────────────────────────────

	public function render_altcha_widget() {
		$altcha_url = home_url('/') . '?baskerville_altcha_challenge=1';
		?>
		<div class="altcha-wrapper">
			<altcha-widget
				challengeurl="<?php echo esc_url($altcha_url); ?>"
				name="altcha"
				auto="onload"
			></altcha-widget>
		</div>
		<noscript>
			<p class="baskerville-noscript-warning"><?php esc_html_e('Please enable JavaScript to complete the security check.', 'baskerville-ai-security'); ?></p>
		</noscript>
		<?php
	}

	public function enqueue_altcha_script() {
		wp_enqueue_script('altcha-widget', plugins_url('assets/js/altcha.min.js', BASKERVILLE_PLUGIN_FILE), array(), BASKERVILLE_VERSION, true);
	}

	public function maybe_enqueue_frontend_script() {
		if (is_singular() && comments_open()) {
			wp_enqueue_script('altcha-widget', plugins_url('assets/js/altcha.min.js', BASKERVILLE_PLUGIN_FILE), array(), BASKERVILLE_VERSION, true);
		}
	}

	/**
	 * Add type="module" to the Altcha script tag.
	 * altcha.min.js is an ES module — without this attribute the browser throws
	 * a SyntaxError and the <altcha-widget> custom element is never defined.
	 */
	public function add_module_type($tag, $handle) {
		if ($handle === 'altcha-widget') {
			return str_replace('<script ', '<script type="module" ', $tag);
		}
		return $tag;
	}

	// ── Form verification ─────────────────────────────────────────────────────

	public function verify_login($user, $username, $password) {
		if (is_wp_error($user) || empty($username)) {
			return $user;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$altcha = isset($_POST['altcha']) ? sanitize_text_field(wp_unslash($_POST['altcha'])) : '';
		if (!$this->verify_altcha_payload($altcha)) {
			$this->log_login_event('fail', 'login');
			return new WP_Error('altcha_failed', __('Please complete the security check.', 'baskerville-ai-security'));
		}
		$this->log_login_event('pass', 'login');
		return $user;
	}

	public function verify_registration($errors, $sanitized_user_login, $user_email) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$altcha = isset($_POST['altcha']) ? sanitize_text_field(wp_unslash($_POST['altcha'])) : '';
		if (!$this->verify_altcha_payload($altcha)) {
			$this->log_login_event('fail', 'register');
			$errors->add('altcha_error', __('Please complete the security check.', 'baskerville-ai-security'));
		} else {
			$this->log_login_event('pass', 'register');
		}
		return $errors;
	}

	public function verify_comment($commentdata) {
		if (current_user_can('manage_options')) {
			return $commentdata;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$altcha = isset($_POST['altcha']) ? sanitize_text_field(wp_unslash($_POST['altcha'])) : '';
		if (!$this->verify_altcha_payload($altcha)) {
			$this->log_login_event('fail', 'comment');
			wp_die(
				esc_html__('Please complete the security check.', 'baskerville-ai-security'),
				esc_html__('Comment Submission Failed', 'baskerville-ai-security'),
				array('back_link' => true)
			);
		}
		$this->log_login_event('pass', 'comment');
		return $commentdata;
	}

	// ── Event logging ─────────────────────────────────────────────────────────

	/**
	 * Log Altcha challenge event to database.
	 * Event types: ac_redir, ac_pass, ac_fail  (mirrors Turnstile's ts_* events)
	 *
	 * @param string      $result 'redirect', 'pass', or 'fail'
	 * @param string|null $reason Failure reason if applicable
	 */
	private function log_challenge_event($result, $reason) {
		global $wpdb;

		$ip             = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
		$baskerville_id = isset($_COOKIE['baskerville_id']) ? substr(sanitize_text_field(wp_unslash($_COOKIE['baskerville_id'])), 0, 100) : '';
		$user_agent     = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

		$short_result = ($result === 'redirect') ? 'redir' : $result; // redir/pass/fail
		$event_type   = 'ac_' . $short_result;                        // ac_redir, ac_pass, ac_fail

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
				'classification'        => 'altcha',
				'had_fp'                => !empty($baskerville_id) ? 1 : 0,
				'evaluation_json'       => '{}',
				'score_reasons'         => '',
				'classification_reason' => 'altcha_challenge',
			),
			array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s', '%s')
		);
	}

	/**
	 * Log a login/registration/comment form Altcha event.
	 * Event types: lf_pass, lf_fail
	 *
	 * @param string $result    'pass' or 'fail'
	 * @param string $form_type 'login', 'register', or 'comment'
	 */
	private function log_login_event($result, $form_type) {
		global $wpdb;

		$ip             = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
		$baskerville_id = isset($_COOKIE['baskerville_id']) ? substr(sanitize_text_field(wp_unslash($_COOKIE['baskerville_id'])), 0, 100) : '';
		$user_agent     = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
		$country_code   = ($this->core && !empty($ip)) ? $this->core->get_country_by_ip($ip) : null;

		$table_name = $wpdb->prefix . 'baskerville_stats';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$table_name,
			array(
				'visit_key'             => wp_generate_uuid4(),
				'ip'                    => $ip,
				'baskerville_id'        => $baskerville_id,
				'timestamp_utc'         => current_time('mysql', true),
				'event_type'            => 'lf_' . $result,
				'block_reason'          => null,
				'user_agent'            => $user_agent,
				'score'                 => 0,
				'classification'        => 'login_form',
				'country_code'          => $country_code,
				'had_fp'                => !empty($baskerville_id) ? 1 : 0,
				'evaluation_json'       => '{}',
				'score_reasons'         => '',
				'classification_reason' => $form_type,
			),
			array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s')
		);
	}
}
