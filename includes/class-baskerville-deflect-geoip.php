<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Deflect GeoIP database handler
 * Uses deflect-ca/deflect-geoip database for IP to country lookups
 *
 * Database format:
 * - latest.json contains metadata about current release
 * - countrydb.csv.gz contains CIDR prefixes mapped to country codes
 */
class Baskerville_Deflect_GeoIP {

	/** Base URL for deflect-geoip releases */
	private const BASE_URL = 'https://deflect-ca.github.io/deflect-geoip';

	/** Option key for storing database version */
	private const VERSION_OPTION = 'baskerville_deflect_geoip_version';

	/** Option key for storing last update check time */
	private const LAST_CHECK_OPTION = 'baskerville_deflect_geoip_last_check';

	/** Database file path relative to wp-content/uploads */
	private const DB_FILE     = 'baskerville-geoip/countrydb.php';
	private const ASN_DB_FILE = 'baskerville-geoip/asndb.php';

	/** Cached database in memory */
	private static ?array $db_cache = null;

	/** Optimized lookup structures */
	private static ?array $ipv4_index = null;
	private static ?array $ipv6_index = null;

	/** ASN database cache: ['ipv4' => [[start, end, org], ...], 'ipv6' => [[start_bin, end_bin, org], ...]] */
	private static ?array $asn_cache = null;

	/**
	 * Check if deflect-geoip database is installed
	 * @return bool
	 */
	public function is_installed(): bool {
		$db_path = $this->get_db_path();
		return file_exists($db_path) && filesize($db_path) > 0;
	}

	/**
	 * Get database file path
	 * @return string
	 */
	public function get_db_path(): string {
		return WP_CONTENT_DIR . '/uploads/' . self::DB_FILE;
	}

	/**
	 * Get current installed version
	 * @return string|null
	 */
	public function get_version(): ?string {
		return get_option(self::VERSION_OPTION, null);
	}

	/**
	 * Check for updates and download if needed
	 * @param bool $force Force update check even if recently checked
	 * @return array{success: bool, message: string, updated?: bool}
	 */
	public function update(bool $force = false): array {
		// Check if we recently checked for updates (within 1 hour)
		$last_check = (int) get_option(self::LAST_CHECK_OPTION, 0);
		if (!$force && (time() - $last_check) < 3600) {
			return array(
				'success' => true,
				'message' => __('Update check skipped (recently checked)', 'baskerville-ai-security'),
				'updated' => false,
			);
		}

		// Fetch latest.json
		$latest_url = self::BASE_URL . '/releases/latest.json';
		$response = wp_remote_get($latest_url, array('timeout' => 30));

		if (is_wp_error($response)) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__('Failed to check for updates: %s', 'baskerville-ai-security'),
					$response->get_error_message()
				),
			);
		}

		$body = wp_remote_retrieve_body($response);
		$latest = json_decode($body, true);

		if (!$latest || empty($latest['version']) || empty($latest['artifacts'][0])) {
			return array(
				'success' => false,
				'message' => __('Invalid response from update server', 'baskerville-ai-security'),
			);
		}

		$version = $latest['version'];
		$sha256  = $latest['artifacts'][0]['sha256'] ?? '';

		// Find artifacts by type
		$country_artifact = null;
		$asn_artifact     = null;
		foreach ( $latest['artifacts'] as $artifact ) {
			if ( ( $artifact['type'] ?? '' ) === 'countrydb.csv.gz' ) {
				$country_artifact = $artifact;
			} elseif ( ( $artifact['type'] ?? '' ) === 'asndb.csv.gz' ) {
				$asn_artifact = $artifact;
			}
		}
		// Fallback: first artifact is countrydb (backward compat with old latest.json)
		if ( ! $country_artifact ) {
			$country_artifact = $latest['artifacts'][0];
		}
		$sha256 = $country_artifact['sha256'] ?? '';

		// Update last check time
		update_option(self::LAST_CHECK_OPTION, time());

		// Check if we already have this version
		$current_version = $this->get_version();
		if ($current_version === $version && $this->is_installed()) {
			return array(
				'success' => true,
				'message' => sprintf(
					/* translators: %s: version string */
					__('Already up to date (version %s)', 'baskerville-ai-security'),
					$version
				),
				'updated' => false,
			);
		}

		// Download countrydb
		$db_url = self::BASE_URL . '/' . $country_artifact['path'];
		$response = wp_remote_get($db_url, array('timeout' => 120));

		if (is_wp_error($response)) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__('Failed to download database: %s', 'baskerville-ai-security'),
					$response->get_error_message()
				),
			);
		}

		$gz_data = wp_remote_retrieve_body($response);

		// Verify SHA256
		if ($sha256 && hash('sha256', $gz_data) !== $sha256) {
			return array(
				'success' => false,
				'message' => __('SHA256 checksum mismatch - download may be corrupted', 'baskerville-ai-security'),
			);
		}

		// Decompress
		$csv_data = @gzdecode($gz_data);
		if ($csv_data === false) {
			return array(
				'success' => false,
				'message' => __('Failed to decompress database', 'baskerville-ai-security'),
			);
		}

		// Parse CSV and build optimized lookup structure
		$result = $this->parse_and_save_db($csv_data, $version);
		if (!$result['success']) {
			return $result;
		}

		// Download and parse asndb (non-fatal if missing)
		if ( $asn_artifact ) {
			$asn_url      = self::BASE_URL . '/' . $asn_artifact['path'];
			$asn_response = wp_remote_get( $asn_url, array( 'timeout' => 120 ) );
			if ( ! is_wp_error( $asn_response ) ) {
				$asn_gz  = wp_remote_retrieve_body( $asn_response );
				$asn_csv = @gzdecode( $asn_gz );
				if ( $asn_csv !== false ) {
					$this->parse_and_save_asn_db( $asn_csv, $version );
				}
			}
		}

		// Update version
		update_option(self::VERSION_OPTION, $version);

		// Clear memory cache
		self::$db_cache  = null;
		self::$ipv4_index = null;
		self::$ipv6_index = null;
		self::$asn_cache  = null;

		return array(
			'success' => true,
			'message' => sprintf(
				/* translators: %s: version string */
				__('Database updated to version %s', 'baskerville-ai-security'),
				$version
			),
			'updated' => true,
		);
	}

	/**
	 * Parse CSV data and save as optimized PHP array
	 * @param string $csv_data Raw CSV content
	 * @param string $version Version string
	 * @return array{success: bool, message: string}
	 */
	private function parse_and_save_db(string $csv_data, string $version): array {
		$lines = explode("\n", $csv_data);

		// Remove header
		if (!empty($lines) && strpos($lines[0], 'prefix') !== false) {
			array_shift($lines);
		}

		$ipv4_prefixes = array();
		$ipv6_prefixes = array();

		foreach ($lines as $line) {
			$line = trim($line);
			if (empty($line)) continue;

			$parts = explode(',', $line, 2);
			if (count($parts) !== 2) continue;

			$prefix = trim($parts[0]);
			$country = strtoupper(trim($parts[1]));

			if (strlen($country) !== 2) continue;

			// Separate IPv4 and IPv6
			if (strpos($prefix, ':') !== false) {
				$ipv6_prefixes[$prefix] = $country;
			} else {
				$ipv4_prefixes[$prefix] = $country;
			}
		}

		// Sort by prefix length (longer prefixes first for most specific match)
		$ipv4_sorted = $this->sort_by_prefix_length($ipv4_prefixes);
		$ipv6_sorted = $this->sort_by_prefix_length($ipv6_prefixes);

		// Build indexed structure for faster lookup
		$ipv4_index = $this->build_ipv4_index($ipv4_sorted);

		// Save as PHP file for fast loading
		$db_path = $this->get_db_path();
		$db_dir = dirname($db_path);

		// Create directory if it doesn't exist
		if (!is_dir($db_dir)) {
			if (!wp_mkdir_p($db_dir)) {
				return array(
					'success' => false,
					'message' => sprintf(
						/* translators: %s: directory path */
						__('Failed to create directory: %s', 'baskerville-ai-security'),
						$db_dir
					),
				);
			}
		}

		// Check if directory is writable
		if (!wp_is_writable($db_dir)) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: directory path */
					__('Directory not writable: %s. Please check permissions (chmod 755).', 'baskerville-ai-security'),
					$db_dir
				),
			);
		}

		$data = array(
			'version' => $version,
			'generated' => time(),
			'ipv4_index' => $ipv4_index,
			'ipv4' => $ipv4_sorted,
			'ipv6' => $ipv6_sorted,
			'stats' => array(
				'ipv4_count' => count($ipv4_sorted),
				'ipv6_count' => count($ipv6_sorted),
			),
		);

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- var_export used to generate a PHP data file, not for debugging.
		$php_content = "<?php\n// Deflect GeoIP Database - Auto-generated\n// Version: {$version}\n// DO NOT EDIT\nreturn " . var_export($data, true) . ";\n";

		// Try to write using WordPress filesystem
		global $wp_filesystem;
		if (!function_exists('WP_Filesystem')) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		// Initialize filesystem
		if (!WP_Filesystem()) {
			// Fallback to direct file write
			$result = @file_put_contents($db_path, $php_content, LOCK_EX);
			if ($result === false) {
				$error_info = error_get_last();
				return array(
					'success' => false,
					'message' => sprintf(
						/* translators: %1$s: file path, %2$s: error message */
						__('Failed to save database to: %1$s. Error: %2$s', 'baskerville-ai-security'),
						$db_path,
						$error_info['message'] ?? 'Unknown error'
					),
				);
			}
		} else {
			// Use WordPress filesystem
			$result = $wp_filesystem->put_contents($db_path, $php_content, FS_CHMOD_FILE);
			if (!$result) {
				// Fallback to direct write
				$result = @file_put_contents($db_path, $php_content, LOCK_EX);
				if ($result === false) {
					return array(
						'success' => false,
						'message' => sprintf(
							/* translators: %s: file path */
							__('Failed to save database to: %s. Check file permissions.', 'baskerville-ai-security'),
							$db_path
						),
					);
				}
			}
		}

		return array(
			'success' => true,
			'message' => sprintf(
				/* translators: 1: IPv4 count, 2: IPv6 count */
				__('Parsed %1$d IPv4 and %2$d IPv6 prefixes', 'baskerville-ai-security'),
				count($ipv4_sorted),
				count($ipv6_sorted)
			),
		);
	}

	/**
	 * Sort prefixes by prefix length (longer first)
	 * @param array $prefixes
	 * @return array
	 */
	private function sort_by_prefix_length(array $prefixes): array {
		uksort($prefixes, function($a, $b) {
			$bits_a = (int) explode('/', $a)[1];
			$bits_b = (int) explode('/', $b)[1];
			return $bits_b - $bits_a; // Longer prefix first
		});
		return $prefixes;
	}

	/**
	 * Build index by first octet for fast IPv4 lookup
	 * @param array $prefixes
	 * @return array
	 */
	private function build_ipv4_index(array $prefixes): array {
		$index = array();
		foreach ($prefixes as $prefix => $country) {
			$first_octet = (int) explode('.', $prefix)[0];
			if (!isset($index[$first_octet])) {
				$index[$first_octet] = array();
			}
			$index[$first_octet][$prefix] = $country;
		}
		return $index;
	}

	/**
	 * Load database into memory
	 * @return bool
	 */
	private function load_db(): bool {
		if (self::$db_cache !== null) {
			return true;
		}

		$db_path = $this->get_db_path();
		if (!file_exists($db_path)) {
			return false;
		}

		$data = include $db_path;
		if (!is_array($data)) {
			return false;
		}

		self::$db_cache = $data;
		self::$ipv4_index = $data['ipv4_index'] ?? array();
		self::$ipv6_index = $data['ipv6'] ?? array();

		return true;
	}

	/**
	 * Lookup country by IP address
	 * @param string $ip IPv4 or IPv6 address
	 * @return string|null Two-letter country code or null if not found
	 */
	public function lookup(string $ip): ?string {
		if (!$this->load_db()) {
			return null;
		}

		// IPv4
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			return $this->lookup_ipv4($ip);
		}

		// IPv6
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			return $this->lookup_ipv6($ip);
		}

		return null;
	}

	/**
	 * Lookup IPv4 address using indexed structure
	 * @param string $ip
	 * @return string|null
	 */
	private function lookup_ipv4(string $ip): ?string {
		$ip_long = ip2long($ip);
		if ($ip_long === false) {
			return null;
		}

		$first_octet = (int) explode('.', $ip)[0];

		// Check indexed prefixes for this first octet
		if (isset(self::$ipv4_index[$first_octet])) {
			foreach (self::$ipv4_index[$first_octet] as $prefix => $country) {
				if ($this->ip_in_cidr_v4($ip_long, $prefix)) {
					return $country;
				}
			}
		}

		// Fallback: check 0.0.0.0/0 type prefixes if any
		if (isset(self::$ipv4_index[0])) {
			foreach (self::$ipv4_index[0] as $prefix => $country) {
				if ($this->ip_in_cidr_v4($ip_long, $prefix)) {
					return $country;
				}
			}
		}

		return null;
	}

	/**
	 * Check if IPv4 long matches CIDR
	 * @param int $ip_long
	 * @param string $cidr
	 * @return bool
	 */
	private function ip_in_cidr_v4(int $ip_long, string $cidr): bool {
		$parts = explode('/', $cidr);
		$subnet = ip2long($parts[0]);
		$bits = (int) ($parts[1] ?? 32);

		if ($subnet === false || $bits < 0 || $bits > 32) {
			return false;
		}

		$mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
		return ($ip_long & $mask) === ($subnet & $mask);
	}

	/**
	 * Lookup IPv6 address
	 * @param string $ip
	 * @return string|null
	 */
	private function lookup_ipv6(string $ip): ?string {
		$ip_bin = @inet_pton($ip);
		if ($ip_bin === false) {
			return null;
		}

		foreach (self::$ipv6_index as $prefix => $country) {
			if ($this->ip_in_cidr_v6($ip_bin, $prefix)) {
				return $country;
			}
		}

		return null;
	}

	/**
	 * Check if IPv6 binary matches CIDR
	 * @param string $ip_bin Binary representation of IP
	 * @param string $cidr
	 * @return bool
	 */
	private function ip_in_cidr_v6(string $ip_bin, string $cidr): bool {
		$parts = explode('/', $cidr);
		$subnet_bin = @inet_pton($parts[0]);
		$bits = (int) ($parts[1] ?? 128);

		if ($subnet_bin === false || $bits < 0 || $bits > 128) {
			return false;
		}

		// Build mask
		$mask = str_repeat("\xff", intdiv($bits, 8));
		$remaining_bits = $bits % 8;
		if ($remaining_bits > 0) {
			$mask .= chr(0xff << (8 - $remaining_bits));
		}
		$mask = str_pad($mask, 16, "\x00");

		return ($ip_bin & $mask) === ($subnet_bin & $mask);
	}

	/**
	 * Get database statistics
	 * @return array
	 */
	public function get_stats(): array {
		if (!$this->load_db()) {
			return array(
				'installed' => false,
				'version' => null,
				'ipv4_count' => 0,
				'ipv6_count' => 0,
			);
		}

		return array(
			'installed' => true,
			'version' => self::$db_cache['version'] ?? null,
			'generated' => self::$db_cache['generated'] ?? null,
			'ipv4_count' => self::$db_cache['stats']['ipv4_count'] ?? 0,
			'ipv6_count' => self::$db_cache['stats']['ipv6_count'] ?? 0,
		);
	}

	/**
	 * Test database with sample IPs
	 * @return array
	 */
	public function test(): array {
		$test_ips = array(
			'8.8.8.8' => 'US',       // Google DNS
			'1.1.1.1' => 'AU',       // Cloudflare (APNIC)
			'185.60.216.35' => null, // Variable
			'2001:4860:4860::8888' => 'US', // Google IPv6 DNS
		);

		$results = array();
		foreach ($test_ips as $ip => $expected) {
			$actual = $this->lookup($ip);
			$results[$ip] = array(
				'expected' => $expected,
				'actual' => $actual,
				'match' => $expected === null || $actual === $expected,
			);
		}

		return $results;
	}

	/**
	 * Parse asndb CSV and save as PHP file.
	 * Format: range_start,range_end,asn,org
	 */
	private function parse_and_save_asn_db( string $csv_data, string $version ): bool {
		$lines  = explode( "\n", $csv_data );
		$ipv4   = []; // [[start_long, end_long, org_string], ...]
		$ipv6   = []; // [[start_bin, end_bin, org_string], ...]

		// Skip header
		if ( ! empty( $lines ) && strpos( $lines[0], 'range_start' ) !== false ) {
			array_shift( $lines );
		}

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( empty( $line ) ) continue;

			$parts = explode( ',', $line, 4 );
			if ( count( $parts ) < 4 ) continue;

			[ $start, $end, $asn, $org ] = $parts;
			$org = trim( $org );
			$label = $org . ' (AS' . trim( $asn ) . ')';

			if ( strpos( $start, ':' ) !== false ) {
				// IPv6
				$s = @inet_pton( trim( $start ) );
				$e = @inet_pton( trim( $end ) );
				if ( $s !== false && $e !== false ) {
					$ipv6[] = [ $s, $e, $label ];
				}
			} else {
				// IPv4
				$s = ip2long( trim( $start ) );
				$e = ip2long( trim( $end ) );
				if ( $s !== false && $e !== false && $s >= 0 && $e >= 0 ) {
					$ipv4[] = [ $s, $e, $label ];
				}
			}
		}

		// Sort by start (for binary search)
		usort( $ipv4, fn( $a, $b ) => $a[0] <=> $b[0] );

		$db_path = WP_CONTENT_DIR . '/uploads/' . self::ASN_DB_FILE;
		$db_dir  = dirname( $db_path );
		if ( ! is_dir( $db_dir ) ) {
			wp_mkdir_p( $db_dir );
		}

		$data = [ 'version' => $version, 'ipv4' => $ipv4, 'ipv6' => $ipv6 ];
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
		$php_content = "<?php\n// Deflect ASN Database - Auto-generated\nreturn " . var_export( $data, true ) . ";\n";
		return @file_put_contents( $db_path, $php_content, LOCK_EX ) !== false;
	}

	/**
	 * Load ASN database into memory.
	 */
	private function load_asn_db(): bool {
		if ( self::$asn_cache !== null ) return true;
		$db_path = WP_CONTENT_DIR . '/uploads/' . self::ASN_DB_FILE;
		if ( ! file_exists( $db_path ) ) return false;
		$data = include $db_path;
		if ( ! is_array( $data ) ) return false;
		self::$asn_cache = $data;
		return true;
	}

	/**
	 * Lookup ASN org string for an IP address.
	 * Returns e.g. "CLOUDFLARENET (AS13335)" or null.
	 */
	public function lookup_asn( string $ip ): ?string {
		if ( ! $this->load_asn_db() ) return null;

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$long   = ip2long( $ip );
			$ranges = self::$asn_cache['ipv4'] ?? [];
			// Binary search for the range containing $long
			$lo = 0; $hi = count( $ranges ) - 1;
			while ( $lo <= $hi ) {
				$mid = intdiv( $lo + $hi, 2 );
				if ( $long < $ranges[ $mid ][0] ) {
					$hi = $mid - 1;
				} elseif ( $long > $ranges[ $mid ][1] ) {
					$lo = $mid + 1;
				} else {
					return $ranges[ $mid ][2];
				}
			}
			return null;
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$bin    = @inet_pton( $ip );
			if ( $bin === false ) return null;
			foreach ( self::$asn_cache['ipv6'] ?? [] as [ $s, $e, $org ] ) {
				if ( strcmp( $bin, $s ) >= 0 && strcmp( $bin, $e ) <= 0 ) {
					return $org;
				}
			}
		}

		return null;
	}

	/**
	 * Delete database and reset
	 * @return bool
	 */
	public function delete(): bool {
		$db_path = $this->get_db_path();
		if (file_exists($db_path)) {
			wp_delete_file($db_path);
		}

		delete_option(self::VERSION_OPTION);
		delete_option(self::LAST_CHECK_OPTION);

		self::$db_cache  = null;
		self::$ipv4_index = null;
		self::$ipv6_index = null;
		self::$asn_cache  = null;

		$asn_path = WP_CONTENT_DIR . '/uploads/' . self::ASN_DB_FILE;
		if ( file_exists( $asn_path ) ) {
			wp_delete_file( $asn_path );
		}

		return true;
	}
}
