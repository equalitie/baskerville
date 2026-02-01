<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Automatic installer for MaxMind GeoIP2 PHP library
 * Downloads and installs the library without requiring composer
 */
class Baskerville_MaxMind_Installer {

	private $vendor_dir;
	private $zip_url = 'https://github.com/maxmind/GeoIP2-php/archive/refs/tags/v2.13.0.zip';
	private $composer_data_url = 'https://github.com/maxmind/MaxMind-DB-Reader-php/archive/refs/tags/v1.11.1.zip';

	public function __construct() {
		$this->vendor_dir = BASKERVILLE_PLUGIN_PATH . 'vendor/';
	}

	/**
	 * Check if MaxMind library is installed
	 */
	public function is_installed() {
		return file_exists($this->vendor_dir . 'autoload.php') &&
			   class_exists('GeoIp2\Database\Reader');
	}

	/**
	 * Install MaxMind library automatically
	 * @return array Status with success/error message
	 */
	public function install() {
		$errors = array();

		// Check if ZipArchive or PclZip is available
		if (!class_exists('ZipArchive') && !class_exists('PclZip')) {
			// Try to load PclZip from WordPress
			if (file_exists(ABSPATH . 'wp-admin/includes/class-pclzip.php')) {
				require_once ABSPATH . 'wp-admin/includes/class-pclzip.php';
			}
		}

		if (!class_exists('ZipArchive') && !class_exists('PclZip')) {
			return array(
				'success' => false,
				'message' => esc_html__('Neither ZipArchive nor PclZip available. Please contact your hosting provider.', 'baskerville'),
				'errors' => array( esc_html__( 'No zip handler available', 'baskerville' ) )
			);
		}

		// Check if we can write to plugin directory
		if (!wp_is_writable(BASKERVILLE_PLUGIN_PATH)) {
			return array(
				'success' => false,
				/* translators: %s: plugin directory path */
				'message' => sprintf( esc_html__('Plugin directory is not writable. Path: %1$s. Please check file permissions.', 'baskerville'), BASKERVILLE_PLUGIN_PATH ),
				'errors' => array( sprintf( esc_html__('Directory not writable: ', 'baskerville'), BASKERVILLE_PLUGIN_PATH ) )
			);
		}

		// Create vendor directory if it doesn't exist
		if (!is_dir($this->vendor_dir)) {
			if (!wp_mkdir_p($this->vendor_dir)) {
				return array(
					'success' => false,
					'message' => esc_html__( 'Failed to create vendor directory at:', 'baskerville' ) . ' ' . $this->vendor_dir,
					'errors' => array( esc_html__( 'mkdir failed', 'baskerville' ) )
				);
			}
		}

		try {
			// Step 1: Download and install MaxMind-DB-Reader (dependency)
			$result = $this->download_and_extract_db_reader();
			if (!$result['success']) {
				$result['errors'][] = esc_html__( 'Step 1 failed: DB-Reader', 'baskerville' );
				return $result;
			}

			// Step 2: Download and install GeoIP2
			$result = $this->download_and_extract_geoip2();
			if (!$result['success']) {
				$result['errors'][] = esc_html__( 'Step 2 failed: GeoIP2', 'baskerville' );
				return $result;
			}

			// Step 3: Create autoload.php
			$this->create_autoload();

			return array(
				'success' => true,
				'message' => esc_html__( 'MaxMind GeoIP2 library installed successfully!', 'baskerville' )
			);

		} catch (Exception $e) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Installation exception:', 'baskerville' ) . ' ' . $e->getMessage(),
				'errors' => array($e->getMessage()),
				'trace' => $e->getTraceAsString()
			);
		}
	}

	/**
	 * Download and extract MaxMind-DB-Reader library
	 */
	private function download_and_extract_db_reader() {
		$zip_file = $this->vendor_dir . 'maxmind-db-reader.zip';

		// Download
		$response = wp_remote_get($this->composer_data_url, array('timeout' => 60));
		if (is_wp_error($response)) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Failed to download MaxMind-DB-Reader:', 'baskerville' ) . ' ' . $response->get_error_message()
			);
		}

		$body = wp_remote_retrieve_body($response);
		if (empty($body)) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Downloaded MaxMind-DB-Reader file is empty.', 'baskerville' )
			);
		}

		// Save zip
		file_put_contents($zip_file, $body);

		// Extract
		$extract_to = $this->vendor_dir . 'maxmind-db-temp/';
		$extract_result = $this->extract_zip($zip_file, $extract_to);
		if (!$extract_result['success']) {
			return $extract_result;
		}

		// Move files to correct location
		$source_dir = $extract_to . 'MaxMind-DB-Reader-php-1.11.1/src/MaxMind/';
		$target_dir = $this->vendor_dir . 'maxmind/';

		if (is_dir($source_dir)) {
			$this->recursive_copy($source_dir, $target_dir);
		}

		// Cleanup
		wp_delete_file($zip_file);
		$this->recursive_delete($extract_to);

		return array('success' => true);
	}

	/**
	 * Download and extract GeoIP2 library
	 */
	private function download_and_extract_geoip2() {
		$zip_file = $this->vendor_dir . 'geoip2.zip';

		// Download
		$response = wp_remote_get($this->zip_url, array('timeout' => 60));
		if (is_wp_error($response)) {
			return array(
				'success' => false,
				'message' => esc_html__('Failed to download GeoIP2:', 'baskerville' ) . ' ' . $response->get_error_message()
			);
		}

		$body = wp_remote_retrieve_body($response);
		if (empty($body)) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Downloaded GeoIP2 file is empty.', 'baskerville' )
			);
		}

		// Save zip
		file_put_contents($zip_file, $body);

		// Extract
		$extract_to = $this->vendor_dir . 'geoip2-temp/';
		$extract_result = $this->extract_zip($zip_file, $extract_to);
		if (!$extract_result['success']) {
			return $extract_result;
		}

		// Move files to correct location
		$source_dir = $extract_to . 'GeoIP2-php-2.13.0/src/';
		$target_dir = $this->vendor_dir . 'geoip2/';

		if (is_dir($source_dir)) {
			$this->recursive_copy($source_dir, $target_dir);
		}

		// Cleanup
		wp_delete_file($zip_file);
		$this->recursive_delete($extract_to);

		return array('success' => true);
	}

	/**
	 * Extract zip file using ZipArchive or PclZip
	 */
	private function extract_zip($zip_file, $extract_to) {
		if (!is_dir($extract_to)) {
			wp_mkdir_p($extract_to);
		}

		// Try ZipArchive first
		if (class_exists('ZipArchive')) {
			$zip = new ZipArchive();
			if ($zip->open($zip_file) === true) {
				$zip->extractTo($extract_to);
				$zip->close();
				return array('success' => true);
			}
		}

		// Fallback to PclZip (included with WordPress)
		if (!class_exists('PclZip')) {
			if (file_exists(ABSPATH . 'wp-admin/includes/class-pclzip.php')) {
				require_once ABSPATH . 'wp-admin/includes/class-pclzip.php';
			}
		}

		if (class_exists('PclZip')) {
			$archive = new PclZip($zip_file);
			$result = $archive->extract(PCLZIP_OPT_PATH, $extract_to);
			if ($result !== 0) {
				return array('success' => true);
			}
			return array(
				'success' => false,
				'message' => esc_html__('PclZip extraction failed: ', 'baskerville') . $archive->errorInfo(true)
			);
		}

		return array(
			'success' => false,
			'message' => esc_html__('No zip extraction method available.', 'baskerville')
		);
	}

	/**
	 * Create autoload.php file
	 */
	private function create_autoload() {
		$autoload_content = "<?php\n"
			. "// Baskerville MaxMind GeoIP2 Autoloader\n\n"
			. "spl_autoload_register(function (\$class) {\n"
			. "    \$prefixes = array(\n"
			. "        'GeoIp2\\\\' => __DIR__ . '/geoip2/',\n"
			. "        'MaxMind\\\\' => __DIR__ . '/maxmind/',\n"
			. "    );\n\n"
			. "    foreach (\$prefixes as \$prefix => \$base_dir) {\n"
			. "        \$len = strlen(\$prefix);\n"
			. "        if (strncmp(\$prefix, \$class, \$len) !== 0) {\n"
			. "            continue;\n"
			. "        }\n\n"
			. "        \$relative_class = substr(\$class, \$len);\n"
			. "        \$file = \$base_dir . str_replace('\\\\', '/', \$relative_class) . '.php';\n\n"
			. "        if (file_exists(\$file)) {\n"
			. "            require \$file;\n"
			. "            return;\n"
			. "        }\n"
			. "    }\n"
			. "});\n";

		file_put_contents($this->vendor_dir . 'autoload.php', $autoload_content);
	}

	/**
	 * Recursive copy directory
	 */
	private function recursive_copy($src, $dst) {
		if (!is_dir($dst)) {
			wp_mkdir_p($dst);
		}

		$dir = opendir($src);
		while (($file = readdir($dir)) !== false) {
			if ($file != '.' && $file != '..') {
				if (is_dir($src . '/' . $file)) {
					$this->recursive_copy($src . '/' . $file, $dst . '/' . $file);
				} else {
					copy($src . '/' . $file, $dst . '/' . $file);
				}
			}
		}
		closedir($dir);
	}

	/**
	 * Recursive delete directory
	 */
	private function recursive_delete($dir) {
		if (!is_dir($dir)) {
			return;
		}

		global $wp_filesystem;
		if (!function_exists('WP_Filesystem')) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		WP_Filesystem();

		$wp_filesystem->rmdir($dir, true);
	}
}
