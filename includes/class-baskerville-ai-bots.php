<?php
/**
 * Known bot User-Agent map.
 *
 * Five categories: ai_training, search_engines, seo_tools, social, security.
 * Used to annotate snapshot histograms (known_bots_json, ai_traffic_json)
 * and enrich LLM payloads with named company attribution.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Baskerville_AI_Bots {

	/**
	 * category → company → [UA patterns (case-insensitive substring match)]
	 *
	 * @return array<string, array<string, string[]>>
	 */
	private static function map(): array {
		return [
			'ai_training' => [
				'OpenAI'       => [ 'GPTBot', 'ChatGPT-User', 'OAI-SearchBot' ],
				'Anthropic'    => [ 'ClaudeBot', 'Claude-Web' ],
				'Google AI'    => [ 'Google-Extended', 'GoogleOther' ],
				'Gemini'       => [ 'Gemini' ],
				'ByteDance'    => [ 'Bytespider' ],
				'Perplexity'   => [ 'PerplexityBot' ],
				'Common Crawl' => [ 'CCBot' ],
				'Amazon'       => [ 'Amazonbot' ],
				'Meta AI'      => [ 'Meta-ExternalAgent' ],
				'Apple'        => [ 'Applebot-Extended' ],
				'Cohere'       => [ 'cohere-ai' ],
				'Diffbot'      => [ 'Diffbot' ],
			],
			'search_engines' => [
				'Google'     => [ 'Googlebot' ],
				'Bing'       => [ 'bingbot' ],
				'Yahoo'      => [ 'Slurp' ],
				'Yandex'     => [ 'YandexBot' ],
				'DuckDuckGo' => [ 'DuckDuckBot' ],
				'Baidu'      => [ 'Baiduspider' ],
			],
			'seo_tools' => [
				'Ahrefs'     => [ 'AhrefsBot' ],
				'Semrush'    => [ 'SemrushBot' ],
				'Majestic'   => [ 'MJ12bot' ],
				'Moz'        => [ 'DotBot' ],
				'DataForSEO' => [ 'DataForSeoBot' ],
			],
			'social' => [
				'Meta'      => [ 'facebookexternalhit', 'FacebookBot' ],
				'Twitter/X' => [ 'Twitterbot' ],
				'LinkedIn'  => [ 'LinkedInBot' ],
				'Telegram'  => [ 'TelegramBot' ],
			],
			'security' => [
				'Shodan'  => [ 'Shodan' ],
				'Censys'  => [ 'censys' ],
				'masscan' => [ 'masscan' ],
			],
		];
	}

	/**
	 * Match a UA string against all known bot patterns.
	 *
	 * @return array{category: string, company: string}|null
	 */
	public static function match( string $ua ): ?array {
		if ( empty( $ua ) ) {
			return null;
		}
		foreach ( self::map() as $category => $companies ) {
			foreach ( $companies as $company => $patterns ) {
				foreach ( $patterns as $pattern ) {
					if ( stripos( $ua, $pattern ) !== false ) {
						return [ 'category' => $category, 'company' => $company ];
					}
				}
			}
		}
		return null;
	}

	/**
	 * Given a list of {k: user_agent, v: count} rows, build:
	 *   - $known_bots: category → company → total count
	 *   - $ai_traffic: company → total count (ai_training only, flat)
	 *
	 * @param  array[] $ua_rows  DB rows with keys 'k' (UA string) and 'v' (count).
	 * @return array{ known_bots: array, ai_traffic: array }
	 */
	public static function aggregate( array $ua_rows ): array {
		$known_bots = [];
		$ai_traffic = [];

		foreach ( $ua_rows as $row ) {
			$match = self::match( (string) $row['k'] );
			if ( ! $match ) {
				continue;
			}
			$cat     = $match['category'];
			$company = $match['company'];
			$cnt     = (int) $row['v'];

			$known_bots[ $cat ][ $company ] = ( $known_bots[ $cat ][ $company ] ?? 0 ) + $cnt;

			if ( $cat === 'ai_training' ) {
				$ai_traffic[ $company ] = ( $ai_traffic[ $company ] ?? 0 ) + $cnt;
			}
		}

		// Sort each category by count descending.
		foreach ( $known_bots as &$companies ) {
			arsort( $companies );
		}
		unset( $companies );
		arsort( $ai_traffic );

		return [
			'known_bots' => $known_bots,
			'ai_traffic' => $ai_traffic,
		];
	}
}
