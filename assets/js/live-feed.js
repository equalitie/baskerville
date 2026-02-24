jQuery(document).ready(function($) {
	var i18n = baskervilleAdmin.i18n;

	if ($('#live-feed-items').length === 0) {
		return;
	}

	function updateLiveFeed() {
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: { action: 'baskerville_get_live_feed' },
			success: function(response) {
				if (response.success && response.data) {
					renderLiveFeed(response.data);
				}
			}
		});
	}

	function updateLiveStats() {
		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: { action: 'baskerville_get_live_stats' },
			success: function(response) {
				if (response.success && response.data) {
					$('#blocks-today').text(response.data.blocks_today.toLocaleString());
					$('#blocks-hour').text(response.data.blocks_hour.toLocaleString());

					if (response.data.top_countries && response.data.top_countries.length > 0) {
						$('#top-country').text(response.data.top_countries[0].country_name || response.data.top_countries[0].country_code || 'N/A');
					}

					renderTopAttackers(response.data.top_ips);
				}
			}
		});
	}

	function renderLiveFeed(events) {
		var container = $('#live-feed-items');
		container.empty();

		if (!events || events.length === 0) {
			container.html('<div class="baskerville-no-data">' + i18n.noRecentEvents + '</div>');
			return;
		}

		events.forEach(function(event) {
			var icon = getEventIcon(event.classification, event.event_type);
			var color = getEventColor(event.classification, event.event_type);
			var timeAgo = getTimeAgo(event.created_at);
			var isTurnstileFail = event.event_type === 'ts_fail';
			var displayLabel = isTurnstileFail ? i18n.turnstileFailed : event.classification.toUpperCase().replace('_', ' ');

			var banBadge = '';
			if (isTurnstileFail) {
				banBadge = '<span class="baskerville-badge baskerville-badge-challenge-failed">' + i18n.challengeFailed + '</span>';
			} else if (event.is_banned) {
				banBadge = '<span class="baskerville-badge baskerville-badge-banned">' + i18n.banned + '</span>';
			} else {
				banBadge = '<span class="baskerville-badge baskerville-badge-detected">' + i18n.detected + '</span>';
			}

			var companyBadge = '';
			if (event.classification === 'ai_bot') {
				var companyName = null;
				var reasonMatch = event.reason && event.reason.match(/\(([^)]+)\)$/);
				if (reasonMatch) {
					companyName = reasonMatch[1];
				}
				if (!companyName && event.block_reason) {
					var blockMatch = event.block_reason.match(/:([^:]+)$/);
					if (blockMatch) {
						companyName = blockMatch[1];
					}
				}
				if (companyName) {
					companyBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-company">' + companyName + '</span>';
				} else if (event.event_type === 'honeypot') {
					companyBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-unknown">' + i18n.unknownBot + '</span>';
				}
			}

			var detectionBadge = '';
			var userAgentInfo = '';
			var isUserAgentBased = event.reason && (
				event.reason.toLowerCase().includes('user agent') ||
				event.reason.toLowerCase().includes('user-agent')
			);

			var truncatedUA;
			if (isTurnstileFail) {
				detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-turnstile">' + i18n.turnstile + '</span>';
				if (event.ua) {
					truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
					userAgentInfo = '<br><span class="baskerville-feed-ua">' + i18n.ua + ' ' + truncatedUA + '</span>';
				}
			} else if (event.classification === 'ai_bot') {
				if (event.event_type === 'honeypot') {
					detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-honeypot">' + i18n.honeypot + '</span>';
					if (event.ua) {
						truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
						userAgentInfo = '<br><span class="baskerville-feed-ua">' + i18n.ua + ' ' + truncatedUA + '</span>';
					}
				} else {
					detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-useragent">' + i18n.userAgent + '</span>';
					if (event.ua) {
						truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
						userAgentInfo = '<br><span class="baskerville-feed-ua">' + i18n.ua + ' ' + truncatedUA + '</span>';
					}
				}
			} else {
				if (isUserAgentBased && event.ua) {
					truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
					userAgentInfo = '<br><span class="baskerville-feed-ua">' + i18n.ua + ' ' + truncatedUA + '</span>';
				}
			}

			var item = $('<div class="live-feed-item"></div>');
			var countryName = event.country_code ? getCountryName(event.country_code) : '';
			var reasonText = isTurnstileFail ? i18n.failedTurnstile : (event.reason || i18n.noReason);
			item.html(
				'<span class="feed-icon">' + icon + '</span> ' +
				'<strong style="color: ' + color + ';">' + displayLabel + '</strong>' +
				detectionBadge + companyBadge + ' ' +
				event.ip + ' ' +
				(countryName ? '<span class="baskerville-feed-country">' + countryName + '</span> ' : '') +
				banBadge +
				'<span class="baskerville-feed-time">' + timeAgo + '</span><br>' +
				'<span class="baskerville-feed-score">' +
				reasonText +
				(event.score ? ' (' + i18n.score + ': ' + event.score + ')' : '') +
				(event.block_reason ? ' | ' + i18n.banReason + ': ' + event.block_reason : '') +
				'</span>' +
				userAgentInfo
			);
			container.append(item);
		});
	}

	function renderTopAttackers(ips) {
		var container = $('#top-attackers-list');
		container.empty();

		if (!ips || ips.length === 0) {
			container.html('<div class="baskerville-no-data">' + i18n.noData + '</div>');
			return;
		}

		ips.forEach(function(item, index) {
			var badge = index === 0 ? '\u{1f947}' : index === 1 ? '\u{1f948}' : index === 2 ? '\u{1f949}' : (index + 1) + '.';
			container.append(
				'<div class="baskerville-attacker-item">' +
				'<strong>' + badge + '</strong> ' +
				item.ip + ' ' +
				(item.country_code ? '<span class="baskerville-feed-country">' + item.country_code + '</span>' : '') +
				'<br><span class="baskerville-attacker-count">' + item.count + ' ' + i18n.attempts + '</span>' +
				'</div>'
			);
		});
	}

	function getEventIcon(classification, eventType) {
		if (eventType === 'ts_fail') return '\u{1f6e1}\ufe0f';
		if (eventType === 'honeypot') return '\u{1f36f}';
		if (classification === 'ai_bot') return '\u{1f916}';
		if (classification === 'bad_bot') return '\u{1f534}';
		if (classification === 'bot') return '\u{1f7e1}';
		return '\u26a0\ufe0f';
	}

	function getEventColor(classification, eventType) {
		if (eventType === 'ts_fail') return '#dc2626';
		if (classification === 'ai_bot') return '#9333ea';
		if (classification === 'bad_bot') return '#dc2626';
		if (classification === 'bot') return '#f59e0b';
		return '#6b7280';
	}

	function getTimeAgo(timestamp) {
		var now = new Date();
		var eventTime = new Date(timestamp);
		var seconds = Math.floor((now - eventTime) / 1000);
		if (seconds < 60) return seconds + 's ago';
		if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
		if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
		return Math.floor(seconds / 86400) + 'd ago';
	}

	function getCountryName(code) {
		var countries = {
			'AF':'Afghanistan','AL':'Albania','DZ':'Algeria','AS':'American Samoa','AD':'Andorra',
			'AO':'Angola','AI':'Anguilla','AQ':'Antarctica','AG':'Antigua and Barbuda','AR':'Argentina',
			'AM':'Armenia','AW':'Aruba','AU':'Australia','AT':'Austria','AZ':'Azerbaijan',
			'BS':'Bahamas','BH':'Bahrain','BD':'Bangladesh','BB':'Barbados','BY':'Belarus',
			'BE':'Belgium','BZ':'Belize','BJ':'Benin','BM':'Bermuda','BT':'Bhutan',
			'BO':'Bolivia','BA':'Bosnia and Herzegovina','BW':'Botswana','BR':'Brazil','BN':'Brunei',
			'BG':'Bulgaria','BF':'Burkina Faso','BI':'Burundi','KH':'Cambodia','CM':'Cameroon',
			'CA':'Canada','CV':'Cape Verde','KY':'Cayman Islands','CF':'Central African Republic','TD':'Chad',
			'CL':'Chile','CN':'China','CO':'Colombia','KM':'Comoros','CG':'Congo',
			'CD':'Congo (DRC)','CK':'Cook Islands','CR':'Costa Rica','CI':'Ivory Coast','HR':'Croatia',
			'CU':'Cuba','CY':'Cyprus','CZ':'Czech Republic','DK':'Denmark','DJ':'Djibouti',
			'DM':'Dominica','DO':'Dominican Republic','EC':'Ecuador','EG':'Egypt','SV':'El Salvador',
			'GQ':'Equatorial Guinea','ER':'Eritrea','EE':'Estonia','ET':'Ethiopia','FJ':'Fiji',
			'FI':'Finland','FR':'France','GA':'Gabon','GM':'Gambia','GE':'Georgia',
			'DE':'Germany','GH':'Ghana','GI':'Gibraltar','GR':'Greece','GL':'Greenland',
			'GD':'Grenada','GU':'Guam','GT':'Guatemala','GN':'Guinea','GW':'Guinea-Bissau',
			'GY':'Guyana','HT':'Haiti','HN':'Honduras','HK':'Hong Kong','HU':'Hungary',
			'IS':'Iceland','IN':'India','ID':'Indonesia','IR':'Iran','IQ':'Iraq',
			'IE':'Ireland','IL':'Israel','IT':'Italy','JM':'Jamaica','JP':'Japan',
			'JO':'Jordan','KZ':'Kazakhstan','KE':'Kenya','KI':'Kiribati','KP':'North Korea',
			'KR':'South Korea','KW':'Kuwait','KG':'Kyrgyzstan','LA':'Laos','LV':'Latvia',
			'LB':'Lebanon','LS':'Lesotho','LR':'Liberia','LY':'Libya','LI':'Liechtenstein',
			'LT':'Lithuania','LU':'Luxembourg','MO':'Macau','MK':'North Macedonia','MG':'Madagascar',
			'MW':'Malawi','MY':'Malaysia','MV':'Maldives','ML':'Mali','MT':'Malta',
			'MH':'Marshall Islands','MR':'Mauritania','MU':'Mauritius','MX':'Mexico','FM':'Micronesia',
			'MD':'Moldova','MC':'Monaco','MN':'Mongolia','ME':'Montenegro','MA':'Morocco',
			'MZ':'Mozambique','MM':'Myanmar','NA':'Namibia','NR':'Nauru','NP':'Nepal',
			'NL':'Netherlands','NZ':'New Zealand','NI':'Nicaragua','NE':'Niger','NG':'Nigeria',
			'NO':'Norway','OM':'Oman','PK':'Pakistan','PW':'Palau','PS':'Palestine',
			'PA':'Panama','PG':'Papua New Guinea','PY':'Paraguay','PE':'Peru','PH':'Philippines',
			'PL':'Poland','PT':'Portugal','PR':'Puerto Rico','QA':'Qatar','RO':'Romania',
			'RU':'Russia','RW':'Rwanda','WS':'Samoa','SM':'San Marino','SA':'Saudi Arabia',
			'SN':'Senegal','RS':'Serbia','SC':'Seychelles','SL':'Sierra Leone','SG':'Singapore',
			'SK':'Slovakia','SI':'Slovenia','SB':'Solomon Islands','SO':'Somalia','ZA':'South Africa',
			'SS':'South Sudan','ES':'Spain','LK':'Sri Lanka','SD':'Sudan','SR':'Suriname',
			'SZ':'Eswatini','SE':'Sweden','CH':'Switzerland','SY':'Syria','TW':'Taiwan',
			'TJ':'Tajikistan','TZ':'Tanzania','TH':'Thailand','TL':'Timor-Leste','TG':'Togo',
			'TO':'Tonga','TT':'Trinidad and Tobago','TN':'Tunisia','TR':'Turkey','TM':'Turkmenistan',
			'TV':'Tuvalu','UG':'Uganda','UA':'Ukraine','AE':'UAE','GB':'United Kingdom',
			'US':'United States','UY':'Uruguay','UZ':'Uzbekistan','VU':'Vanuatu','VA':'Vatican City',
			'VE':'Venezuela','VN':'Vietnam','YE':'Yemen','ZM':'Zambia','ZW':'Zimbabwe'
		};
		return countries[code] || code;
	}

	updateLiveFeed();
	updateLiveStats();
	setInterval(updateLiveFeed, 10000);
	setInterval(updateLiveStats, 10000);
});
