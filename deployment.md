```commandline
zip -r baskerville-plugin.zip baskerville_plugin/ -x "*.DS_Store" "baskerville_wp/.idea/*" "baskerville_wp/.git/*" "baskerville_wp/node_modules/*" "baskerville_wp/*.log"   
```

```commandline
curl -sS -X POST 'https://wp.greything.com/wp-json/baskerville/v1/fp' \
  -H 'Content-Type: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  --data-binary @- <<'JSON'
{
  "baskerville_id": "test-curl-1",
  "fingerprint": {
    "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "screen": "1920x1080",
    "viewport": "400x300",
    "timezone": "Etc/UTC",
    "language": "ru-RU",
    "languages": ["ru-RU"],
    "touchSupport": { "touchEvent": false, "maxTouchPoints": 0 },
    "device": { "platform": "iPhone", "memory": "unknown", "cores": "unknown", "webdriver": true },
    "quirks": { "webgl": "enabled" },
    "dpr": 1,
    "pluginsCount": 0,
    "pdfViewer": false,
    "outerToInner": 1.8,
    "aspectRatio": 1.3333,
    "viewportToScreen": 0.0578,
    "tzOffsetNow": 0,
    "tzOffsetJan": 0,
    "tzOffsetJul": 0,
    "vendor": "Apple",
    "productSub": "20030107",
    "webglExtCount": 0,
    "permissions": { "notifications": "denied", "clipboard-read": "denied" }
  },
  "url": "https://wp.greything.com/",
  "ts": 1737930000000
}
JSON

```


```commandline
curl -sS -X POST 'https://wp.greything.com/wp-json/baskerville/v1/fp' \
  -H 'Content-Type: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  --data-binary @- <<'JSON'
{
  "baskerville_id": "test-curl-2",
  "fingerprint": {
    "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "screen": "1920x1080",
    "viewport": "640x480",
    "timezone": "Europe/Rome",
    "language": "ru-RU",
    "languages": ["ru-RU"],
    "touchSupport": { "touchEvent": false, "maxTouchPoints": 0 },
    "device": { "platform": "iPhone", "memory": "unknown", "cores": "unknown", "webdriver": false },
    "quirks": { "webgl": "enabled" },
    "dpr": 1,
    "pluginsCount": 0,
    "pdfViewer": false,
    "outerToInner": 1.65,
    "aspectRatio": 1.3333,
    "viewportToScreen": 0.1481,
    "tzOffsetNow": -120,
    "tzOffsetJan": -60,
    "tzOffsetJul": -120,
    "vendor": "Apple",
    "productSub": "20030107",
    "webglExtCount": 0,
    "permissions": { "notifications": "prompt" }
  },
  "url": "https://wp.greything.com/",
  "ts": 1737930000000
}
JSON

```

```commandline
curl -sS -X POST 'https://wp.greything.com/wp-json/baskerville/v1/fp' \
  -H 'Content-Type: application/json' \
  --data '{"baskerville_id":"dev-2","fingerprint":{"userAgent":"test","screen":"1920x1080","viewport":"800x600","language":"en","touchSupport":{"touchEvent":false,"maxTouchPoints":0},"device":{"platform":"Mac","webdriver":false}}}'


```