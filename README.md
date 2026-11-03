# fingerprints

A self-hosted tool that captures and analyses **browser fingerprints** across every layer of a request. It terminates TLS itself so it can see what a reverse proxy would hide.

| Layer | What is captured |
|---|---|
| **TLS** (separate section `tls`) | Raw ClientHello → **JA3**, **JA3N**, **JA4**, JA4_r, JA4_o, **peetprint**, decoded cipher suites, extensions (in order), groups, key shares, signature algorithms, ALPN/ALPS, cert compression, ECH, GREASE, plus the negotiated parameters |
| **HTTP/2** | Decrypted frames → **Akamai HTTP/2 fingerprint** (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order), HEADERS priority/flags, initial frame log |
| **HTTP** | Header **wire order and casing** (HPACK-decoded for h2, raw for HTTP/1.x), **JA4H**, client hints (`Accept-CH` is sent to request high-entropy hints) |
| **JavaScript** (~40 probes) | navigator, userAgentData high-entropy values, screen, Intl/timezone, media queries, canvas (with noise-injection check), WebGL/WebGL2 (unmasked renderer, params, extensions, precision, render hash), WebGPU adapter, audio (OfflineAudioContext), fonts, font preferences, emoji/DOMRect/SVG metrics, math, JS engine quirks, CPU architecture, WASM features, ~100 feature flags, CSS.supports bitmap, codecs/MSE/MediaRecorder/DRM, speech voices, media devices, permissions, storage/quota, battery, network, keyboard layout, WebRTC codecs and ICE (local/public IP), XR, Apple Pay, timer resolution, **Web Worker vs main thread comparison**, **automation detection** (webdriver, Selenium/Playwright/Puppeteer globals, CDP `Runtime.enable` detection, SwiftShader, …), **API tampering ("lies") detection** (non-native getters, own props on `navigator`, iframe realm mismatch) |
| **Libraries** | [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) 5.3.0 and [ThumbmarkJS](https://github.com/thumbmarkjs/thumbmarkjs) 1.12.0 (both MIT, vendored and served locally, telemetry disabled) |
| **Analysis** | Cross-layer consistency checks, for example a UA that claims Chrome but has a Go/Python TLS stack, HTTP/2 settings that don't match the UA, a client-hint platform that differs from the UA, a worker that differs from the main thread, or automation and tampering signals. Each report gets a 0–100 suspicion score |

## Modes

* **Echo / return** (default): the report goes back to the client and nothing is stored.
* **Store**: the report is also saved in SQLite. The response includes an `id`, a **permalink** (`/f/{id}`) and an API URL (`/api/fingerprints/{id}`). Stored reports can be read back at any time, searched by hash to show a browser's history, and diffed.

## Quick start

```sh
go run ./cmd/fingerprints                 # https://localhost:8443 (self-signed) + http://localhost:8080
# open https://localhost:8443/            – collects, shows a report; "Save" stores it
# open https://localhost:8443/?mode=store – collects and stores automatically

curl -k https://localhost:8443/api/server              # TLS/HTTP2/header fingerprint of curl (JSON)
curl -k https://localhost:8443/api/server?format=text  # same, flattened "key = value"
```

For real browsers, use a trusted certificate:

```sh
fingerprints -https :443 -http :80 -acme fp.example.com -public-url https://fp.example.com
# or: -cert fullchain.pem -key privkey.pem
```

Docker: `docker build -t fingerprints . && docker run -p 443:8443 -v fpdata:/data fingerprints -https :8443 -cert ... -key ...`

### Flags

| flag | default | |
|---|---|---|
| `-https` | `:8443` | TLS listener. TLS **must** terminate here for TLS/HTTP2 fingerprints |
| `-http` | `:8080` | plain HTTP listener (JS + header order only, no TLS fingerprint) |
| `-cert`, `-key` | | PEM certificate; a self-signed one is generated if omitted (`-hosts` sets its names) |
| `-acme` | | domains for automatic Let's Encrypt certificates (TLS-ALPN-01, needs port 443) |
| `-db` | `fingerprints.db` | SQLite path; `-db ""` disables storage |
| `-public-url` | | base URL for permalinks |
| `-trust-proxy` | false | take the client IP from `X-Forwarded-For` |
| `-admin-token` | `$FP_ADMIN_TOKEN` | if set, it is required for listing, history and delete |
| `-read-only` | false | disable storing |

> **Deploying behind a proxy:** a load balancer that terminates TLS hides the client's ClientHello and HTTP/2 frames. Use TCP/TLS passthrough (for example nginx `stream` with `ssl_preread`, HAProxy `mode tcp`, or a Cloudflare Spectrum TCP app) so the TLS connection reaches this server untouched.

## API

| Method & path | Description |
|---|---|
| `GET /` | Collector UI (`?mode=store`, `?label=`, `?webrtc=0`, `?libs=0`, `?auto=0`) |
| `GET /f/{id}` | Permalink page for a stored fingerprint: history and "compare with this browser now" |
| `GET /api/server` (`/api/tls`, `/tls`, `/json`) | Server-side fingerprint of this request (TLS, HTTP/2, headers) |
| `POST /api/fingerprint?mode=echo\|store` | Submit client data (body below) and get the full report back. Stores it when `mode=store` (201 + `Location`) |
| `GET /api/fingerprint?mode=store` | Store a server-side-only fingerprint (for curl, bots, non-JS clients) |
| `GET /api/fingerprints/{id}` | Read a stored report |
| `GET /api/fingerprints/{id}/related` | Other stored reports with the same combined hash, browser hash, FingerprintJS visitorId or JA4 |
| `GET /api/fingerprints?ja4=&ja3=&http2=&browser_hash=&combined_hash=&visitor_id=&ip=&label=&limit=&before=` | Search the history, newest first, paginated with `before` / `next_before` |
| `GET /api/compare?a={id}&b={id}` | Field-by-field diff of two stored reports. If `b` is omitted, `a` is compared with the current request |
| `DELETE /api/fingerprints/{id}` | Delete a stored report (requires `-admin-token`) |
| `GET /api/info` | Server capabilities |

All JSON endpoints accept `?format=json` (pretty, default), `?format=compact` or `?format=text`. The text format is also used when the request has `Accept: text/plain`.

Admin endpoints take `Authorization: Bearer <token>` or `?token=`.

### Client payload

```js
// <script src="/static/collect.js"></script> (optionally the vendored libraries too)
const data = await FPCollect.collect({ webrtc: true });   // { client: {components}, libraries }
data.label = 'my-device';
const report = await fetch('/api/fingerprint?mode=store', { method: 'POST', body: JSON.stringify(data) }).then(r => r.json());
console.log(report.permalink);
```

### Report shape

```jsonc
{
  "id": "p5D9xWzMnjNc", "permalink": "https://…/f/p5D9xWzMnjNc", "api_url": "https://…/api/fingerprints/p5D9xWzMnjNc",
  "mode": "store", "created_at": "…",
  "summary":  { "ja4": "t13d1516h2_8daaf6152771_…", "ja3_hash": "…", "http2_akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
                "ja4h": "…", "browser_hash": "…", "combined_hash": "…", "fingerprintjs_visitor_id": "…", "thumbmark": "…", "suspicion_score": 0 },
  "hashes":   { "ja3", "ja3n", "ja4", "ja4_o", "peetprint", "http2_akamai", "ja4h", "header_order", "browser", "browser_all", "transport", "combined" },
  "analysis": { "suspicion_score", "ua_family", "tls_family", "http2_family", "checks": [ { "name", "status", "detail" } ], "flags" },
  "network":  { "ip", "port", "connection_id", "request_number_on_connection", "tls_handshake_ms", "protocol" },
  "tls":      { "ja3", "ja3_hash", "ja3n", "ja4", "ja4_r", "ja4_o", "ja4_ro", "peetprint", "client_hello": { … }, "negotiated": { … } },
  "http2":    { "akamai_fingerprint", "settings", "connection_window_update", "priority_frames", "pseudo_header_order", "first_headers_frame", "initial_frames" },
  "http":     { "method", "path", "version", "header_order", "headers", "header_source", "ja4h", "ja4h_r", "client_hints" },
  "client":   { "components": { "<probe>": { "value", "error", "duration_ms", "hash" } } },
  "libraries":{ "fingerprintjs": { "visitorId", "confidence", "components" }, "thumbmarkjs": { "thumbmark", "components" } }
}
```

### Hashes

* `browser`: a hash of every JS probe except the volatile ones (battery, connection, window size, document, timing, storage quota, WebRTC, gamepads, media devices, permissions). It stays the same across page loads of the same browser.
* `transport`: JA4 + HTTP/2 fingerprint, which identifies the network stack.
* `combined`: transport + browser.

Use these with `/api/fingerprints?browser_hash=…` or `/related` to follow one browser through its history.

## Layout

```
cmd/fingerprints     main: listeners, certificates (self-signed / file / ACME)
internal/capture     raw TCP accept → records the ClientHello → TLS handshake → tees decrypted bytes → net/http (h1) / x/net/http2 (h2)
internal/tlsfp       ClientHello parser, JA3/JA3N/JA4/peetprint
internal/h2fp        streaming HTTP/2 frame + HPACK parser, Akamai fingerprint, per-request header order
internal/httpfp      HTTP/1.x raw header order, JA4H
internal/store       SQLite (pure Go, modernc.org/sqlite) storage and history queries
internal/server      HTTP API, report assembly, hashing, consistency analysis
web/static           collector (collect.js), UI, vendored FingerprintJS/ThumbmarkJS
```

## Privacy

This tool collects highly identifying data, including IP addresses and WebRTC local and public addresses. Run it only where you have the right to. Tell users what it does, use `-admin-token` on public deployments so the history can't be browsed, and use `?webrtc=0` to skip the STUN probe.
