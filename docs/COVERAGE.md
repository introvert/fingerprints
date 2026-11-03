# Coverage review

This compares the signals collected here against popular fingerprinting libraries and test sites, as reviewed in November 2026. ✅ = collected, ➖ = partial, ❌ = not collected (with the reason).

## Transport layer (server side)

| Signal | tls.peet.ws | BrowserLeaks | FoxIO JA4+ | here |
|---|---|---|---|---|
| JA3 / JA3N | ✅ | ✅ | – | ✅ `tls.ja3`, `tls.ja3n` |
| JA4 / JA4_r / JA4_o | ✅ | ✅ | ✅ | ✅ |
| peetprint | ✅ | – | – | ✅ |
| Full ClientHello: ciphers, extensions in order, raw extension bytes, groups, key shares, sig algs, ALPN/ALPS, cert compression, record size limit, delegated credentials, PSK, ticket, ECH | ✅ | ➖ | – | ✅ `tls.client_hello.*`, `raw_hex` |
| Client random, session ID | ✅ | – | – | ✅ |
| Negotiated version, cipher, group, resumption | ➖ | ✅ | – | ✅ `tls.negotiated` |
| Akamai HTTP/2 fingerprint | ✅ | ✅ | – | ✅ `http2.akamai_fingerprint` |
| Full HTTP/2 client frame log (SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS, PRIORITY_UPDATE, RST, GOAWAY, PING) | ✅ | ➖ | – | ✅ `http2.frames` |
| HPACK representation per header (indexed / literal / never-indexed / huffman) | ❌ | ❌ | – | ✅ `http.headers[].hpack`, `http2.hpack_fingerprint` |
| HTTP/3 / QUIC ClientHello (JA4 `q…`), transport parameters, Initial packet layout | ❌ | ✅ | ✅ | ✅ `http3.quic` (passive Initial decryption) |
| HTTP/3 SETTINGS | ❌ | ➖ | – | ➖ values only; quic-go does not expose their order |
| Header order and casing (HTTP/1.1, HTTP/2) | ✅ | ✅ | – | ✅ `http.header_order`, `http.header_name_casing` |
| HTTP/3 header order | – | – | – | ❌ QPACK is decoded inside quic-go |
| JA4H | – | – | ✅ | ✅ for both the page request (`navigation`) and the fetch request |
| Client hints (high-entropy, via `Accept-CH` / `Critical-CH`) | ➖ | ✅ | – | ✅ `http.client_hints` |
| TCP SYN: TTL, window, options order, MSS, window scale, DF/ECN (JA4T, p0f-style) | ✅ | ✅ | ✅ JA4T | ✅ `tcp.syn` (Linux, CAP_NET_RAW) |
| Kernel TCP_INFO (RTT, MSS, negotiated options) | – | – | – | ✅ `tcp.info` |
| Timings: TLS RTT, handshake, handshake to first request, preface to HEADERS, QUIC RTT | ➖ | – | ➖ JA4L | ✅ `timing.*` |
| JA4S / JA4X (server-side TLS and certificate fingerprints) | – | – | ✅ | ❌ these fingerprint servers, not clients |
| DNS resolver leak | – | ✅ | – | ❌ needs an authoritative DNS server |
| IP geolocation / ASN / proxy lists | – | ✅ | – | ❌ needs an external database (easy to add on `network.ip`) |

## JavaScript

| Signal | FingerprintJS 5 | ThumbmarkJS | CreepJS | ClientJS | here |
|---|---|---|---|---|---|
| navigator, userAgentData high-entropy values | ✅ | ✅ | ✅ | ✅ | ✅ |
| screen, screen frame, DPR | ✅ | ✅ | ✅ | ✅ | ✅ |
| timezone, Intl, date locale | ✅ | ✅ | ✅ | ✅ | ✅ |
| canvas 2D, plus a noise check | ✅ | ✅ | ✅ | ✅ | ✅ (renders twice, samples pixels) |
| WebGL / WebGL2 parameters, extensions, shader precision, render hash | ✅ | ✅ | ✅ | ➖ | ✅ |
| WebGPU adapter | – | ✅ | ✅ | – | ✅ |
| Audio (OfflineAudioContext), base latency | ✅ | ✅ | ✅ | – | ✅ |
| Fonts (measurement), font preferences | ✅ | ✅ | ✅ | ✅ | ✅ |
| Emoji / DOMRect / SVG / TextMetrics | ➖ | – | ✅ | – | ✅ |
| Math, architecture, JS engine quirks | ✅ | ✅ | ✅ | – | ✅ |
| Media queries (color scheme, contrast, HDR, gamut, motion…) | ✅ | ✅ | ✅ | – | ✅ |
| Plugins, MIME types, PDF viewer | ✅ | ✅ | ✅ | ✅ | ✅ |
| Storage (local/session/IndexedDB/openDatabase), quota | ✅ | ✅ | ✅ | ✅ | ✅ |
| Content-blocker detection (domBlockers) | ✅ | – | – | – | ✅ |
| Vendor flavors | ✅ | – | – | – | ✅ |
| Apple Pay, Private Click Measurement | ✅ | – | – | – | ✅ |
| Permissions | – | ✅ | ✅ | – | ✅ |
| Speech voices, media devices, codecs, DRM | – | ✅ | ✅ | – | ✅ |
| WebRTC codecs and ICE (local/public IP) | – | ✅ | ✅ | – | ✅ |
| Dedicated / shared / service worker comparison | – | – | ✅ | – | ✅ |
| Lies / tampering (native-code checks, iframe realm, own properties) | – | – | ✅ | – | ✅ |
| Headless / automation (webdriver, CDP, Selenium/Playwright/Puppeteer, SwiftShader) | ➖ (Pro) | – | ✅ | – | ✅ |
| System colors and fonts, engine API surface counts, max call stack | – | – | ✅ | – | ✅ |
| Brave / Tor / Firefox resistFingerprinting detection | – | – | ✅ | – | ✅ |
| Private-mode heuristics | – | ✅ | – | – | ✅ (heuristic) |
| Keyboard layout, battery, network information, XR, gamepads | – | ➖ | ➖ | – | ✅ |
| Image formats (AVIF/WebP/JXL), CSS.supports bitmap, feature flags | – | – | ➖ | – | ✅ |
| Navigation Timing, RTT pings, clock skew, actual protocol (h3/h2) | – | – | ➖ | – | ✅ `latency`, `navigationTiming` |
| Geolocation, `queryLocalFonts`, `getScreenDetails` | – | – | – | – | ❌ these show a permission prompt |

The FingerprintJS and ThumbmarkJS outputs are also included verbatim under `libraries`.

## Cross-layer checks

The `analysis.checks` list compares layers against each other:

* UA vs TLS family, UA vs HTTP/2 settings, UA OS vs TCP SYN TTL/options
* Client hints vs JavaScript, and the main thread vs dedicated, shared and service workers
* Fetch metadata on the page request
* JavaScript RTT vs transport RTT, which can reveal a proxy or relay
* MTU vs a VPN, clock skew, automation signals, tampering, and canvas noise
