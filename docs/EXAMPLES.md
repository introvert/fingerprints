# Example captures: Chrome and Firefox

Real captures made with this server on Linux, using the unmodified browser binaries in headless mode (Chrome launched directly, not through an automation driver). The full JSON reports are next to this file:

* [`chrome-153-h2.json`](chrome-153-h2.json)
* [`chrome-153-h3.json`](chrome-153-h3.json)
* [`firefox-159.json`](firefox-159.json)

| | Chrome 153 (HTTP/2) | Chrome 153 (HTTP/3) | Firefox 159 |
|---|---|---|---|
| Protocol | `h2` | `h3` | `h2` |
| JA4 | `t13d1518h2_8daaf6152771_a12c4694fc1a` | `q13i0312h3_55b375c5d22e_b1ea0fbf605d` | `t13d1517h2_8daaf6152771_3cbfd9057e0d` |
| JA3 hash | `47a276f2cda6b72ef3c032a5821375af` | `890de31d04d97c4a41d14ea63a988bea` | `9d42e90b0225e779f03141ddcd699df2` |
| JA3N hash | `3f3d862c81e0cff3d61fab03c6740f44` | `983903d184d7fdfa3525037212f36868` | `f9c6a2c424206e61efb6c1a6325596b5` |
| GREASE | `True` | `False` | `False` |
| ALPS | `["h2"]` | `["h3"]` | – |
| record_size_limit | – | – | `16385` |
| ECH | – | – | `outer` |
| Key exchange | `X25519MLKEM768` | `X25519MLKEM768` | `X25519MLKEM768` |
| Akamai HTTP/2 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | – | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |
| HPACK fingerprint | `I,Ai*,I,Wi*,An*,An,An,An,An*,An,An,An,An*,An,An,An,An*,An*,An,An,An,An,Ai*,An,An*,An,An…` | – | `I,Wi*,Ai*,I,Ai*,Ai*,Ai*,Ai*,An*,An*,An*,An*,An*,An*,An*` |
| QUIC fingerprint | – | `v1\|8\|0\|1-3-4-5-6-7-8-9-f-11-20-3127-3128\|grease=1` | – |
| QUIC Initial packets | – | `2` | – |
| HTTP/3 SETTINGS | – | `{"enable_connect_protocol":false,"h3_datagram":true,"other":{"GREASE_0x1a7a436d85":1995…` | – |
| JA4H (page request) | `ge20nn34enus_46d62dee0101_000000000000_000000000000` | – | `ge20nn11enus_3901d4197baf_000000000000_000000000000` |
| JA4H (fetch) | `po20nn37enus_53055d8eb680_000000000000_000000000000` | – | `po20nn14enus_db0d0680510f_000000000000_000000000000` |
| Header casing | `lowercase` | `Canonical-Case` | `lowercase` |
| JA4T (TCP SYN) | `65495_2-4-8-1-3_65495_10` | – | `65495_2-4-8-1-3_65495_10` |
| TLS round trip ms | `2.777` | – | `2.232` |
| Browser hash | `32b72e15d344894fe5552c482b0bd62b` | `20b24b8f44609e8572058626371fa289` | `d54dd9aead77d8c60b3d31532067977b` |
| FingerprintJS visitorId | `31b4f88f4eb04c4ae918bd669e3dca93` | `31b4f88f4eb04c4ae918bd669e3dca93` | `964f51f050eda621ecd92eff782bab03` |
| ThumbmarkJS | `e25aa1ab34ef7faccb9b108fe0d116ba` | `e25aa1ab34ef7faccb9b108fe0d116ba` | `dbffb3b8c835ad6978108f43ae6fe840` |
| Families UA/TLS/H2 | `chromium / chromium / chromium` | `chromium / chromium / –` | `firefox / firefox / firefox` |
| Suspicion score | `80` | `80` | `0` |
| Flags | `["headless_user_agent","automation_signals"]` | `["headless_user_agent","automation_signals"]` | – |

## Reading it

* **TLS:** Chrome sends GREASE values and ALPS (`h2` over TCP, `h3` over QUIC). Firefox sends neither, but has `record_size_limit` and an ECH outer extension. Both negotiate the post-quantum `X25519MLKEM768`. The cipher part of JA4 (`8daaf6152771`) is identical for both browsers over TCP, so the extension part is what tells them apart.
* **HTTP/2:** the two Akamai strings match the values published for each browser. Chrome sends a 6 MB stream window and pseudo-header order `m,a,s,p`; Firefox sends a 128 KB window, `MAX_FRAME_SIZE`, and `m,p,a,s`. The HPACK fingerprints differ too: Chrome sends many more client-hint headers.
* **HTTP/3:** Chrome over QUIC sends only 3 cipher suites (`q13…03…`), splits its post-quantum ClientHello across 2 Initial packets, and adds GREASE to both its transport parameters and its HTTP/3 SETTINGS. HTTP/3 header order is not observable (QPACK is decoded inside quic-go), so JA4H is left empty for that transport rather than reported wrongly.
* **TLS resumption:** the stored Chrome HTTP/2 connection was a resumed session (`tls.client_hello.pre_shared_key: true`). The PSK extension counts toward JA4's extension total, which is why this capture shows `1518`; a fresh Chrome connection shows one fewer. The report always says whether a capture was resumed. Chrome also sends two code points not yet in the name table (`0xca34`, `0x12e0`). They are recorded by number.
* **Page request vs fetch:** the two JA4H values differ in each browser (`ge…` vs `po…`, different header sets), which is why both are kept.
* **The same browser over two protocols:** FingerprintJS and ThumbmarkJS are identical across Chrome's HTTP/2 and HTTP/3 captures, while the transport fingerprints differ completely. The stable `browser` hash differs between the two for one reason only: the HTTP/3 capture was loaded from `127.0.0.1` rather than `localhost`, and Chrome allows the `unload` permissions-policy feature on one origin but not the other. On a single deployed origin this does not vary.
* **Bot score:** Chrome scores 80 because its UA says `HeadlessChrome` and WebGL runs on SwiftShader, both genuine headless signals. Firefox scores 0: its UA, TLS and HTTP/2 layers all agree it is Firefox, and headless Firefox exposes no automation markers.
* **TCP:** both browsers show the same JA4T, because the SYN is produced by the operating system (here the Linux loopback, MSS 65495), not by the browser.
