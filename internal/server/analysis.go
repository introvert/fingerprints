package server

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/introvert/fingerprints/internal/tlsfp"
)

// Check is a single consistency / bot check.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | warn | info | skip
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"-"`
}

// Analysis summarises cross-layer consistency checks. A high score means
// the client looks automated, spoofed or privacy-hardened.
type Analysis struct {
	Score       int      `json:"suspicion_score"`
	UAFamily    string   `json:"ua_family"`
	TLSFamily   string   `json:"tls_family"`
	HTTP2Family string   `json:"http2_family,omitempty"`
	Checks      []Check  `json:"checks"`
	Flags       []string `json:"flags,omitempty"`
}

var (
	reFirefox  = regexp.MustCompile(`Firefox/\d`)
	reChromium = regexp.MustCompile(`(Chrome|Chromium|CriOS|Edg|OPR|YaBrowser|SamsungBrowser)/\d`)
	reSafari   = regexp.MustCompile(`Version/[\d.]+.*Safari/`)
	// software rasterisers and hypervisor display adapters
	reVirtualGPU = regexp.MustCompile(`(?i)SwiftShader|llvmpipe|softpipe|lavapipe|VMware|VirtualBox|Parallels|Microsoft Basic Render|Apple Paravirtual|VirGL|virtio|QXL|Red Hat|Mesa OffScreen|Hyper-V`)
)

func uaFamily(ua string) string {
	switch {
	case ua == "":
		return "none"
	case strings.Contains(ua, "FxiOS") || strings.Contains(ua, "CriOS") || strings.Contains(ua, "EdgiOS"):
		return "safari" // all iOS browsers use WebKit / Apple TLS stack
	case reFirefox.MatchString(ua):
		return "firefox"
	case reChromium.MatchString(ua):
		return "chromium"
	case reSafari.MatchString(ua):
		return "safari"
	case strings.HasPrefix(ua, "curl/"):
		return "curl"
	case strings.Contains(strings.ToLower(ua), "python") || strings.HasPrefix(ua, "Go-http-client") ||
		strings.Contains(ua, "okhttp") || strings.HasPrefix(ua, "Wget") || strings.Contains(ua, "node") ||
		strings.Contains(ua, "axios") || strings.Contains(ua, "Java/"):
		return "library"
	}
	return "other"
}

// tlsFamily is a heuristic classification of the TLS stack.
func tlsFamily(f *tlsfp.Fingerprint) string {
	if f == nil {
		return "unknown"
	}
	c := f.ClientHello
	has := func(id uint16) bool { return slices.Contains(c.ExtensionOrder, id) }
	switch {
	case has(17513) || has(17613): // ALPS is Chromium/BoringSSL only (QUIC ClientHellos carry no GREASE)
		return "chromium"
	case !c.GREASE && has(28) && has(34):
		return "firefox"
	case c.GREASE && has(27):
		return "safari" // GREASE + cert compression, no ALPS
	case c.GREASE:
		return "chromium-like"
	}
	return "library/other"
}

func http2Family(akamai string) string {
	if akamai == "" {
		return ""
	}
	parts := strings.Split(akamai, "|")
	if len(parts) != 4 {
		return "unknown"
	}
	switch {
	case parts[3] == "m,a,s,p" && strings.HasPrefix(parts[0], "1:65536;2:0;4:6291456"):
		return "chromium"
	case parts[3] == "m,p,a,s":
		return "firefox"
	case (parts[3] == "m,s,p,a" || parts[3] == "m,s,a,p") && strings.HasPrefix(parts[0], "2:0;"):
		return "safari"
	case parts[3] == "m,a,s,p":
		return "chromium-like"
	}
	return "other"
}

func compatible(ua, layer string) bool {
	if layer == "" || layer == "unknown" {
		return true
	}
	switch ua {
	case "chromium":
		return layer == "chromium" || layer == "chromium-like"
	case "firefox":
		return layer == "firefox"
	case "safari":
		return layer == "safari" || layer == "chromium-like"
	case "curl", "library":
		return layer == "library/other" || layer == "other"
	}
	return true
}

func analyze(rep *Report) *Analysis {
	a := &Analysis{UAFamily: uaFamily(rep.HTTP.UserAgent)}
	add := func(name, status, detail string, weight int) {
		a.Checks = append(a.Checks, Check{Name: name, Status: status, Detail: detail, Weight: weight})
		if status == "fail" {
			a.Score += weight
			a.Flags = append(a.Flags, name)
		} else if status == "warn" {
			a.Score += weight / 2
			a.Flags = append(a.Flags, name)
		}
	}

	// --- transport vs user agent ---
	if rep.TLS != nil && rep.TLS.Fingerprint != nil {
		a.TLSFamily = tlsFamily(rep.TLS.Fingerprint)
		st := "pass"
		if !compatible(a.UAFamily, a.TLSFamily) {
			st = "fail"
		}
		add("tls_matches_user_agent", st, fmt.Sprintf("UA looks like %s, TLS ClientHello looks like %s", a.UAFamily, a.TLSFamily), 30)
	} else {
		a.TLSFamily = "unknown"
		add("tls_matches_user_agent", "skip", "no TLS fingerprint available", 0)
	}
	if rep.HTTP2 != nil {
		a.HTTP2Family = http2Family(rep.HTTP2.Akamai)
		st := "pass"
		if !compatible(a.UAFamily, a.HTTP2Family) {
			st = "fail"
		}
		add("http2_matches_user_agent", st, fmt.Sprintf("UA looks like %s, HTTP/2 settings look like %s", a.UAFamily, a.HTTP2Family), 25)
	} else if (a.UAFamily == "chromium" || a.UAFamily == "firefox" || a.UAFamily == "safari") && rep.Network.ApplicationProtocol != "h3" {
		if rep.TLS != nil && rep.TLS.Negotiated != nil {
			add("http2_used", "warn", "browser UA but connection did not negotiate HTTP/2", 10)
		}
	}
	if strings.Contains(rep.HTTP.UserAgent, "Headless") {
		add("headless_user_agent", "fail", "user agent advertises a headless browser", 40)
	}

	// --- TCP/IP layer ---
	if rep.TCP != nil && rep.TCP.SYN != nil {
		syn := rep.TCP.SYN
		uaOS := uaPlatform(rep.HTTP.UserAgent)
		want := 64
		if uaOS == "Windows" {
			want = 128
		}
		if uaOS != "" && syn.InitialTTL != 0 && syn.InitialTTL != want {
			add("tcp_os_matches_user_agent", "fail", fmt.Sprintf("UA says %s but SYN initial TTL %d / options suggest %s", uaOS, syn.InitialTTL, syn.OSGuess), 25)
		} else if uaOS != "" {
			add("tcp_os_matches_user_agent", "pass", fmt.Sprintf("SYN looks like %s (TTL %d, %d hops)", syn.OSGuess, syn.InitialTTL, syn.Hops), 25)
		}
		if syn.MSS > 0 && syn.MTUGuess < 1500 && syn.MTUGuess > 0 {
			add("network_link", "warn", fmt.Sprintf("MSS %d → MTU %d: %s", syn.MSS, syn.MTUGuess, syn.LinkGuess), 10)
		}
	}
	// --- proxy / forwarding headers added by intermediaries ---
	var proxyHdrs []string
	for _, h := range rep.HTTP.Headers {
		switch strings.ToLower(h.Name) {
		case "via", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
			"client-ip", "true-client-ip", "cf-connecting-ip", "x-proxy-id", "x-bluecoat-via", "proxy-connection", "x-originating-ip":
			proxyHdrs = append(proxyHdrs, h.Name)
		}
	}
	if len(proxyHdrs) > 0 {
		add("proxy_headers", "warn", "request carries proxy/forwarding headers: "+strings.Join(proxyHdrs, ", "), 15)
	}
	if rep.Navigation != nil && rep.Navigation.HTTP != nil && (a.UAFamily == "chromium" || a.UAFamily == "firefox" || a.UAFamily == "safari") && rep.TLS != nil && rep.TLS.Negotiated != nil {
		has := false
		for _, h := range rep.Navigation.HTTP.Headers {
			if strings.EqualFold(h.Name, "sec-fetch-dest") {
				has = true
			}
		}
		if has {
			add("navigation_fetch_metadata", "pass", "", 15)
		} else {
			add("navigation_fetch_metadata", "warn", "browser UA but the page request had no Sec-Fetch-* headers", 15)
		}
	}

	if rep.Client == nil {
		add("javascript", "info", "no client-side data (JavaScript not run or server-only request)", 0)
		finishScore(a)
		return a
	}

	// --- JS vs headers ---
	var nav struct {
		UserAgent           string   `json:"userAgent"`
		Platform            string   `json:"platform"`
		Language            string   `json:"language"`
		Languages           []string `json:"languages"`
		Webdriver           any      `json:"webdriver"`
		HardwareConcurrency any      `json:"hardwareConcurrency"`
		DeviceMemory        any      `json:"deviceMemory"`
	}
	if rep.component("navigator", &nav) {
		st, d := "pass", ""
		if nav.UserAgent != rep.HTTP.UserAgent {
			st, d = "fail", fmt.Sprintf("header=%q js=%q", rep.HTTP.UserAgent, nav.UserAgent)
		}
		add("user_agent_header_matches_js", st, d, 30)
		if al := firstLang(headerValue(rep, "accept-language")); al != "" && len(nav.Languages) > 0 {
			st = "pass"
			if !strings.EqualFold(al, nav.Languages[0]) {
				st = "warn"
			}
			add("accept_language_matches_js", st, fmt.Sprintf("header=%q navigator.languages[0]=%q", al, nav.Languages[0]), 10)
		}
		if nav.Webdriver == true {
			add("navigator_webdriver", "fail", "navigator.webdriver is true", 50)
		}
	}

	var uad struct {
		Platform string `json:"platform"`
		Mobile   bool   `json:"mobile"`
	}
	if rep.component("userAgentData", &uad) && uad.Platform != "" {
		hp := strings.Trim(rep.HTTP.ClientHints["sec-ch-ua-platform"], `"`)
		if hp != "" {
			st := "pass"
			if hp != uad.Platform {
				st = "fail"
			}
			add("client_hints_platform_matches_js", st, fmt.Sprintf("Sec-CH-UA-Platform=%q userAgentData.platform=%q", hp, uad.Platform), 25)
		}
		if p := uaPlatform(rep.HTTP.UserAgent); p != "" && !strings.EqualFold(p, uad.Platform) {
			add("ua_platform_matches_client_hints", "fail", fmt.Sprintf("UA says %s, userAgentData.platform says %s", p, uad.Platform), 25)
		}
	}
	if a.UAFamily == "chromium" && rep.HTTP.ClientHints["sec-ch-ua"] == "" && rep.TLS != nil && rep.TLS.Negotiated != nil {
		add("client_hints_present", "warn", "Chromium UA over HTTPS but no Sec-CH-UA header", 10)
	}

	// --- worker vs main thread ---
	var wk map[string]any
	if rep.component("worker", &wk) {
		var diffs []string
		var main map[string]any
		rep.component("navigator", &main)
		var intl map[string]any
		rep.component("intl", &intl)
		for _, k := range []string{"userAgent", "platform", "hardwareConcurrency", "deviceMemory", "language"} {
			if wv, ok := wk[k]; ok && main != nil && fmt.Sprint(wv) != fmt.Sprint(main[k]) {
				diffs = append(diffs, fmt.Sprintf("%s: main=%v worker=%v", k, main[k], wv))
			}
		}
		if wv, ok := wk["timezone"]; ok && intl != nil && fmt.Sprint(wv) != fmt.Sprint(intl["timezone"]) {
			diffs = append(diffs, fmt.Sprintf("timezone: main=%v worker=%v", intl["timezone"], wv))
		}
		if len(diffs) > 0 {
			add("worker_matches_main_thread", "fail", strings.Join(diffs, "; "), 35)
		} else {
			add("worker_matches_main_thread", "pass", "", 35)
		}
	}

	// --- automation / tampering signals from JS ---
	var auto struct {
		Detected []string `json:"detected"`
	}
	if rep.component("automation", &auto) {
		if len(auto.Detected) > 0 {
			add("automation_signals", "fail", strings.Join(auto.Detected, ", "), 40)
		} else {
			add("automation_signals", "pass", "", 40)
		}
	}
	var lies struct {
		Lies []string `json:"lies"`
	}
	if rep.component("tampering", &lies) {
		if len(lies.Lies) > 0 {
			add("api_tampering", "fail", strings.Join(lies.Lies, ", "), 30)
		} else {
			add("api_tampering", "pass", "", 30)
		}
	}
	var canvas struct {
		Stable *bool `json:"stable"`
	}
	if rep.component("canvas", &canvas) && canvas.Stable != nil {
		if !*canvas.Stable {
			add("canvas_randomization", "warn", "canvas output differs between two identical renders (anti-fingerprinting noise)", 20)
		} else {
			add("canvas_randomization", "pass", "", 20)
		}
	}
	// --- latency: JS-measured RTT vs kernel RTT of this TCP connection ---
	var lat struct {
		MedianRTT   float64 `json:"medianRttMs"`
		ClockSkewMS float64 `json:"clockSkewMs"`
	}
	if rep.component("latency", &lat) {
		tcpRTT := 0.0
		if rep.Timing != nil {
			tcpRTT = rep.Timing.TCPRTTMS
			if tcpRTT == 0 {
				tcpRTT = rep.Timing.QUICMinRTTMS
			}
		}
		if lat.MedianRTT > 0 && tcpRTT > 0 {
			st := "pass"
			if lat.MedianRTT-tcpRTT > 50 && lat.MedianRTT > 3*tcpRTT {
				st = "warn"
			}
			add("rtt_consistency", st, fmt.Sprintf("JS round-trip %.1f ms vs transport RTT %.1f ms (a large gap suggests a proxy/relay)", lat.MedianRTT, tcpRTT), 20)
		}
		if abs(lat.ClockSkewMS) > 5*60*1000 {
			add("clock_skew", "warn", fmt.Sprintf("client clock differs from server by %.0f s", lat.ClockSkewMS/1000), 10)
		}
	}
	// --- other worker scopes ---
	for _, scope := range []string{"sharedWorker", "serviceWorker"} {
		var sw map[string]any
		var main map[string]any
		if rep.component(scope, &sw) && rep.component("navigator", &main) && sw["userAgent"] != nil {
			var diffs []string
			for _, k := range []string{"userAgent", "platform", "hardwareConcurrency", "language"} {
				if v, ok := sw[k]; ok && fmt.Sprint(v) != fmt.Sprint(main[k]) {
					diffs = append(diffs, fmt.Sprintf("%s: main=%v %s=%v", k, main[k], scope, v))
				}
			}
			st := "pass"
			if len(diffs) > 0 {
				st = "fail"
			}
			add(scope+"_matches_main_thread", st, strings.Join(diffs, "; "), 30)
		}
	}
	var res struct {
		Detected []string `json:"detected"`
	}
	if rep.component("resistance", &res) && len(res.Detected) > 0 {
		add("privacy_resistance", "info", strings.Join(res.Detected, ", "), 0)
	}
	// --- virtual machine / software rendering ---
	var gl struct {
		Renderer string `json:"unmaskedRenderer"`
	}
	if rep.component("webgl", &gl) && gl.Renderer != "" {
		if m := reVirtualGPU.FindString(gl.Renderer); m != "" {
			add("virtual_or_software_gpu", "warn", "WebGL renderer indicates "+m+": "+gl.Renderer, 15)
		} else {
			add("virtual_or_software_gpu", "pass", gl.Renderer, 15)
		}
	}
	var tz struct {
		Timezone string `json:"timezone"`
	}
	if rep.component("intl", &tz) && tz.Timezone == "" {
		add("timezone_present", "warn", "Intl timezone missing", 10)
	}
	finishScore(a)
	return a
}

func finishScore(a *Analysis) {
	if a.Score > 100 {
		a.Score = 100
	}
}

func headerValue(rep *Report, name string) string {
	for _, h := range rep.HTTP.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func firstLang(v string) string {
	if v == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(strings.Split(v, ",")[0], ";")[0])
}

func uaPlatform(ua string) string {
	switch {
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "CrOS"):
		return "Chrome OS"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"):
		return "macOS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return ""
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
