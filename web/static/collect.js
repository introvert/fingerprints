/*
 * fingerprints collector — gathers browser fingerprint signals.
 *
 * Usage:
 *   const data = await FPCollect.collect({ webrtc: true, libraries: true });
 *   // data = { client: { version, duration_ms, components: { name: {value, error, duration_ms} } },
 *   //          libraries: { fingerprintjs: {...}, thumbmarkjs: {...} } }
 *
 * Every component is isolated: failures are reported as `error`, never thrown.
 */
(function (global) {
  'use strict';
  const VERSION = '1.0.0';

  // ---------- helpers ----------
  const has = (o, k) => { try { return k in o; } catch (e) { return false; } };
  const safe = (fn, d = null) => { try { const v = fn(); return v === undefined ? d : v; } catch (e) { return d; } };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const withTimeout = (p, ms, label) => Promise.race([
    Promise.resolve(p),
    new Promise((_, rej) => setTimeout(() => rej(new Error((label || 'timeout') + ' after ' + ms + 'ms')), ms)),
  ]);
  // cyrb53 — fast 53-bit string hash (hex), works without secure context.
  function hash(str) {
    str = String(str);
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
  }
  const isNative = (fn) => {
    try { return typeof fn === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(fn)); }
    catch (e) { return false; }
  };
  const getter = (proto, prop) => safe(() => Object.getOwnPropertyDescriptor(proto, prop).get);

  // ---------- components ----------
  const C = {};

  C.navigator = () => {
    const n = navigator;
    return {
      userAgent: n.userAgent, appVersion: n.appVersion, appName: n.appName, appCodeName: n.appCodeName,
      platform: n.platform, vendor: n.vendor, vendorSub: n.vendorSub, product: n.product, productSub: n.productSub,
      oscpu: n.oscpu, cpuClass: n.cpuClass, buildID: n.buildID,
      language: n.language, languages: n.languages ? Array.from(n.languages) : null,
      hardwareConcurrency: n.hardwareConcurrency, deviceMemory: n.deviceMemory, maxTouchPoints: n.maxTouchPoints,
      cookieEnabled: n.cookieEnabled, doNotTrack: n.doNotTrack ?? global.doNotTrack ?? n.msDoNotTrack ?? null,
      globalPrivacyControl: n.globalPrivacyControl, pdfViewerEnabled: n.pdfViewerEnabled, webdriver: n.webdriver,
      onLine: n.onLine, javaEnabled: safe(() => n.javaEnabled()),
      plugins: safe(() => Array.from(n.plugins).map((p) => ({
        name: p.name, filename: p.filename, description: p.description,
        mimeTypes: Array.from(p).map((m) => m.type),
      })), []),
      mimeTypes: safe(() => Array.from(n.mimeTypes).map((m) => m.type), []),
      prototypeKeys: safe(() => { const k = []; for (const x in n) k.push(x); return k.length; }),
    };
  };

  C.userAgentData = async () => {
    const u = navigator.userAgentData;
    if (!u) return null;
    const out = { brands: u.brands, mobile: u.mobile, platform: u.platform };
    try {
      out.highEntropy = await u.getHighEntropyValues([
        'architecture', 'bitness', 'brands', 'formFactors', 'fullVersionList', 'model', 'platformVersion',
        'uaFullVersion', 'wow64',
      ]);
    } catch (e) { out.highEntropyError = String(e); }
    return out;
  };

  C.screen = () => {
    const s = screen;
    return {
      width: s.width, height: s.height, availWidth: s.availWidth, availHeight: s.availHeight,
      availLeft: s.availLeft, availTop: s.availTop, colorDepth: s.colorDepth, pixelDepth: s.pixelDepth,
      devicePixelRatio: global.devicePixelRatio, isExtended: s.isExtended,
      // screen frame: OS taskbar/dock size
      frame: [s.availTop, s.width - s.availWidth - (s.availLeft || 0), s.height - s.availHeight - (s.availTop || 0), s.availLeft],
    };
  };

  C.window = () => ({
    innerWidth: innerWidth, innerHeight: innerHeight, outerWidth: outerWidth, outerHeight: outerHeight,
    screenX: global.screenX, screenY: global.screenY, orientation: safe(() => ({ type: screen.orientation.type, angle: screen.orientation.angle })), visualViewport: safe(() => ({ w: visualViewport.width, h: visualViewport.height, scale: visualViewport.scale })),
    historyLength: history.length, isSecureContext: global.isSecureContext, crossOriginIsolated: global.crossOriginIsolated,
    inIframe: safe(() => global.self !== global.top, true), opener: !!global.opener,
    globalsCount: safe(() => Object.getOwnPropertyNames(global).length),
    // last own globals: extensions and automation tools often inject them
    customGlobals: safe(() => Object.getOwnPropertyNames(global).filter((k) => !/^(on|webkit|moz)/.test(k)).slice(-25)),
    chromeKeys: safe(() => (global.chrome ? Object.keys(global.chrome) : null)),
  });

  C.document = () => ({
    characterSet: document.characterSet, compatMode: document.compatMode, contentType: document.contentType,
    referrer: document.referrer, visibilityState: document.visibilityState, hasFocus: safe(() => document.hasFocus()),
    cookieLength: safe(() => document.cookie.length), designMode: document.designMode,
    fullscreenEnabled: document.fullscreenEnabled, pictureInPictureEnabled: document.pictureInPictureEnabled,
    lang: document.documentElement.lang, dir: document.dir,
  });

  C.intl = () => {
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const d = new Date(Date.UTC(2020, 0, 15, 12, 34, 56, 789));
    const jan = new Date(2024, 0, 1).getTimezoneOffset(), jul = new Date(2024, 6, 1).getTimezoneOffset();
    const sv = (k) => safe(() => Intl.supportedValuesOf(k).length);
    return {
      timezone: dtf.timeZone, offsets: [jan, jul], // current offset omitted: it flips at DST
      locale: dtf.locale, calendar: dtf.calendar, numberingSystem: dtf.numberingSystem, hourCycle: safe(() => new Intl.DateTimeFormat(undefined, { hour: 'numeric' }).resolvedOptions().hourCycle),
      numberFormat: safe(() => Intl.NumberFormat().resolvedOptions().locale),
      collator: safe(() => Intl.Collator().resolvedOptions().locale),
      pluralRules: safe(() => new Intl.PluralRules().resolvedOptions().locale),
      relativeTime: safe(() => new Intl.RelativeTimeFormat().format(-1, 'day')),
      listFormat: safe(() => new Intl.ListFormat().format(['a', 'b', 'c'])),
      displayNames: safe(() => new Intl.DisplayNames(undefined, { type: 'region' }).of('US')),
      dateString: d.toString(), localeString: d.toLocaleString(), localeNumber: (1234567.891).toLocaleString(),
      currency: safe(() => new Intl.NumberFormat(undefined, { style: 'currency', currency: 'EUR' }).format(1234.5)),
      supportedValues: { calendar: sv('calendar'), collation: sv('collation'), currency: sv('currency'), numberingSystem: sv('numberingSystem'), timeZone: sv('timeZone'), unit: sv('unit') },
    };
  };

  const mq = (q) => safe(() => matchMedia(q).matches);
  const pick = (feature, values) => { for (const v of values) if (mq(`(${feature}: ${v})`)) return v; return null; };
  C.mediaQueries = () => ({
    colorScheme: pick('prefers-color-scheme', ['dark', 'light']),
    reducedMotion: pick('prefers-reduced-motion', ['reduce', 'no-preference']),
    reducedTransparency: pick('prefers-reduced-transparency', ['reduce', 'no-preference']),
    reducedData: pick('prefers-reduced-data', ['reduce', 'no-preference']),
    contrast: pick('prefers-contrast', ['no-preference', 'more', 'less', 'custom']),
    forcedColors: pick('forced-colors', ['none', 'active']),
    invertedColors: pick('inverted-colors', ['none', 'inverted']),
    colorGamut: pick('color-gamut', ['rec2020', 'p3', 'srgb']),
    dynamicRange: pick('dynamic-range', ['high', 'standard']),
    videoDynamicRange: pick('video-dynamic-range', ['high', 'standard']),
    monochrome: mq('(monochrome)') ? (() => { for (let i = 1; i <= 100; i++) if (mq(`(max-monochrome: ${i})`)) return i; return null; })() : 0,
    pointer: pick('pointer', ['fine', 'coarse', 'none']), anyPointer: pick('any-pointer', ['fine', 'coarse', 'none']),
    hover: pick('hover', ['hover', 'none']), anyHover: pick('any-hover', ['hover', 'none']),
    displayMode: pick('display-mode', ['fullscreen', 'standalone', 'minimal-ui', 'browser']),
    update: pick('update', ['fast', 'slow', 'none']), scripting: pick('scripting', ['enabled', 'initial-only', 'none']),
  });

  // --- canvas ---
  function drawCanvas() {
    const c = document.createElement('canvas');
    c.width = 280; c.height = 60;
    const x = c.getContext('2d');
    if (!x) return null;
    x.textBaseline = 'alphabetic';
    x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20);
    x.fillStyle = '#069'; x.font = '11pt "Times New Roman"';
    x.fillText('Cwm fjordbank gly 😃 \u{1F9F6}', 2, 15);
    x.fillStyle = 'rgba(102, 204, 0, 0.2)'; x.font = '18pt Arial';
    x.fillText('Cwm fjordbank gly 😃', 4, 45);
    x.globalCompositeOperation = 'multiply';
    for (const [col, cx, cy] of [['#f2f', 40, 40], ['#2ff', 80, 40], ['#ff2', 60, 60]]) {
      x.fillStyle = col; x.beginPath(); x.arc(cx, cy, 40, 0, Math.PI * 2, true); x.closePath(); x.fill();
    }
    x.fillStyle = '#f9c'; x.arc(75, 75, 75, 0, Math.PI * 2, true); x.arc(75, 75, 25, 0, Math.PI * 2, true); x.fill('evenodd');
    return c;
  }
  C.canvas = () => {
    const a = drawCanvas();
    if (!a) return { supported: false };
    const d1 = a.toDataURL(), d2 = drawCanvas().toDataURL();
    const w = document.createElement('canvas').getContext('2d');
    w.rect(0, 0, 10, 10); w.rect(2, 2, 6, 6);
    const ctx = a.getContext('2d');
    return {
      supported: true, hash: hash(d1), length: d1.length, stable: d1 === d2,
      winding: w.isPointInPath(5, 5, 'evenodd') === false,
      // pixel sample (detects per-pixel noise injection)
      pixelSample: hash(Array.from(ctx.getImageData(0, 0, 50, 20).data).join(',')),
      textMetrics: safe(() => {
        const m = ctx.measureText('Cwm fjordbank gly 😃');
        return [m.width, m.actualBoundingBoxAscent, m.actualBoundingBoxDescent, m.actualBoundingBoxLeft, m.actualBoundingBoxRight, m.fontBoundingBoxAscent].map((v) => (v == null ? null : +v.toFixed(4)));
      }),
    };
  };

  C.emoji = () => {
    const s = document.createElement('span');
    s.style.cssText = 'position:absolute;left:-9999px;font-size:48px;white-space:nowrap;line-height:normal';
    document.body.appendChild(s);
    const out = {};
    for (const e of ['😀', '👩‍❤️‍👨', '🏳️‍🌈', '🫠', '🧑🏽‍💻', '🇸🇮', '☺', '🪿', '🫨', '🙂‍↕️']) {
      s.textContent = e;
      const r = s.getBoundingClientRect();
      out[e] = +r.width.toFixed(3) + 'x' + +r.height.toFixed(3);
    }
    s.remove();
    return { hash: hash(JSON.stringify(out)), sizes: out };
  };

  C.domRect = () => {
    const el = document.createElement('div');
    el.style.cssText = 'position:fixed;left:0;top:0;visibility:hidden;pointer-events:none;width:123.456px;transform:rotate(12.3deg) skew(3deg) scale(1.0123);font:16.5px serif;';
    el.textContent = 'Fingerprint DOMRect ¶ ƒ ∫';
    document.body.appendChild(el);
    const r = el.getBoundingClientRect();
    const range = document.createRange(); range.selectNodeContents(el);
    const rr = range.getBoundingClientRect();
    el.remove();
    const vals = [r.x, r.y, r.width, r.height, rr.width, rr.height];
    return { values: vals, hash: hash(vals.join(',')) };
  };

  C.svg = () => {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.style.cssText = 'position:absolute;left:-9999px';
    const t = document.createElementNS(ns, 'text');
    t.textContent = 'Sphinx of black quartz, judge my vow 😀';
    svg.appendChild(t); document.body.appendChild(svg);
    const len = t.getComputedTextLength();
    const box = safe(() => { const b = t.getBBox(); return [b.width, b.height]; });
    svg.remove();
    return { textLength: len, bbox: box };
  };

  // --- WebGL ---
  const GL_PARAMS = ['ALIASED_LINE_WIDTH_RANGE', 'ALIASED_POINT_SIZE_RANGE', 'ALPHA_BITS', 'BLUE_BITS', 'DEPTH_BITS', 'GREEN_BITS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS', 'MAX_CUBE_MAP_TEXTURE_SIZE', 'MAX_FRAGMENT_UNIFORM_VECTORS', 'MAX_RENDERBUFFER_SIZE', 'MAX_TEXTURE_IMAGE_UNITS', 'MAX_TEXTURE_SIZE', 'MAX_VARYING_VECTORS', 'MAX_VERTEX_ATTRIBS', 'MAX_VERTEX_TEXTURE_IMAGE_UNITS', 'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_VIEWPORT_DIMS', 'RED_BITS', 'RENDERER', 'SHADING_LANGUAGE_VERSION', 'STENCIL_BITS', 'SUBPIXEL_BITS', 'VENDOR', 'VERSION', 'SAMPLES', 'SAMPLE_BUFFERS'];
  const GL2_PARAMS = ['MAX_3D_TEXTURE_SIZE', 'MAX_ARRAY_TEXTURE_LAYERS', 'MAX_COLOR_ATTACHMENTS', 'MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS', 'MAX_COMBINED_UNIFORM_BLOCKS', 'MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS', 'MAX_DRAW_BUFFERS', 'MAX_ELEMENT_INDEX', 'MAX_ELEMENTS_INDICES', 'MAX_ELEMENTS_VERTICES', 'MAX_FRAGMENT_INPUT_COMPONENTS', 'MAX_FRAGMENT_UNIFORM_BLOCKS', 'MAX_FRAGMENT_UNIFORM_COMPONENTS', 'MAX_PROGRAM_TEXEL_OFFSET', 'MAX_SAMPLES', 'MAX_SERVER_WAIT_TIMEOUT', 'MAX_TEXTURE_LOD_BIAS', 'MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS', 'MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS', 'MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS', 'MAX_UNIFORM_BLOCK_SIZE', 'MAX_UNIFORM_BUFFER_BINDINGS', 'MAX_VARYING_COMPONENTS', 'MAX_VERTEX_OUTPUT_COMPONENTS', 'MAX_VERTEX_UNIFORM_BLOCKS', 'MAX_VERTEX_UNIFORM_COMPONENTS', 'MIN_PROGRAM_TEXEL_OFFSET', 'UNIFORM_BUFFER_OFFSET_ALIGNMENT'];
  const norm = (v) => (v && typeof v === 'object' && 'length' in v ? Array.from(v) : v);

  function glInfo(type) {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext(type) || (type === 'webgl' ? canvas.getContext('experimental-webgl') : null);
    if (!gl) return { supported: false };
    const out = { supported: true, params: {}, contextAttributes: safe(() => gl.getContextAttributes()) };
    for (const p of GL_PARAMS.concat(type === 'webgl2' ? GL2_PARAMS : [])) out.params[p] = safe(() => norm(gl.getParameter(gl[p])));
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    if (dbg) {
      out.unmaskedVendor = safe(() => gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));
      out.unmaskedRenderer = safe(() => gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
    }
    const af = gl.getExtension('EXT_texture_filter_anisotropic') || gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic');
    if (af) out.maxAnisotropy = safe(() => gl.getParameter(af.MAX_TEXTURE_MAX_ANISOTROPY_EXT));
    out.extensions = safe(() => gl.getSupportedExtensions(), []);
    out.shaderPrecision = {};
    for (const sh of ['VERTEX_SHADER', 'FRAGMENT_SHADER']) {
      for (const pr of ['LOW_FLOAT', 'MEDIUM_FLOAT', 'HIGH_FLOAT', 'LOW_INT', 'MEDIUM_INT', 'HIGH_INT']) {
        out.shaderPrecision[sh + '.' + pr] = safe(() => { const f = gl.getShaderPrecisionFormat(gl[sh], gl[pr]); return [f.rangeMin, f.rangeMax, f.precision]; });
      }
    }
    // rendered image hash
    out.imageHash = safe(() => {
      canvas.width = 64; canvas.height = 64;
      const vs = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vs, 'attribute vec2 p;varying vec2 v;void main(){v=p;gl_Position=vec4(p,0.,1.);}');
      gl.compileShader(vs);
      const fs = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fs, 'precision mediump float;varying vec2 v;void main(){gl_FragColor=vec4(sin(v.x*12.34)*.5+.5,cos(v.y*7.89)*.5+.5,fract(v.x*v.y*43758.5453),1.);}');
      gl.compileShader(fs);
      const pg = gl.createProgram();
      gl.attachShader(pg, vs); gl.attachShader(pg, fs); gl.linkProgram(pg); gl.useProgram(pg);
      const b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.9, -0.8, 0.85, -0.7, 0.1, 0.95]), gl.STATIC_DRAW);
      const loc = gl.getAttribLocation(pg, 'p'); gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      gl.clearColor(0.1, 0.2, 0.3, 1); gl.clear(gl.COLOR_BUFFER_BIT); gl.drawArrays(gl.TRIANGLES, 0, 3);
      const px = new Uint8Array(64 * 64 * 4); gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
      return hash(px.join(','));
    });
    safe(() => gl.getExtension('WEBGL_lose_context').loseContext());
    return out;
  }
  C.webgl = () => glInfo('webgl');
  C.webgl2 = () => glInfo('webgl2');

  C.webgpu = async () => {
    if (!navigator.gpu) return { supported: false };
    const adapter = await withTimeout(navigator.gpu.requestAdapter(), 2000, 'requestAdapter');
    if (!adapter) return { supported: true, adapter: null };
    const info = adapter.info || (adapter.requestAdapterInfo ? await adapter.requestAdapterInfo() : {});
    const limits = {};
    for (const k in adapter.limits) limits[k] = adapter.limits[k];
    return {
      supported: true,
      info: { vendor: info.vendor, architecture: info.architecture, device: info.device, description: info.description, subgroupMinSize: info.subgroupMinSize, subgroupMaxSize: info.subgroupMaxSize, isFallbackAdapter: info.isFallbackAdapter ?? adapter.isFallbackAdapter },
      features: Array.from(adapter.features || []).sort(), limits,
      preferredCanvasFormat: safe(() => navigator.gpu.getPreferredCanvasFormat()),
      wgslLanguageFeatures: safe(() => Array.from(navigator.gpu.wgslLanguageFeatures).sort()),
    };
  };

  // --- audio ---
  C.audio = async () => {
    const OAC = global.OfflineAudioContext || global.webkitOfflineAudioContext;
    if (!OAC) return { supported: false };
    const ctx = new OAC(1, 5000, 44100);
    const osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12; comp.attack.value = 0; comp.release.value = 0.25;
    osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
    const buf = await withTimeout(new Promise((res, rej) => {
      ctx.oncomplete = (e) => res(e.renderedBuffer);
      const p = ctx.startRendering(); if (p && p.catch) p.catch(rej);
    }), 3000, 'audio render');
    const data = buf.getChannelData(0);
    let sum = 0; for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
    // second run for stability (noise injection check)
    const out = { supported: true, sum: sum, hash: hash(Array.from(data.slice(4500, 5000)).join(',')) };
    const AC = global.AudioContext || global.webkitAudioContext;
    if (AC) {
      const ac = new AC();
      Object.assign(out, { sampleRate: ac.sampleRate, maxChannelCount: ac.destination.maxChannelCount, channelCountMode: ac.destination.channelCountMode });
      safe(() => ac.close());
    }
    return out;
  };

  // Latency/state depend on autoplay policy and user gestures: kept out of the stable hash.
  C.audioContext = () => {
    const AC = global.AudioContext || global.webkitAudioContext;
    if (!AC) return { supported: false };
    const ac = new AC();
    const out = { supported: true, state: ac.state, baseLatency: ac.baseLatency, outputLatency: ac.outputLatency };
    safe(() => ac.close());
    return out;
  };

  // --- fonts (width/height measurement against generic fallbacks) ---
  const FONTS = ['Agency FB', 'Arial', 'Arial Black', 'Arial Narrow', 'Arial Unicode MS', 'Bahnschrift', 'Baskerville', 'Bitstream Vera Sans Mono', 'Book Antiqua', 'Bookman Old Style', 'Calibri', 'Cambria', 'Cambria Math', 'Candara', 'Century', 'Century Gothic', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel', 'Courier', 'Courier New', 'Didot', 'DejaVu Sans', 'DejaVu Sans Mono', 'DejaVu Serif', 'Droid Sans', 'Ebrima', 'Franklin Gothic', 'Futura', 'Gabriola', 'Garamond', 'Geneva', 'Georgia', 'Gill Sans', 'Helvetica', 'Helvetica Neue', 'HoloLens MDL2 Assets', 'Impact', 'Ink Free', 'Javanese Text', 'Leelawadee UI', 'Liberation Mono', 'Liberation Sans', 'Liberation Serif', 'Lucida Console', 'Lucida Grande', 'Lucida Sans Unicode', 'MS Gothic', 'MS Outlook', 'MS Reference Sans Serif', 'MS Sans Serif', 'MS Serif', 'MT Extra', 'MYRIAD PRO', 'Malgun Gothic', 'Marlett', 'Menlo', 'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft New Tai Lue', 'Microsoft PhagsPa', 'Microsoft Sans Serif', 'Microsoft Tai Le', 'Microsoft YaHei', 'Microsoft Yi Baiti', 'MingLiU-ExtB', 'Monaco', 'Mongolian Baiti', 'Monotype Corsiva', 'Myanmar Text', 'Nirmala UI', 'Noto Color Emoji', 'Noto Sans', 'Noto Serif', 'Optima', 'Palatino', 'Palatino Linotype', 'Perpetua', 'Roboto', 'Rockwell', 'SF Pro', 'Segoe Fluent Icons', 'Segoe MDL2 Assets', 'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Emoji', 'Segoe UI Symbol', 'SimSun', 'Sitka', 'Skia', 'Sylfaen', 'Symbol', 'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Ubuntu Mono', 'Verdana', 'Webdings', 'Wingdings', 'Yu Gothic', 'Zapfino', 'Apple Color Emoji', 'Apple SD Gothic Neo', 'PingFang SC', 'Hiragino Sans', 'Cantarell', 'Fira Sans', 'Source Code Pro', 'Open Sans', 'Lato', 'Montserrat'];
  C.fonts = () => {
    const base = ['monospace', 'sans-serif', 'serif'];
    const text = 'mmmmmmmmmmlli1WwQ@#ñ€漢😀';
    const root = document.createElement('div');
    root.style.cssText = 'position:absolute;left:-9999px;top:0;visibility:hidden';
    const mk = (family) => {
      const s = document.createElement('span');
      s.style.cssText = `font-size:72px;font-family:${family};white-space:nowrap;line-height:normal;font-style:normal;font-weight:normal;letter-spacing:normal`;
      s.textContent = text; root.appendChild(s); return s;
    };
    const baseSpans = base.map(mk);
    const testSpans = FONTS.map((f) => base.map((b) => mk(`'${f}',${b}`)));
    document.body.appendChild(root);
    const bw = baseSpans.map((s) => [s.offsetWidth, s.offsetHeight]);
    const found = FONTS.filter((f, i) => testSpans[i].some((s, j) => s.offsetWidth !== bw[j][0] || s.offsetHeight !== bw[j][1]));
    root.remove();
    return { available: found, count: found.length, tested: FONTS.length, hash: hash(found.join(',')) };
  };

  C.fontPreferences = () => {
    const root = document.createElement('div');
    root.style.cssText = 'position:absolute;left:-9999px;visibility:hidden';
    document.body.appendChild(root);
    const out = {};
    for (const [k, fam] of Object.entries({ default: '', serif: 'serif', sans: 'sans-serif', mono: 'monospace', system: 'system-ui', apple: '-apple-system', min: 'none;font-size:1px' })) {
      const s = document.createElement('span');
      s.style.cssText = 'white-space:nowrap;' + (fam ? 'font-family:' + fam : '');
      s.textContent = 'mmMwWLliI0fiflO&1'; root.appendChild(s);
      out[k] = s.getBoundingClientRect().width;
    }
    root.remove();
    return out;
  };

  C.math = () => {
    const M = Math;
    return {
      acos: M.acos(0.123124234234234242), acosh: M.acosh(1e308), asin: M.asin(0.123124234234234242),
      asinh: M.asinh(1), atanh: M.atanh(0.5), atan: M.atan(0.5), sin: M.sin(-1e300), sinh: M.sinh(1),
      cos: M.cos(10.000000000123), cosh: M.cosh(1), tan: M.tan(-1e300), tanh: M.tanh(1), exp: M.exp(1),
      expm1: M.expm1(1), log1p: M.log1p(10), cbrt: M.cbrt(Math.PI), pow: M.pow(Math.PI, -100),
      log10: M.log10(7), hypot: M.hypot(1.0000001, 2.0000001, 3.0000001), sinPi: M.sin(Math.PI), fround: M.fround(5.5555555555),
    };
  };

  C.jsEngine = () => {
    const errMsg = (fn) => { try { fn(); } catch (e) { return e.message; } return null; };
    return {
      evalLength: eval.toString().length,
      errorMessages: {
        undef: errMsg(() => null.x), call: errMsg(() => (void 0)()), stack: errMsg(() => { const f = () => f(); f(); }),
        bigint: errMsg(() => BigInt(1.5)), json: errMsg(() => JSON.parse('{')),
      },
      stackFormat: safe(() => { const s = new Error('x').stack || ''; return s.split('\n').slice(0, 2).map((l) => l.replace(/https?:\/\/[^\s)]+/g, 'URL')); }),
      stackTraceLimit: Error.stackTraceLimit, captureStackTrace: typeof Error.captureStackTrace,
      floatPrecision: (0.1 + 0.2).toString(), toFixed: (1.005).toFixed(2), exp: (123.456).toExponential(20),
      // architecture: x86 vs ARM give different NaN bit patterns
      architecture: safe(() => { const f = new Float32Array(1), u = new Uint8Array(f.buffer); f[0] = Infinity; f[0] = f[0] - f[0]; return u[3]; }),
      features: {
        bigint: typeof BigInt, weakRef: typeof WeakRef, finalizationRegistry: typeof FinalizationRegistry,
        atomics: typeof Atomics, sharedArrayBuffer: typeof SharedArrayBuffer, structuredClone: typeof structuredClone,
        arrayAt: typeof [].at, findLast: typeof [].findLast, toSorted: typeof [].toSorted, groupBy: typeof Object.groupBy,
        promiseWithResolvers: typeof Promise.withResolvers, iteratorHelpers: typeof globalThis.Iterator,
        setUnion: typeof new Set().union, regexpV: safe(() => { new RegExp('[\\p{L}--[a-z]]', 'v'); return true; }, false),
        temporal: typeof globalThis.Temporal, float16: typeof globalThis.Float16Array, regexpEscape: typeof RegExp.escape,
        errorIsError: typeof Error.isError, uint8Base64: typeof Uint8Array.fromBase64, mathSumPrecise: typeof Math.sumPrecise,
      },
      wasm: safe(() => ({
        supported: typeof WebAssembly === 'object',
        simd: WebAssembly.validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11])),
        bulkMemory: WebAssembly.validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 5, 3, 1, 0, 1, 10, 14, 1, 12, 0, 65, 0, 65, 0, 65, 0, 252, 10, 0, 0, 11])),
      })),
    };
  };

  C.features = () => {
    const w = global, n = navigator;
    const list = {
      serviceWorker: has(n, 'serviceWorker'), webWorker: has(w, 'Worker'), sharedWorker: has(w, 'SharedWorker'),
      indexedDB: safe(() => !!w.indexedDB, false), localStorage: safe(() => !!w.localStorage, false), sessionStorage: safe(() => !!w.sessionStorage, false),
      openDatabase: has(w, 'openDatabase'), caches: has(w, 'caches'), storageBuckets: has(n, 'storageBuckets'),
      webrtc: has(w, 'RTCPeerConnection'), webTransport: has(w, 'WebTransport'), webSocket: has(w, 'WebSocket'),
      webSocketStream: has(w, 'WebSocketStream'), bluetooth: has(n, 'bluetooth'), usb: has(n, 'usb'), hid: has(n, 'hid'),
      serial: has(n, 'serial'), nfc: has(w, 'NDEFReader'), xr: has(n, 'xr'), gamepad: has(n, 'getGamepads'),
      share: has(n, 'share'), clipboard: has(n, 'clipboard'), credentials: has(n, 'credentials'),
      publicKeyCredential: has(w, 'PublicKeyCredential'), paymentRequest: has(w, 'PaymentRequest'),
      applePay: has(w, 'ApplePaySession'), contacts: has(n, 'contacts'), wakeLock: has(n, 'wakeLock'),
      geolocation: has(n, 'geolocation'), mediaSession: has(n, 'mediaSession'), presentation: has(n, 'presentation'),
      keyboard: has(n, 'keyboard'), virtualKeyboard: has(n, 'virtualKeyboard'), ink: has(n, 'ink'),
      scheduling: has(n, 'scheduling'), scheduler: has(w, 'scheduler'), locks: has(n, 'locks'), windowControlsOverlay: has(n, 'windowControlsOverlay'),
      managed: has(n, 'managed'), login: has(n, 'login'), identityCredential: has(w, 'IdentityCredential'),
      privateAttribution: has(n, 'privateAttribution'), attributionReporting: has(w, 'AttributionReporting') || has(document, 'featurePolicy'),
      topics: has(document, 'browsingTopics'), sharedStorage: has(w, 'sharedStorage'), fencedFrame: has(w, 'HTMLFencedFrameElement'),
      runAdAuction: has(n, 'runAdAuction'), protectedAudience: has(n, 'joinAdInterestGroup'), storageAccess: has(document, 'requestStorageAccess'),
      documentPictureInPicture: has(w, 'documentPictureInPicture'), eyeDropper: has(w, 'EyeDropper'), fileSystemAccess: has(w, 'showOpenFilePicker'),
      originPrivateFS: safe(() => has(n.storage, 'getDirectory'), false), compressionStream: has(w, 'CompressionStream'),
      offscreenCanvas: has(w, 'OffscreenCanvas'), imageDecoder: has(w, 'ImageDecoder'), videoDecoder: has(w, 'VideoDecoder'),
      audioWorklet: has(w, 'AudioWorklet'), speechRecognition: has(w, 'SpeechRecognition') || has(w, 'webkitSpeechRecognition'),
      speechSynthesis: has(w, 'speechSynthesis'), notification: has(w, 'Notification'), pushManager: has(w, 'PushManager'),
      backgroundFetch: has(w, 'BackgroundFetchManager'), periodicSync: has(w, 'PeriodicSyncManager'), sync: has(w, 'SyncManager'),
      reportingObserver: has(w, 'ReportingObserver'), navigationApi: has(w, 'navigation'), viewTransition: has(document, 'startViewTransition'),
      popover: has(HTMLElement.prototype, 'popover'), dialog: has(w, 'HTMLDialogElement'), customElements: has(w, 'customElements'),
      trustedTypes: has(w, 'trustedTypes'), sanitizer: has(w, 'Sanitizer'), cookieStore: has(w, 'cookieStore'),
      launchQueue: has(w, 'launchQueue'), translator: has(w, 'Translator'), languageModel: has(w, 'LanguageModel') || has(w, 'ai'),
      summarizer: has(w, 'Summarizer'), webnn: has(n, 'ml'), computePressure: has(w, 'PressureObserver'), idleDetector: has(w, 'IdleDetector'),
      deviceOrientation: has(w, 'DeviceOrientationEvent'), deviceMotion: has(w, 'DeviceMotionEvent'), accelerometer: has(w, 'Accelerometer'),
      touchEvent: has(w, 'TouchEvent'), pointerEvent: has(w, 'PointerEvent'), mozInnerScreenX: has(w, 'mozInnerScreenX'),
      safariPushNotification: safe(() => has(w.safari, 'pushNotification'), false), webkitMessageHandlers: safe(() => has(w.webkit, 'messageHandlers'), false),
      msSaveBlob: has(n, 'msSaveBlob'), brave: has(n, 'brave'), opr: has(w, 'opr'), yandex: has(w, 'yandex'),
      onLine: n.onLine, cssPaintWorklet: has(w.CSS || {}, 'paintWorklet'), cssHighlights: has(w.CSS || {}, 'highlights'),
    };
    return { flags: list, hash: hash(JSON.stringify(list)) };
  };

  C.cssSupports = () => {
    const q = ['display: grid', 'display: contents', 'display: flow-root', 'container-type: inline-size', 'selector(:has(a))', 'selector(:is(a))', 'selector(:focus-visible)', 'selector(:user-invalid)', 'selector(:popover-open)', 'selector(::target-text)', 'selector(:state(x))', 'selector(&)', 'aspect-ratio: 1', 'backdrop-filter: blur(1px)', '-webkit-backdrop-filter: blur(1px)', 'color: color-mix(in srgb, red, blue)', 'color: oklch(50% 0.1 10)', 'color: lab(50% 10 10)', 'color: rgb(from red r g b)', 'color: light-dark(red, blue)', 'color: contrast-color(red)', 'text-wrap: balance', 'text-wrap: pretty', 'anchor-name: --a', 'position-try: flip-block', 'view-transition-name: a', 'animation-timeline: scroll()', 'field-sizing: content', 'interpolate-size: allow-keywords', 'math-depth: 1', 'font-palette: dark', 'scrollbar-gutter: stable', 'scrollbar-color: red blue', 'overflow: clip', 'inset: 0', 'accent-color: red', 'hyphenate-character: "-"', 'text-box: trim-both cap alphabetic', 'reading-flow: normal', 'appearance: base-select', '-moz-appearance: none', '-webkit-touch-callout: none', 'zoom: 1', 'width: calc-size(auto, size)', 'width: sibling-index()', 'corner-shape: squircle', 'transition-behavior: allow-discrete', 'content-visibility: auto', 'mask: none', '-webkit-mask: none', 'font-size-adjust: from-font', 'initial-letter: 2', 'ruby-align: center', 'white-space-collapse: collapse', 'paint-order: stroke', 'contain-intrinsic-size: auto 100px', 'offset-path: none', 'translate: 1px', 'width: 1rcap', 'width: 1cqi', 'width: 1dvh', 'top: env(safe-area-inset-top)'];
    const out = {};
    for (const s of q) out[s] = safe(() => (s.startsWith('selector(') ? CSS.supports(s) : CSS.supports('(' + s + ')')), null);
    const bits = Object.values(out).map((v) => (v ? 1 : 0)).join('');
    return { supported: out, bitmap: bits, hash: hash(bits) };
  };

  C.codecs = async () => {
    const v = document.createElement('video'), a = document.createElement('audio');
    const video = ['video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="avc1.640028"', 'video/mp4; codecs="hev1.1.6.L93.B0"', 'video/mp4; codecs="hvc1.1.6.L93.B0"', 'video/mp4; codecs="av01.0.05M.08"', 'video/mp4; codecs="vp09.00.10.08"', 'video/webm; codecs="vp8"', 'video/webm; codecs="vp9"', 'video/webm; codecs="av1"', 'video/ogg; codecs="theora"', 'video/x-matroska', 'video/quicktime', 'application/x-mpegURL', 'application/vnd.apple.mpegurl', 'video/mp4; codecs="dvh1.05.06"'];
    const audio = ['audio/mpeg', 'audio/mp4; codecs="mp4a.40.2"', 'audio/mp4; codecs="ac-3"', 'audio/mp4; codecs="ec-3"', 'audio/mp4; codecs="flac"', 'audio/mp4; codecs="opus"', 'audio/ogg; codecs="vorbis"', 'audio/ogg; codecs="opus"', 'audio/ogg; codecs="flac"', 'audio/webm; codecs="opus"', 'audio/wav; codecs="1"', 'audio/aac', 'audio/x-m4a', 'audio/flac', 'audio/x-caf'];
    const out = { video: {}, audio: {}, mse: {}, recorder: {}, decodingInfo: {} };
    for (const t of video) { out.video[t] = v.canPlayType(t); out.mse[t] = safe(() => MediaSource.isTypeSupported(t)); out.recorder[t] = safe(() => MediaRecorder.isTypeSupported(t)); }
    for (const t of audio) { out.audio[t] = a.canPlayType(t); out.recorder[t] = safe(() => MediaRecorder.isTypeSupported(t)); }
    if (navigator.mediaCapabilities) {
      const cfgs = { h264: 'video/mp4; codecs="avc1.640028"', hevc: 'video/mp4; codecs="hvc1.1.6.L93.B0"', vp9: 'video/webm; codecs="vp09.00.10.08"', av1: 'video/mp4; codecs="av01.0.05M.08"' };
      await Promise.all(Object.entries(cfgs).map(async ([k, ct]) => {
        try {
          const r = await navigator.mediaCapabilities.decodingInfo({ type: 'media-source', video: { contentType: ct, width: 1920, height: 1080, bitrate: 5000000, framerate: 30 } });
          out.decodingInfo[k] = [r.supported, r.smooth, r.powerEfficient];
        } catch (e) { out.decodingInfo[k] = String(e.name); }
      }));
    }
    out.drm = {};
    if (navigator.requestMediaKeySystemAccess) {
      const ks = ['com.widevine.alpha', 'com.microsoft.playready', 'com.microsoft.playready.recommendation', 'com.apple.fps', 'com.apple.fps.1_0', 'org.w3.clearkey'];
      await Promise.all(ks.map(async (k) => {
        try {
          await withTimeout(navigator.requestMediaKeySystemAccess(k, [{ initDataTypes: ['cenc'], videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }] }]), 1500);
          out.drm[k] = true;
        } catch (e) { out.drm[k] = false; }
      }));
    }
    out.hash = hash(JSON.stringify(out));
    return out;
  };

  C.speech = async () => {
    if (!global.speechSynthesis) return { supported: false };
    let voices = speechSynthesis.getVoices();
    if (!voices.length) {
      await Promise.race([new Promise((r) => speechSynthesis.addEventListener('voiceschanged', r, { once: true })), sleep(1200)]);
      voices = speechSynthesis.getVoices();
    }
    const list = voices.map((v) => [v.name, v.lang, v.localService, v.default].join('|'));
    return { count: list.length, voices: list, hash: hash(list.join(',')) };
  };

  C.mediaDevices = async () => {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return { supported: false };
    const d = await navigator.mediaDevices.enumerateDevices();
    const kinds = {};
    for (const x of d) kinds[x.kind] = (kinds[x.kind] || 0) + 1;
    return {
      supported: true, kinds, labelsVisible: d.some((x) => x.label),
      deviceIdsHash: hash(d.map((x) => x.deviceId).join(',')), groupCount: new Set(d.map((x) => x.groupId)).size,
      supportedConstraints: Object.keys(navigator.mediaDevices.getSupportedConstraints() || {}).length,
    };
  };

  C.permissions = async () => {
    if (!navigator.permissions) return { supported: false };
    const names = ['accelerometer', 'ambient-light-sensor', 'background-fetch', 'background-sync', 'bluetooth', 'camera', 'clipboard-read', 'clipboard-write', 'display-capture', 'geolocation', 'gyroscope', 'local-fonts', 'magnetometer', 'microphone', 'midi', 'nfc', 'notifications', 'payment-handler', 'periodic-background-sync', 'persistent-storage', 'push', 'screen-wake-lock', 'speaker-selection', 'storage-access', 'top-level-storage-access', 'window-management', 'xr-spatial-tracking', 'keyboard-lock', 'pointer-lock', 'captured-surface-control', 'local-network-access'];
    const out = {};
    await Promise.all(names.map(async (name) => {
      try {
        const desc = name === 'push' ? { name, userVisibleOnly: true } : { name };
        out[name] = (await withTimeout(navigator.permissions.query(desc), 1000)).state;
      } catch (e) { out[name] = 'unsupported'; }
    }));
    out['Notification.permission'] = safe(() => Notification.permission);
    return out;
  };

  C.storage = async () => {
    const out = {};
    try { const e = await withTimeout(navigator.storage.estimate(), 1500); out.estimate = { quota: e.quota, usage: e.usage }; } catch (e) { out.estimate = null; }
    try { out.persisted = await withTimeout(navigator.storage.persisted(), 1500); } catch (e) { out.persisted = null; }
    out.localStorageWorks = safe(() => { localStorage.setItem('__fp', '1'); localStorage.removeItem('__fp'); return true; }, false);
    out.cookieWorks = safe(() => { document.cookie = '__fpc=1; SameSite=Lax'; const ok = document.cookie.includes('__fpc=1'); document.cookie = '__fpc=; Max-Age=0'; return ok; }, false);
    try {
      out.indexedDBWorks = await withTimeout(new Promise((res) => {
        const r = indexedDB.open('__fp_test');
        r.onsuccess = () => { r.result.close(); indexedDB.deleteDatabase('__fp_test'); res(true); };
        r.onerror = () => res(false);
      }), 1500);
    } catch (e) { out.indexedDBWorks = false; }
    return out;
  };

  C.battery = async () => {
    if (!navigator.getBattery) return { supported: false };
    const b = await withTimeout(navigator.getBattery(), 1500);
    return { supported: true, charging: b.charging, level: b.level, chargingTime: b.chargingTime, dischargingTime: b.dischargingTime };
  };

  C.connection = () => {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!c) return { supported: false };
    return { supported: true, effectiveType: c.effectiveType, type: c.type, rtt: c.rtt, downlink: c.downlink, downlinkMax: c.downlinkMax, saveData: c.saveData };
  };

  C.touch = () => {
    let touchEvent = false;
    try { document.createEvent('TouchEvent'); touchEvent = true; } catch (e) { /* no */ }
    return { maxTouchPoints: navigator.maxTouchPoints || navigator.msMaxTouchPoints || 0, touchEvent, ontouchstart: 'ontouchstart' in global };
  };

  C.keyboard = async () => {
    if (!navigator.keyboard || !navigator.keyboard.getLayoutMap) return { supported: false };
    const m = await withTimeout(navigator.keyboard.getLayoutMap(), 1000);
    const keys = ['KeyQ', 'KeyW', 'KeyY', 'KeyZ', 'KeyA', 'Semicolon', 'Quote', 'BracketLeft', 'BracketRight', 'Backquote', 'Minus', 'Equal', 'Digit2', 'IntlBackslash', 'Slash'];
    const out = {};
    for (const k of keys) out[k] = m.get(k);
    return { supported: true, size: m.size, keys: out };
  };

  C.webrtc = async (opts) => {
    const PC = global.RTCPeerConnection || global.webkitRTCPeerConnection;
    if (!PC) return { supported: false };
    const out = { supported: true };
    out.audioCodecs = safe(() => RTCRtpSender.getCapabilities('audio').codecs.map((c) => c.mimeType + '/' + c.clockRate + (c.channels ? '/' + c.channels : '') + (c.sdpFmtpLine ? ';' + c.sdpFmtpLine : '')));
    out.videoCodecs = safe(() => RTCRtpSender.getCapabilities('video').codecs.map((c) => c.mimeType + (c.sdpFmtpLine ? ';' + c.sdpFmtpLine : '')));
    out.audioExtensions = safe(() => RTCRtpSender.getCapabilities('audio').headerExtensions.map((h) => h.uri));
    out.videoExtensions = safe(() => RTCRtpSender.getCapabilities('video').headerExtensions.map((h) => h.uri));
    out.codecsHash = hash(JSON.stringify([out.audioCodecs, out.videoCodecs, out.audioExtensions, out.videoExtensions]));
    if (opts.webrtc === false) return out;
    // ICE candidates: reveal local (mDNS) and public (srflx) addresses.
    const pc = new PC({ iceServers: [{ urls: opts.stun || 'stun:stun.l.google.com:19302' }] });
    const cands = [];
    let sdp = '';
    try {
      pc.createDataChannel('fp');
      await pc.setLocalDescription(await pc.createOffer());
      await withTimeout(new Promise((res) => {
        pc.onicecandidate = (e) => { if (!e.candidate) res(); else cands.push(e.candidate.candidate); };
        pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); };
      }), 3000).catch(() => {});
      sdp = pc.localDescription ? pc.localDescription.sdp : '';
    } finally {
      pc.close();
    }
    const parsed = cands.map((c) => { const p = c.split(' '); return { protocol: p[2], address: p[4], port: p[5], type: p[7] }; });
    out.candidates = parsed;
    out.publicIPs = [...new Set(parsed.filter((c) => c.type === 'srflx').map((c) => c.address))];
    out.localAddresses = [...new Set(parsed.filter((c) => c.type === 'host').map((c) => c.address))];
    out.sdpHash = hash(sdp.replace(/\r\n(o|a=fingerprint|a=ice-ufrag|a=ice-pwd|a=candidate|a=msid-semantic).*/g, ''));
    return out;
  };

  C.gamepads = () => safe(() => Array.from(navigator.getGamepads()).filter(Boolean).map((g) => g.id), []);

  C.xr = async () => {
    if (!navigator.xr) return { supported: false };
    const out = { supported: true };
    for (const m of ['inline', 'immersive-vr', 'immersive-ar']) {
      try { out[m] = await withTimeout(navigator.xr.isSessionSupported(m), 1000); } catch (e) { out[m] = null; }
    }
    return out;
  };

  C.applePay = () => {
    if (!global.ApplePaySession) return { supported: false };
    return { supported: true, canMakePayments: safe(() => ApplePaySession.canMakePayments()), version: safe(() => { for (let v = 20; v > 0; v--) if (ApplePaySession.supportsVersion(v)) return v; return 0; }) };
  };

  C.timing = () => {
    const samples = [];
    let last = performance.now();
    for (let i = 0; i < 20000 && samples.length < 20; i++) { const t = performance.now(); if (t !== last) { samples.push(t - last); last = t; } }
    return {
      performanceNowResolution: samples.length ? Math.min(...samples) : null,
      timeOrigin: performance.timeOrigin, dateNowVsTimeOrigin: Date.now() - (performance.timeOrigin + performance.now()),
      navigationType: safe(() => performance.getEntriesByType('navigation')[0].type),
      nextHopProtocol: safe(() => performance.getEntriesByType('navigation')[0].nextHopProtocol),
      memory: safe(() => ({ jsHeapSizeLimit: performance.memory.jsHeapSizeLimit })),
      // depends on JIT tier-up timing, so it lives in this volatile component
      maxCallStack: (() => { let d = 0; const f = () => { d++; f(); }; try { f(); } catch (e) { /* overflow */ } return d; })(),
    };
  };

  // --- worker scope: spoofing extensions often forget to patch workers ---
  C.worker = () => new Promise((resolve, reject) => {
    const src = `self.onmessage=async()=>{const n=self.navigator;let gl=null;try{const c=new OffscreenCanvas(1,1).getContext('webgl');const d=c.getExtension('WEBGL_debug_renderer_info');gl=d?[c.getParameter(d.UNMASKED_VENDOR_WEBGL),c.getParameter(d.UNMASKED_RENDERER_WEBGL)]:[c.getParameter(c.VENDOR),c.getParameter(c.RENDERER)];}catch(e){}
let uad=null;try{uad=n.userAgentData?await n.userAgentData.getHighEntropyValues(['platformVersion','architecture','bitness']):null}catch(e){}
let cv=null;try{const oc=new OffscreenCanvas(200,40),x=oc.getContext('2d');x.font='16px Arial';x.fillStyle='#069';x.fillText('Cwm fjordbank gly 😃',2,20);const d=x.getImageData(0,0,200,40).data;let h=0;for(let i=0;i<d.length;i++)h=(h*31+d[i])|0;cv=(h>>>0).toString(16);}catch(e){}
postMessage({offscreenCanvasHash:cv,userAgent:n.userAgent,platform:n.platform,language:n.language,languages:n.languages?[...n.languages]:null,hardwareConcurrency:n.hardwareConcurrency,deviceMemory:n.deviceMemory,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,webgl:gl,userAgentData:uad,webdriver:n.webdriver});};`;
    let url;
    try { url = URL.createObjectURL(new Blob([src], { type: 'application/javascript' })); } catch (e) { return reject(e); }
    const w = new Worker(url);
    const t = setTimeout(() => { w.terminate(); URL.revokeObjectURL(url); reject(new Error('worker timeout')); }, 2500);
    w.onmessage = (e) => { clearTimeout(t); w.terminate(); URL.revokeObjectURL(url); resolve(e.data); };
    w.onerror = (e) => { clearTimeout(t); w.terminate(); URL.revokeObjectURL(url); reject(new Error(e.message || 'worker error')); };
    w.postMessage(1);
  });

  // --- automation / bot detection ---
  C.automation = () => {
    const w = global, d = document, n = navigator;
    const sig = {};
    sig.webdriver = n.webdriver === true;
    sig.headlessUA = /HeadlessChrome|PhantomJS|SlimerJS|Electron|jsdom|HtmlUnit/i.test(n.userAgent);
    sig.seleniumGlobals = ['_selenium', 'callSelenium', '_Selenium_IDE_Recorder', '__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__webdriver_script_func', '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt', '_WEBDRIVER_ELEM_CACHE', 'webdriver', 'domAutomation', 'domAutomationController'].filter((k) => k in w || k in d);
    sig.cdcVars = Object.getOwnPropertyNames(w).concat(Object.getOwnPropertyNames(d)).filter((k) => /^\$?cdc_|^\$wdc_|_Symbol$|^__playwright|^__pw|^__puppeteer|^__nightmare|^_phantom|^callPhantom|^Buffer$|^emit$|^spawn$|^__lastWatir/.test(k));
    sig.documentAttrs = ['selenium', 'webdriver', 'driver'].filter((a) => d.documentElement.getAttribute(a) != null);
    sig.phantom = !!(w.callPhantom || w._phantom);
    sig.nightmare = !!w.__nightmare;
    sig.electron = safe(() => !!(w.process && w.process.versions && w.process.versions.electron), false);
    sig.chromeObjectMissing = /Chrome\//.test(n.userAgent) && !/Edg|OPR|CriOS|Mobile/.test(n.userAgent) && !w.chrome;
    sig.noPlugins = /Chrome\//.test(n.userAgent) && !/Mobile|Android/.test(n.userAgent) && n.plugins && n.plugins.length === 0;
    sig.noLanguages = !n.languages || n.languages.length === 0;
    sig.zeroOuterSize = w.outerWidth === 0 && w.outerHeight === 0;
    sig.permissionsInconsistent = false; // filled by async check below
    sig.webdriverDescriptorPatched = safe(() => { const desc = Object.getOwnPropertyDescriptor(n, 'webdriver'); return !!desc; }, false);
    sig.swiftshader = safe(() => { const c = d.createElement('canvas').getContext('webgl'); const e = c.getExtension('WEBGL_debug_renderer_info'); return /SwiftShader|llvmpipe|softpipe|Mesa OffScreen/i.test(c.getParameter(e.UNMASKED_RENDERER_WEBGL)); }, false);
    // CDP detection: DevTools protocol (Runtime.enable) serialises console args,
    // touching the getter of an Error's stack.
    let cdp = false;
    try {
      const e = new Error();
      Object.defineProperty(e, 'stack', { configurable: false, enumerable: false, get() { cdp = true; return ''; } });
      console.debug(e);
    } catch (_) { /* ignore */ }
    sig.cdpRuntimeEnabled = cdp;
    sig.headlessBrands = safe(() => navigator.userAgentData.brands.some((b) => /Headless/i.test(b.brand)), false);
    sig.zeroConnectionRtt = safe(() => navigator.connection.rtt === 0 && /Chrome/.test(n.userAgent) && !/Mobile/.test(n.userAgent), false);
    sig.noOuterChrome = !/Mobile|Android|iPhone|iPad/.test(n.userAgent) && w.outerHeight > 0 && w.outerHeight === w.innerHeight && w.outerWidth === w.innerWidth && !document.fullscreenElement;
    sig.stackHasAutomation = safe(() => /puppeteer_evaluation_script|__playwright|pptr:|selenium/i.test(new Error().stack), false);
    return sig;
  };

  // --- API tampering ("lies") detection ---
  C.tampering = () => {
    const lies = [];
    const checks = [
      ['Navigator.userAgent', Navigator.prototype, 'userAgent'], ['Navigator.platform', Navigator.prototype, 'platform'],
      ['Navigator.languages', Navigator.prototype, 'languages'], ['Navigator.hardwareConcurrency', Navigator.prototype, 'hardwareConcurrency'],
      ['Navigator.deviceMemory', Navigator.prototype, 'deviceMemory'], ['Navigator.webdriver', Navigator.prototype, 'webdriver'],
      ['Navigator.plugins', Navigator.prototype, 'plugins'], ['Navigator.vendor', Navigator.prototype, 'vendor'],
      ['Screen.width', Screen.prototype, 'width'], ['Screen.height', Screen.prototype, 'height'], ['Screen.colorDepth', Screen.prototype, 'colorDepth'],
      ['Document.hidden', Document.prototype, 'hidden'],
    ];
    for (const [name, proto, prop] of checks) {
      const g = getter(proto, prop);
      if (g && !isNative(g)) lies.push(name + ' (getter not native)');
    }
    const fns = [
      ['HTMLCanvasElement.toDataURL', HTMLCanvasElement.prototype.toDataURL], ['HTMLCanvasElement.toBlob', HTMLCanvasElement.prototype.toBlob],
      ['CanvasRenderingContext2D.getImageData', safe(() => CanvasRenderingContext2D.prototype.getImageData)],
      ['CanvasRenderingContext2D.measureText', safe(() => CanvasRenderingContext2D.prototype.measureText)],
      ['WebGLRenderingContext.getParameter', safe(() => WebGLRenderingContext.prototype.getParameter)],
      ['WebGL2RenderingContext.getParameter', safe(() => WebGL2RenderingContext.prototype.getParameter)],
      ['AudioBuffer.getChannelData', safe(() => AudioBuffer.prototype.getChannelData)],
      ['Element.getBoundingClientRect', Element.prototype.getBoundingClientRect], ['Element.getClientRects', Element.prototype.getClientRects],
      ['Date.getTimezoneOffset', Date.prototype.getTimezoneOffset], ['Intl.DateTimeFormat.resolvedOptions', Intl.DateTimeFormat.prototype.resolvedOptions],
      ['Function.toString', Function.prototype.toString], ['Permissions.query', safe(() => Permissions.prototype.query)],
      ['MediaDevices.enumerateDevices', safe(() => MediaDevices.prototype.enumerateDevices)], ['Math.random', Math.random],
    ];
    for (const [name, fn] of fns) if (fn && !isNative(fn)) lies.push(name + ' (not native)');
    // own properties on navigator / screen instances mean someone redefined them
    for (const [label, obj] of [['navigator', navigator], ['screen', screen]]) {
      const own = Object.getOwnPropertyNames(obj);
      if (own.length) lies.push(label + ' has own props: ' + own.slice(0, 10).join(','));
    }
    // Function.prototype.toString proxies leak through class-ness checks
    const proxyLeak = safe(() => { Object.create(Function.prototype.toString).toString(); return false; }, true) === false;
    if (proxyLeak) lies.push('Function.prototype.toString behaves like a Proxy');
    const tsName = safe(() => Function.prototype.toString.name);
    if (tsName !== 'toString') lies.push('Function.prototype.toString renamed');
    // iframe comparison: fresh realm vs main realm
    const iframe = safe(() => {
      const f = document.createElement('iframe'); f.style.display = 'none'; f.srcdoc = ''; document.body.appendChild(f);
      const n = f.contentWindow.navigator;
      const r = { userAgent: n.userAgent, platform: n.platform, hardwareConcurrency: n.hardwareConcurrency, languages: n.languages && [...n.languages], webdriver: n.webdriver };
      f.remove(); return r;
    });
    if (iframe) {
      for (const k of ['userAgent', 'platform', 'hardwareConcurrency']) if (iframe[k] !== navigator[k]) lies.push(`iframe navigator.${k} differs`);
    }
    return { lies, iframe };
  };


  // ===== additions from the library gap review (FingerprintJS / CreepJS / BrowserLeaks) =====

  // Ad / content blocker detection (bait elements, as FingerprintJS "domBlockers").
  C.domBlockers = async () => {
    const baits = {
      generic: ['adsbox', 'ad-banner', 'ad-placeholder', 'adsbygoogle', 'pub_300x250', 'textAd', 'banner-ads', 'sponsored-ad'],
      ids: ['ad_banner', 'ad-slot', 'carbonads', 'google_ads_frame'],
    };
    const root = document.createElement('div');
    root.style.cssText = 'position:absolute;left:-9999px;top:0';
    const els = [];
    for (const c of baits.generic) { const e = document.createElement('div'); e.className = c; e.innerHTML = '&nbsp;'; e.style.height = '10px'; root.appendChild(e); els.push(['.' + c, e]); }
    for (const id of baits.ids) { const e = document.createElement('div'); e.id = id; e.innerHTML = '&nbsp;'; e.style.height = '10px'; root.appendChild(e); els.push(['#' + id, e]); }
    document.body.appendChild(root);
    await sleep(60);
    const blocked = els.filter(([, e]) => !e.offsetParent || e.offsetHeight === 0 || getComputedStyle(e).display === 'none').map(([s]) => s);
    root.remove();
    let scriptBlocked = null;
    try {
      const r = await withTimeout(fetch('/static/ads.js?adtag=1&ad_slot=1', { cache: 'no-store' }), 1500);
      scriptBlocked = !r.ok;
    } catch (e) { scriptBlocked = true; }
    return { blocked, adblock: blocked.length > 0 || scriptBlocked === true, baitRequestBlocked: scriptBlocked };
  };

  // Browser-specific globals ("vendorFlavors").
  C.vendorFlavors = () => {
    const keys = ['chrome', 'safari', '__crWeb', '__gCrWeb', 'yandex', '__yb', '__ybro', '__firefox__', '__edgeTrackingPreventionStatistics', 'webkit', 'oprt', 'samsungAr', 'ucweb', 'UCShellJava', 'puffinDevice', 'opr', 'brave', 'duckduckgo', 'msWriteProfilerMark', 'InstallTrigger', 'mozRTCPeerConnection', 'onmozfullscreenchange'];
    return keys.filter((k) => safe(() => global[k] !== undefined && global[k] !== null, false) || (k === 'brave' && !!navigator.brave) || (k === 'duckduckgo' && !!navigator.duckduckgo));
  };

  C.privateClickMeasurement = () => {
    const a = document.createElement('a');
    return { attributionSourceId: a.attributionSourceId ?? a.attributionsourceid ?? null, attributionSrc: 'attributionSrc' in a };
  };

  // CSS system colours reveal OS / theme / accessibility settings.
  C.systemColors = () => {
    const names = ['AccentColor', 'AccentColorText', 'ActiveText', 'ButtonBorder', 'ButtonFace', 'ButtonText', 'Canvas', 'CanvasText', 'Field', 'FieldText', 'GrayText', 'Highlight', 'HighlightText', 'LinkText', 'Mark', 'MarkText', 'SelectedItem', 'SelectedItemText', 'VisitedText', 'ActiveBorder', 'ActiveCaption', 'AppWorkspace', 'Background', 'ButtonHighlight', 'ButtonShadow', 'CaptionText', 'InactiveBorder', 'InactiveCaption', 'InactiveCaptionText', 'InfoBackground', 'InfoText', 'Menu', 'MenuText', 'Scrollbar', 'ThreeDDarkShadow', 'ThreeDFace', 'ThreeDHighlight', 'ThreeDLightShadow', 'ThreeDShadow', 'Window', 'WindowFrame', 'WindowText', '-webkit-focus-ring-color'];
    const el = document.createElement('div');
    document.body.appendChild(el);
    const out = {};
    for (const n of names) { el.style.color = ''; el.style.color = n; out[n] = el.style.color ? getComputedStyle(el).color : null; }
    const sysFonts = {};
    for (const f of ['caption', 'icon', 'menu', 'message-box', 'small-caption', 'status-bar', 'system-ui']) {
      el.style.font = ''; el.style.font = f === 'system-ui' ? '12px system-ui' : f;
      const cs = getComputedStyle(el); sysFonts[f] = cs.fontSize + ' ' + cs.fontFamily;
    }
    el.remove();
    return { colors: out, fonts: sysFonts, hash: hash(JSON.stringify([out, sysFonts])) };
  };

  // Property counts track the exact engine version (CreepJS-style).
  C.engineSurface = () => {
    const count = (o) => safe(() => Object.getOwnPropertyNames(o).length);
    return {
      windowProps: count(global), documentProps: count(Document.prototype), htmlElementProps: count(HTMLElement.prototype),
      elementProps: count(Element.prototype), navigatorProps: count(Navigator.prototype), cssStyleProps: safe(() => getComputedStyle(document.documentElement).length),
      cssPropertyNames: safe(() => Object.getOwnPropertyNames(CSSStyleDeclaration.prototype).length), mathProps: count(Math),
      intlProps: count(Intl), webglProps: safe(() => count(WebGLRenderingContext.prototype)), errorProps: count(Error),
      permissionsPolicy: safe(() => (document.featurePolicy || document.permissionsPolicy).allowedFeatures().sort()),
    };
  };

  // Detection of anti-fingerprinting modes (Brave, Tor, Firefox RFP, DuckDuckGo, Safari).
  C.resistance = async () => {
    const d = [];
    if (navigator.brave) { try { if (await navigator.brave.isBrave()) d.push('brave'); } catch (e) { d.push('brave'); } }
    if (navigator.duckduckgo) d.push('duckduckgo');
    const ff = /Firefox\//.test(navigator.userAgent);
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const res = safe(() => { const a = performance.now(); let b = a; while (b === a) b = performance.now(); return b - a; }, 0);
    // A single indicator (e.g. a machine that is really in UTC) is not enough:
    // resistFingerprinting is reported only when several of its effects coincide.
    const rfp = [];
    if (ff && tz === 'UTC') rfp.push('utc');
    if (ff && screen.width === innerWidth && screen.height === innerHeight && !document.fullscreenElement) rfp.push('screen=window');
    if (ff && res >= 16) rfp.push('16ms_timers');
    if (ff && navigator.platform === 'Win32' && !/Windows/.test(navigator.oscpu || 'Windows')) rfp.push('spoofed_platform');
    if (rfp.length >= 2) d.push('firefox_rfp(' + rfp.join('+') + ')');
    if (ff && innerWidth % 200 === 0 && innerHeight % 100 === 0 && rfp.length) d.push('tor_letterboxing_like');
    if (res >= 16) d.push('coarse_timers(' + res.toFixed(1) + 'ms)');
    return { detected: d, timerResolutionMs: +res.toFixed(3) };
  };

  // Private / incognito mode heuristics.
  C.privateMode = async () => {
    const signals = [];
    try {
      const { quota } = await navigator.storage.estimate();
      if (/Chrome\//.test(navigator.userAgent) && quota && quota < 1.2e9 && performance.memory) {
        if (quota < performance.memory.jsHeapSizeLimit * 2) signals.push('chromium_small_quota');
      }
      if (/Safari\//.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent)) {
        try { await navigator.storage.getDirectory(); } catch (e) { if (/unknown transient/i.test(e.message)) signals.push('safari_opfs_unavailable'); }
      }
    } catch (e) { /* ignore */ }
    if (/Firefox\//.test(navigator.userAgent) && !navigator.serviceWorker) signals.push('firefox_no_service_worker');
    return { likely: signals.length > 0, signals };
  };

  C.imageFormats = async () => {
    const imgs = {
      webp: 'data:image/webp;base64,UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==',
      avif: 'data:image/avif;base64,AAAAIGZ0eXBhdmlmAAAAAGF2aWZtaWYxbWlhZk1BMUIAAADybWV0YQAAAAAAAAAoaGRscgAAAAAAAAAAcGljdAAAAAAAAAAAAAAAAGxpYmF2aWYAAAAADnBpdG0AAAAAAAEAAAAeaWxvYwAAAABEAAABAAEAAAABAAABGgAAAB0AAAAoaWluZgAAAAAAAQAAABppbmZlAgAAAAABAABhdjAxQ29sb3IAAAAAamlwcnAAAABLaXBjbwAAABRpc3BlAAAAAAAAAAIAAAACAAAAEHBpeGkAAAAAAwgICAAAAAxhdjFDgQ0MAAAAABNjb2xybmNseAACAAIAAYAAAAAXaXBtYQAAAAAAAAABAAEEAQKDBAAAACVtZGF0EgAKCBgANogQEAwgMg8f8D///8WfhwB8+ErK42A=',
      jxl: 'data:image/jxl;base64,/woIELASCAgQAFwASxLFgkWAHL0xqnCBCV0qDp901Te/5QM=',
    };
    const out = {};
    await Promise.all(Object.entries(imgs).map(([k, src]) => new Promise((res) => {
      const i = new Image();
      const t = setTimeout(() => { out[k] = null; res(); }, 1500);
      i.onload = () => { clearTimeout(t); out[k] = i.width > 0; res(); };
      i.onerror = () => { clearTimeout(t); out[k] = false; res(); };
      i.src = src;
    })));
    return out;
  };

  // Navigation Timing of this page + paint timings.
  C.navigationTiming = () => {
    const n = performance.getEntriesByType('navigation')[0];
    if (!n) return { supported: false };
    const r = (v) => (v == null ? null : +v.toFixed(2));
    return {
      nextHopProtocol: n.nextHopProtocol, type: n.type, deliveryType: n.deliveryType, renderBlockingStatus: n.renderBlockingStatus,
      redirectCount: n.redirectCount, transferSize: n.transferSize, encodedBodySize: n.encodedBodySize, decodedBodySize: n.decodedBodySize,
      dnsMs: r(n.domainLookupEnd - n.domainLookupStart), connectMs: r(n.connectEnd - n.connectStart),
      tlsMs: n.secureConnectionStart > 0 ? r(n.connectEnd - n.secureConnectionStart) : null,
      requestToFirstByteMs: r(n.responseStart - n.requestStart), firstInterimResponseStart: r(n.firstInterimResponseStart),
      downloadMs: r(n.responseEnd - n.responseStart), domInteractiveMs: r(n.domInteractive), domContentLoadedMs: r(n.domContentLoadedEventEnd), loadMs: r(n.loadEventEnd),
      workerStart: r(n.workerStart), serverTiming: (n.serverTiming || []).map((s) => ({ name: s.name, duration: s.duration, description: s.description })),
      paint: performance.getEntriesByType('paint').map((p) => [p.name, r(p.startTime)]),
    };
  };

  // Round-trip probes against /api/ping: client RTT, jitter, clock skew and
  // the protocol actually used (h3 after Alt-Svc, h2, http/1.1).
  C.latency = async (opts) => {
    const url = opts.pingUrl || '/api/ping';
    const samples = [], skews = [], protos = new Set(), conns = new Set();
    const n = Math.max(2, opts.pings || 6);
    for (let i = 0; i < n; i++) {
      const t0 = performance.now(), wall0 = Date.now();
      const r = await withTimeout(fetch(url + '?i=' + i + '&t=' + wall0, { cache: 'no-store' }), 3000);
      const j = await r.json();
      const t1 = performance.now();
      samples.push(t1 - t0);
      skews.push(j.server_time_unix_ms - (wall0 + (t1 - t0) / 2));
      if (j.protocol) protos.add(j.protocol);
      if (j.connection_id) conns.add(j.connection_id);
      const e = performance.getEntriesByName(r.url).pop();
      if (e && e.nextHopProtocol) protos.add('resource:' + e.nextHopProtocol);
    }
    const sorted = samples.slice(1).sort((a, b) => a - b); // first may include connection setup
    const med = sorted[Math.floor(sorted.length / 2)];
    const sk = skews.slice(1).sort((a, b) => a - b);
    return {
      samplesMs: samples.map((v) => +v.toFixed(2)), medianRttMs: +med.toFixed(2), minRttMs: +sorted[0].toFixed(2),
      jitterMs: +(sorted[sorted.length - 1] - sorted[0]).toFixed(2), clockSkewMs: +sk[Math.floor(sk.length / 2)].toFixed(1),
      protocols: [...protos], connections: conns.size,
    };
  };

  // Shared worker scope (another realm spoofers often miss).
  const WORKER_PROBE = `const n=self.navigator;const info=()=>({userAgent:n.userAgent,platform:n.platform,language:n.language,languages:n.languages?[...n.languages]:null,hardwareConcurrency:n.hardwareConcurrency,deviceMemory:n.deviceMemory,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,webdriver:n.webdriver});`;
  C.sharedWorker = () => new Promise((resolve, reject) => {
    if (!global.SharedWorker) return resolve({ supported: false });
    const url = URL.createObjectURL(new Blob([WORKER_PROBE + 'onconnect=(e)=>{const p=e.ports[0];p.postMessage(info());};'], { type: 'application/javascript' }));
    let w;
    try { w = new SharedWorker(url); } catch (e) { return resolve({ supported: true, error: String(e) }); }
    const t = setTimeout(() => { w.port.close(); URL.revokeObjectURL(url); reject(new Error('shared worker timeout')); }, 2500);
    w.port.onmessage = (e) => { clearTimeout(t); w.port.close(); URL.revokeObjectURL(url); resolve(Object.assign({ supported: true }, e.data)); };
    w.port.start();
  });

  // Service worker scope (registered under /static/ and removed afterwards).
  C.serviceWorker = async () => {
    if (!navigator.serviceWorker || !global.isSecureContext) return { supported: false };
    const reg = await withTimeout(navigator.serviceWorker.register('/static/fp-sw.js', { scope: '/static/fp-sw/' }), 3000);
    try {
      const sw = reg.installing || reg.waiting || reg.active;
      if (sw.state !== 'activated') await withTimeout(new Promise((r) => sw.addEventListener('statechange', () => sw.state === 'activated' && r())), 3000);
      const data = await withTimeout(new Promise((res) => {
        const ch = new MessageChannel();
        ch.port1.onmessage = (e) => res(e.data);
        sw.postMessage('fp', [ch.port2]);
      }), 2000);
      return Object.assign({ supported: true }, data);
    } finally {
      reg.unregister();
    }
  };

  const ORDER = ['navigator', 'userAgentData', 'screen', 'window', 'document', 'intl', 'mediaQueries', 'canvas', 'emoji', 'domRect', 'svg', 'webgl', 'webgl2', 'webgpu', 'audio', 'audioContext', 'fonts', 'fontPreferences', 'math', 'jsEngine', 'features', 'cssSupports', 'codecs', 'speech', 'mediaDevices', 'permissions', 'storage', 'battery', 'connection', 'touch', 'keyboard', 'webrtc', 'gamepads', 'xr', 'applePay', 'timing', 'worker', 'sharedWorker', 'serviceWorker', 'automation', 'tampering', 'domBlockers', 'vendorFlavors', 'privateClickMeasurement', 'systemColors', 'engineSurface', 'resistance', 'privateMode', 'imageFormats', 'navigationTiming', 'latency'];

  async function runComponent(name, opts) {
    const t0 = performance.now();
    try {
      const value = await withTimeout(C[name](opts), opts.timeout || 5000, name);
      return { value: value === undefined ? null : value, duration_ms: +(performance.now() - t0).toFixed(2) };
    } catch (e) {
      return { error: String((e && e.message) || e), duration_ms: +(performance.now() - t0).toFixed(2) };
    }
  }

  async function runLibraries(opts) {
    const out = {};
    const jobs = [];
    if (global.FingerprintJS && opts.libraries !== false) {
      jobs.push((async () => {
        const t0 = performance.now();
        try {
          const agent = await global.FingerprintJS.load({ monitoring: false });
          const r = await withTimeout(agent.get(), 8000, 'fingerprintjs');
          const comps = {};
          for (const [k, v] of Object.entries(r.components)) comps[k] = 'error' in v ? { error: String(v.error) } : { value: v.value };
          out.fingerprintjs = { version: r.version, visitorId: r.visitorId, confidence: r.confidence, components: comps, duration_ms: +(performance.now() - t0).toFixed(1) };
        } catch (e) { out.fingerprintjs = { error: String(e) }; }
      })());
    }
    if (global.ThumbmarkJS && opts.libraries !== false) {
      jobs.push((async () => {
        const t0 = performance.now();
        try {
          const tm = new global.ThumbmarkJS.Thumbmark({ logging: false, collect_beacon: false });
          const r = await withTimeout(tm.get(), 8000, 'thumbmarkjs');
          out.thumbmarkjs = { thumbmark: r.thumbmark, version: r.version, components: r.components, duration_ms: +(performance.now() - t0).toFixed(1) };
        } catch (e) { out.thumbmarkjs = { error: String(e) }; }
      })());
    }
    await Promise.all(jobs);
    return out;
  }

  /**
   * collect({ only?: string[], skip?: string[], webrtc?: bool, stun?: string,
   *           libraries?: bool, timeout?: ms, onProgress?: (name, result) => void })
   */
  async function collect(opts = {}) {
    const t0 = performance.now();
    let names = opts.only || ORDER;
    if (opts.skip) names = names.filter((n) => !opts.skip.includes(n));
    const components = {};
    const libsP = runLibraries(opts);
    await Promise.all(names.map(async (n) => {
      components[n] = await runComponent(n, opts);
      if (opts.onProgress) opts.onProgress(n, components[n]);
    }));
    const p = components.permissions && components.permissions.value, a = components.automation && components.automation.value;
    // Notification.permission 'denied' while permissions.query says 'prompt' is a classic headless tell
    if (p && a) {
      a.permissionsInconsistent = p['Notification.permission'] === 'denied' && p.notifications === 'prompt';
    }
    if (a) a.detected = Object.entries(a).filter(([k, v]) => k !== 'detected' && (v === true || (Array.isArray(v) && v.length))).map(([k]) => k);
    const libraries = await libsP;
    return { client: { version: VERSION, duration_ms: +(performance.now() - t0).toFixed(1), components }, libraries };
  }

  global.FPCollect = { collect, components: C, order: ORDER, hash, version: VERSION };
})(typeof window !== 'undefined' ? window : globalThis);
