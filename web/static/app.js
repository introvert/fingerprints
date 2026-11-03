(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else e.setAttribute(k, v);
    }
    for (const k of kids) if (k != null) e.append(k);
    return e;
  };
  const params = new URLSearchParams(location.search);
  const viewMatch = location.pathname.match(/^\/f\/([A-Za-z0-9]+)$/);
  let lastPayload = null, lastReport = null;

  const status = (msg) => { $('status').textContent = msg; };

  // ---------- rendering ----------
  const SUMMARY_LABELS = {
    ja4: 'JA4 (TLS)', ja4_quic: 'JA4 (QUIC)', ja4t: 'JA4T (TCP)', tcp_os_guess: 'TCP OS guess', tcp_rtt_ms: 'TCP RTT (ms)',
    ja4h_navigation: 'JA4H (page request)', ja3_hash: 'JA3 hash', peetprint_hash: 'Peetprint hash', http2_akamai: 'HTTP/2 (Akamai)',
    ja4h: 'JA4H (HTTP)', browser_hash: 'Browser hash (stable JS)', combined_hash: 'Combined hash',
    fingerprintjs_visitor_id: 'FingerprintJS visitorId', thumbmark: 'ThumbmarkJS', ip: 'IP address',
    user_agent: 'User-Agent', protocol: 'Protocol', tls_version: 'TLS version', suspicion_score: 'Suspicion score',
  };

  function renderSummary(rep) {
    const cards = $('cards');
    cards.replaceChildren();
    const order = Object.keys(SUMMARY_LABELS);
    const keys = Object.keys(rep.summary || {}).sort((a, b) => order.indexOf(a) - order.indexOf(b));
    for (const k of keys) {
      cards.append(el('div', { class: 'card' },
        el('div', { class: 'k', text: SUMMARY_LABELS[k] || k }),
        el('div', { class: 'v', text: String(rep.summary[k]) })));
    }
    $('summary').hidden = false;
  }

  function renderAnalysis(rep) {
    const a = rep.analysis;
    if (!a) return;
    const score = $('score');
    score.textContent = 'score ' + a.suspicion_score + '/100';
    score.className = 'pill ' + (a.suspicion_score >= 40 ? 'bad' : a.suspicion_score > 0 ? 'warn' : 'ok');
    const body = $('checks');
    body.replaceChildren();
    body.append(el('tr', {}, el('td', { text: 'families' }), el('td', { class: 'st-info', text: 'info' }),
      el('td', { text: `UA: ${a.ua_family} · TLS: ${a.tls_family}` + (a.http2_family ? ` · HTTP/2: ${a.http2_family}` : '') })));
    for (const c of a.checks || []) {
      body.append(el('tr', {}, el('td', { text: c.name }), el('td', { class: 'st-' + c.status, text: c.status }), el('td', { text: c.detail || '' })));
    }
    $('analysis').hidden = false;
  }

  function valueNode(v) {
    let cls = 'str', text;
    if (v === null || v === undefined) { cls = 'nil'; text = 'null'; }
    else if (typeof v === 'number') { cls = 'num'; text = String(v); }
    else if (typeof v === 'boolean') { cls = 'bool'; text = String(v); }
    else text = typeof v === 'string' ? v : JSON.stringify(v);
    return el('div', { class: 'val ' + cls, text });
  }
  const isScalarArray = (a) => Array.isArray(a) && a.length <= 64 && a.every((x) => x === null || typeof x !== 'object');

  function tree(label, v, meta, open) {
    const d = el('details');
    if (open) d.open = true;
    d.append(el('summary', {}, label, meta ? el('span', { class: 'meta', text: meta }) : null));
    const kv = el('div', { class: 'kv' });
    const entries = Array.isArray(v) ? v.map((x, i) => [String(i), x]) : Object.entries(v || {});
    for (const [k, x] of entries) {
      if (x && typeof x === 'object' && !isScalarArray(x)) {
        const n = Array.isArray(x) ? `[${x.length}]` : `{${Object.keys(x).length}}`;
        kv.append(tree(k, x, n, false));
      } else {
        kv.append(el('div', { class: 'key', text: k }), valueNode(Array.isArray(x) ? x.join(', ') : x));
      }
    }
    d.append(kv);
    return d;
  }

  function renderTree(rep) {
    const root = $('tree');
    root.replaceChildren();
    const sections = [
      ['Hashes', rep.hashes], ['Timing', rep.timing], ['Network', rep.network], ['TCP/IP', rep.tcp], ['TLS', rep.tls],
      ['HTTP/2', rep.http2], ['HTTP/3 / QUIC', rep.http3], ['HTTP request', rep.http], ['Page (navigation) request', rep.navigation],
    ];
    for (const [name, v] of sections) if (v) root.append(tree(name, v, null, name === 'Hashes'));
    const comps = rep.client && rep.client.components;
    if (comps) {
      const d = el('details', { open: '' });
      d.append(el('summary', {}, 'JavaScript components', el('span', { class: 'meta', text: `${Object.keys(comps).length} probes · ${rep.client.duration_ms} ms` })));
      const inner = el('div', { class: 'kv' });
      for (const [name, c] of Object.entries(comps)) {
        const meta = (c.error ? 'error: ' + c.error : '') + (c.hash ? ` #${c.hash}` : '') + (c.duration_ms != null ? ` · ${c.duration_ms} ms` : '');
        const val = c.value && typeof c.value === 'object' ? c.value : { value: c.value === undefined ? null : c.value };
        inner.append(tree(name, val, meta, false));
      }
      d.append(inner);
      root.append(d);
    }
    if (rep.libraries) {
      for (const [name, v] of Object.entries(rep.libraries)) root.append(tree('Library: ' + name, v, v.visitorId || v.thumbmark || v.error || '', false));
    }
    $('details').hidden = false;
  }

  function render(rep) {
    lastReport = rep;
    renderSummary(rep);
    renderAnalysis(rep);
    renderTree(rep);
  }

  function showPermalink(rep) {
    const p = $('permalink');
    p.replaceChildren(
      el('div', {}, el('b', { text: 'Saved. ' }), 'Permalink: ', el('a', { href: rep.permalink, text: rep.permalink })),
      el('div', { class: 'muted' }, 'JSON: ', el('a', { href: rep.api_url, text: rep.api_url })));
    p.hidden = false;
  }

  // ---------- actions ----------
  async function gather() {
    const opts = { webrtc: $('opt-webrtc').checked, libraries: $('opt-libs').checked };
    if (!opts.libraries) { delete window.FingerprintJS; delete window.ThumbmarkJS; }
    let done = 0;
    const total = window.FPCollect.order.length;
    opts.onProgress = (n) => status(`Collecting… ${++done}/${total} (${n})`);
    const data = await window.FPCollect.collect(opts);
    const label = $('opt-label').value.trim();
    if (label) data.label = label;
    const nonce = document.querySelector('meta[name="fp-nonce"]');
    if (nonce && !nonce.content.includes('{')) data.nonce = nonce.content;
    return data;
  }

  async function post(mode, payload) {
    const r = await fetch('/api/fingerprint?mode=' + mode, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), cache: 'no-store',
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  }

  async function run() {
    $('btn-run').disabled = $('btn-save').disabled = true;
    try {
      status('Collecting…');
      lastPayload = await gather();
      const mode = params.get('mode') === 'store' ? 'store' : 'echo';
      status('Analysing…');
      const rep = await post(mode, lastPayload);
      render(rep);
      if (rep.id) showPermalink(rep);
      status(`Done in ${lastPayload.client.duration_ms} ms.` + (rep.id ? ' Stored.' : ' Not stored.'));
    } catch (e) {
      status('Error: ' + e.message);
    } finally {
      $('btn-run').disabled = $('btn-save').disabled = false;
    }
  }

  async function save() {
    if (!lastPayload) return run();
    $('btn-save').disabled = true;
    try {
      status('Saving…');
      const label = $('opt-label').value.trim();
      if (label) lastPayload.label = label;
      const rep = await post('store', lastPayload);
      render(rep);
      showPermalink(rep);
      status('Stored as ' + rep.id + '.');
    } catch (e) {
      status('Error: ' + e.message);
    } finally {
      $('btn-save').disabled = false;
    }
  }

  // ---------- permalink view ----------
  async function view(id) {
    $('title').textContent = 'Stored fingerprint ' + id;
    $('opt-webrtc').parentElement.hidden = $('opt-libs').parentElement.hidden = $('opt-label').hidden = true;
    $('btn-save').hidden = true;
    $('btn-run').textContent = 'Compare with this browser now';
    $('btn-run').className = '';
    status('Loading…');
    const r = await fetch('/api/fingerprints/' + encodeURIComponent(id));
    const rep = await r.json();
    if (!r.ok) { status('Error: ' + (rep.error || r.statusText)); return; }
    $('subtitle').textContent = `Captured ${new Date(rep.created_at).toLocaleString()}` + (rep.label ? ` · label: ${rep.label}` : '') + ` · mode: ${rep.mode}`;
    render(rep);
    status('');
    loadRelated(id);
    $('btn-run').onclick = () => compareNow(rep);
  }

  async function loadRelated(id) {
    try {
      const r = await fetch('/api/fingerprints/' + encodeURIComponent(id) + '/related');
      if (!r.ok) return;
      const j = await r.json();
      const body = $('related-body');
      body.replaceChildren();
      let any = false;
      for (const [k, list] of Object.entries(j.related || {})) {
        if (!list.length) continue;
        any = true;
        const ul = el('ul');
        for (const s of list) {
          ul.append(el('li', {}, el('a', { href: '/f/' + s.id, text: s.id }), ` · ${new Date(s.created_at).toLocaleString()} · ${s.ip}` + (s.label ? ` · ${s.label}` : '')));
        }
        body.append(el('div', { class: 'related-group' }, el('h3', { text: `Same ${k} (${list.length})` }), ul));
      }
      if (!any) body.append(el('p', { class: 'muted', text: 'No other stored fingerprints share these identifiers.' }));
      $('related').hidden = false;
    } catch (e) { /* history is optional */ }
  }

  async function compareNow(stored) {
    $('btn-run').disabled = true;
    try {
      status('Collecting this browser…');
      const now = await post('echo', await gather());
      const body = $('compare-body');
      body.replaceChildren();
      const keys = [...new Set([...Object.keys(stored.hashes || {}), ...Object.keys(now.hashes || {})])].sort();
      for (const k of keys) {
        const a = stored.hashes[k] || '', b = now.hashes[k] || '';
        body.append(el('tr', {}, el('td', { text: k }), el('td', { class: 'mono', text: a }), el('td', { class: 'mono', text: b }),
          el('td', { class: a === b ? 'st-pass' : 'st-fail', text: a === b ? 'same' : 'differs' })));
      }
      $('compare').hidden = false;
      $('compare').scrollIntoView({ behavior: 'smooth' });
      status('Compared.');
    } catch (e) {
      status('Error: ' + e.message);
    } finally {
      $('btn-run').disabled = false;
    }
  }

  // ---------- wiring ----------
  $('btn-expand').onclick = () => document.querySelectorAll('#tree details').forEach((d) => (d.open = true));
  $('btn-collapse').onclick = () => document.querySelectorAll('#tree details').forEach((d) => (d.open = false));
  $('btn-copy').onclick = async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2)); status('Copied JSON to clipboard.'); }
    catch (e) { status('Copy failed: ' + e.message); }
  };
  $('btn-download').onclick = () => {
    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: 'fingerprint-' + (lastReport.id || Date.now()) + '.json' });
    document.body.append(a); a.click(); a.remove();
  };
  if (params.get('label')) $('opt-label').value = params.get('label');
  if (params.get('webrtc') === '0') $('opt-webrtc').checked = false;
  if (params.get('libs') === '0') $('opt-libs').checked = false;

  if (viewMatch) {
    view(viewMatch[1]);
  } else {
    $('btn-run').onclick = run;
    $('btn-save').onclick = save;
    if (params.get('auto') !== '0') run(); else status('Press "Run again" to collect.');
  }
})();
