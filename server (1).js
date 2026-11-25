import http from 'node:http';
import dns from 'node:dns/promises';
import net from 'node:net';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import * as cheerio from 'cheerio';
import { CookieJar } from 'tough-cookie';

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '127.0.0.1'; // only this machine; a tunnel or Caddy reaches it
const AUTH_USER = process.env.AUTH_USER || '';
const AUTH_PASS = process.env.AUTH_PASS || '';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1'; // only for local testing

if (!['127.0.0.1', 'localhost', '::1'].includes(HOST) && !(AUTH_USER && AUTH_PASS)) {
  console.error('Refusing to listen publicly: set AUTH_USER and AUTH_PASS first.');
  process.exit(1);
}

function authorized(req) {
  if (!AUTH_USER || !AUTH_PASS) return true;
  const m = /^Basic (.+)$/i.exec(req.headers.authorization || '');
  if (!m) return false;
  const hash = (s) => crypto.createHash('sha256').update(s).digest();
  return crypto.timingSafeEqual(hash(Buffer.from(m[1], 'base64').toString()), hash(`${AUTH_USER}:${AUTH_PASS}`));
}
const PATH = '/proxy';
const PREFIX = `${PATH}?url=`;
const SKIP = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;
const jars = new Map(); // session id -> CookieJar (in memory)

// ---------- browser shell (tabs, address bar, tab disguise) ----------
const LANDING = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inbox</title>
<link rel="icon" id="fav" href="data:,">
<style>
:root{--strip:#dee1e6;--bar:#fff;--ink:#202124;--muted:#5f6368;--pill:#f1f3f4;--line:#dadce0;--accent:#1a73e8;--onacc:#fff;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--strip:#202124;--bar:#35363a;--ink:#e8eaed;--muted:#9aa0a6;--pill:#202124;--line:#4a4c50;--accent:#8ab4f8;--onacc:#202124;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;background:var(--bar);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}
#strip{display:flex;align-items:flex-end;gap:2px;background:var(--strip);padding:8px 8px 0;overflow-x:auto;flex:none}
.tab{display:flex;align-items:center;gap:8px;flex:0 1 200px;min-width:90px;height:34px;padding:0 6px 0 12px;border-radius:10px 10px 0 0;color:var(--muted);cursor:pointer}
.tab:hover{background:color-mix(in srgb,var(--bar) 45%,transparent)}
.tab.on{background:var(--bar);color:var(--ink)}
.tab .t{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tab .x{border:0;background:transparent;color:inherit;width:20px;height:20px;border-radius:50%;cursor:pointer;font-size:15px;line-height:1}
.tab .x:hover{background:var(--line)}
#plus{flex:none;border:0;background:transparent;color:var(--muted);width:32px;height:32px;margin-bottom:1px;border-radius:50%;font-size:20px;cursor:pointer}
#plus:hover{background:color-mix(in srgb,var(--bar) 45%,transparent)}
#bar{display:flex;align-items:center;gap:6px;padding:6px 10px;background:var(--bar);border-bottom:1px solid var(--line);flex:none}
.nav{border:0;background:transparent;color:var(--ink);width:32px;height:32px;border-radius:50%;cursor:pointer;font-size:18px}
.nav:hover{background:var(--pill)}
#addr{flex:1;min-width:0;height:36px;border:2px solid transparent;border-radius:18px;background:var(--pill);color:var(--ink);font:inherit;padding:0 16px;outline:0}
#addr:focus{border-color:var(--accent);background:var(--bar)}
select{height:32px;border:1px solid var(--line);border-radius:8px;background:var(--bar);color:var(--ink);font:inherit;padding:0 6px}
#view{flex:1;position:relative;min-height:0}
iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#fff}
#home{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;gap:28px;padding:24px;background:var(--bar)}
#home h1{margin:0;font:600 clamp(2.6rem,9vw,4.5rem)/1 system-ui,sans-serif;letter-spacing:-.03em}
#home input{width:min(580px,100%);height:48px;border:1px solid var(--line);border-radius:24px;background:var(--bar);color:var(--ink);font:inherit;font-size:16px;padding:0 22px;outline:0;box-shadow:0 1px 6px rgba(32,33,36,.2)}
#home input:focus{border-color:var(--accent)}
button:focus-visible,select:focus-visible,.tab:focus-visible{outline:2px solid var(--accent)}
dialog{width:min(420px,92vw);border:1px solid var(--line);border-radius:14px;background:var(--bar);color:var(--ink);padding:20px}
dialog::backdrop{background:rgba(0,0,0,.45)}
dialog h2{margin:0 0 14px;font-size:18px}
dialog label{display:block;margin:0 0 12px}
dialog label input{display:block;width:100%;margin-top:6px;font:inherit;color:inherit}
#ctitle{height:36px;border:1px solid var(--line);border-radius:8px;background:var(--pill);padding:0 10px}
.prev{display:flex;align-items:center;gap:10px;margin:0 0 14px;color:var(--muted)}
.crow{display:flex;align-items:center;gap:10px;margin:0 0 8px}
.crow span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
dialog button{height:34px;border:1px solid var(--line);border-radius:8px;background:var(--pill);color:var(--ink);font:inherit;padding:0 14px;cursor:pointer}
#csave{background:var(--accent);border-color:var(--accent);color:var(--onacc)}
</style></head>
<body>
<div id="strip" role="tablist"><button id="plus" title="New tab" aria-label="New tab">+</button></div>
<div id="bar">
<button class="nav" id="back" title="Back" aria-label="Back">←</button>
<button class="nav" id="fwd" title="Forward" aria-label="Forward">→</button>
<button class="nav" id="rel" title="Reload" aria-label="Reload">↻</button>
<input id="addr" placeholder="Search or enter a web address" autocomplete="off" aria-label="Address">
<select id="cloak" title="Browser tab disguise" aria-label="Browser tab disguise"></select>
</div>
<div id="view"><div id="home"><h1>Relay</h1><input id="q" placeholder="Search or enter a web address" autocomplete="off" aria-label="Search"></div></div>
<dialog id="dlg">
<h2>Custom tab disguise</h2>
<label>Tab title<input id="ctitle" maxlength="60" placeholder="For example: Inbox (3)" autocomplete="off"></label>
<label>Icon (optional)<input id="cicon" type="file" accept="image/*"></label>
<div class="prev"><img id="cprev" alt="" width="32" height="32"><span>Preview of the tab icon</span></div>
<div id="clist"></div>
<div class="row"><button id="cclose" type="button">Close</button><button id="csave" type="button">Save and use</button></div>
</dialog>
<script>
(function () {
  var PRE = '/proxy?url=';
  var $ = function (s) { return document.querySelector(s); };
  var strip = $('#strip'), view = $('#view'), home = $('#home'), addr = $('#addr'), q = $('#q'), fav = $('#fav');
  var tabs = [], cur = null;

  var ICONS = {
    Inbox: '<rect x="2" y="5" width="20" height="14" rx="2" fill="#d93025"/><path d="M3 7l9 6 9-6" stroke="#fff" stroke-width="2" fill="none"/>',
    Documents: '<rect x="5" y="2" width="14" height="20" rx="2" fill="#1a73e8"/><path d="M8 8h8M8 12h8M8 16h5" stroke="#fff" stroke-width="2"/>',
    Calendar: '<rect x="3" y="4" width="18" height="17" rx="2" fill="#188038"/><path d="M3 9h18M8 13h3M13 13h3M8 17h3" stroke="#fff" stroke-width="2"/>',
    Notes: '<rect x="4" y="3" width="16" height="18" rx="2" fill="#f9ab00"/><path d="M8 9h8M8 13h8" stroke="#fff" stroke-width="2"/>'
  };
  var customs = [], dlg = $('#dlg'), pendingIcon = '';
  function loadCustoms() { try { customs = JSON.parse(localStorage.getItem('relay-customs') || '[]'); } catch (e) { customs = []; } }
  function saveCustoms() { try { localStorage.setItem('relay-customs', JSON.stringify(customs)); } catch (e) {} }
  function svgIcon(body) { return 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' + body + '</svg>'); }
  function findCustom(name) { for (var i = 0; i < customs.length; i++) if (customs[i].name === name) return customs[i]; return null; }
  function applyCloak(name) {
    var c = findCustom(name);
    if (!c && !ICONS[name]) name = 'Inbox';
    document.title = name;
    fav.href = c && c.icon ? c.icon : svgIcon(ICONS[c ? 'Inbox' : name]);
    $('#cloak').value = name;
    try { localStorage.setItem('relay-cloak', name); } catch (e) {}
  }
  function fillSelect() {
    var s = $('#cloak'), o;
    s.innerHTML = '';
    Object.keys(ICONS).concat(customs.map(function (c) { return c.name; })).forEach(function (n) {
      o = document.createElement('option'); o.textContent = n; o.value = n; s.appendChild(o);
    });
    o = document.createElement('option'); o.textContent = 'Custom…'; o.value = '__new'; s.appendChild(o);
  }
  // Shrinks an uploaded image to a small square so it fits in browser storage.
  function readIcon(file, done) {
    var r = new FileReader();
    r.onload = function () {
      var img = new Image();
      img.onload = function () {
        try {
          var w = img.naturalWidth || 64, h = img.naturalHeight || 64, s = Math.min(w, h);
          var c = document.createElement('canvas'); c.width = c.height = 64;
          c.getContext('2d').drawImage(img, (w - s) / 2, (h - s) / 2, s, s, 0, 0, 64, 64);
          done(c.toDataURL('image/png'));
        } catch (e) { done(''); }
      };
      img.onerror = function () { done(''); };
      img.src = r.result;
    };
    r.onerror = function () { done(''); };
    r.readAsDataURL(file);
  }
  function drawList() {
    var l = $('#clist');
    l.innerHTML = '';
    customs.forEach(function (c) {
      var row = document.createElement('div'), im = document.createElement('img'), sp = document.createElement('span'), b = document.createElement('button');
      row.className = 'crow'; im.width = 20; im.height = 20; im.alt = ''; im.src = c.icon || svgIcon(ICONS.Inbox);
      sp.textContent = c.name; b.type = 'button'; b.textContent = 'Remove';
      b.onclick = function () {
        customs = customs.filter(function (x) { return x !== c; });
        saveCustoms(); fillSelect(); drawList();
        if (document.title === c.name) applyCloak('Inbox'); else $('#cloak').value = document.title;
      };
      row.appendChild(im); row.appendChild(sp); row.appendChild(b); l.appendChild(row);
    });
  }
  function openDialog() {
    pendingIcon = ''; $('#ctitle').value = ''; $('#cicon').value = ''; $('#cprev').src = svgIcon(ICONS.Inbox);
    drawList(); dlg.showModal(); $('#ctitle').focus();
  }
  $('#cicon').onchange = function () {
    var f = this.files && this.files[0];
    if (!f) return;
    readIcon(f, function (url) { if (url) { pendingIcon = url; $('#cprev').src = url; } else alert('That file could not be used as an icon.'); });
  };
  $('#csave').onclick = function () {
    var name = $('#ctitle').value.trim(), c;
    if (!name) { $('#ctitle').focus(); return; }
    c = findCustom(name);
    if (c) { if (pendingIcon) c.icon = pendingIcon; } else customs.push({ name: name, icon: pendingIcon });
    saveCustoms(); fillSelect(); applyCloak(name); dlg.close();
  };
  $('#cclose').onclick = function () { dlg.close(); };
  dlg.onclose = function () { $('#cloak').value = document.title; };

  function target(s) {
    s = s.trim();
    if (/^https?:\/\//i.test(s)) return s;
    if (/^[^\s\/]+\.[^\s\/]+(\/\S*)?$/.test(s)) return 'https://' + s;
    return 'https://duckduckgo.com/html/?q=' + encodeURIComponent(s);
  }
  function realUrl(href) {
    try {
      var u = new URL(href);
      if (u.pathname !== '/proxy') return '';
      var f = u.searchParams.get('__pxform');
      if (f) { u.searchParams.delete('__pxform'); var d = new URL(f); d.search = u.searchParams.toString(); return d.href; }
      return u.searchParams.get('url') || '';
    } catch (e) { return ''; }
  }
  function host(u) { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return u; } }

  function newTab() {
    var t = { url: '', title: 'New tab', started: false, frame: document.createElement('iframe'), el: null };
    t.frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-modals allow-downloads');
    t.frame.style.display = 'none';
    view.appendChild(t.frame);
    tabs.push(t);
    select(t);
    return t;
  }
  function load(t, src) { t.started = true; t.title = 'Loading…'; t.frame.src = src; draw(); }
  function visit(t, text) { load(t, PRE + encodeURIComponent(target(text))); }
  function select(t) { cur = t; draw(); if (!t.started) q.focus(); }
  function closeTab(t) {
    var i = tabs.indexOf(t);
    t.frame.remove();
    if (t.el) t.el.remove();
    tabs.splice(i, 1);
    if (!tabs.length) { newTab(); return; }
    if (cur === t) cur = tabs[Math.max(0, i - 1)];
    draw();
  }

  function draw() {
    tabs.forEach(function (t) {
      if (!t.el) {
        t.el = document.createElement('div');
        t.el.setAttribute('role', 'tab');
        t.el.tabIndex = 0;
        t.el.innerHTML = '<span class="t"></span><button class="x" aria-label="Close tab">×</button>';
        t.el.onclick = function () { select(t); };
        t.el.onkeydown = function (e) { if (e.key === 'Enter' && e.target === t.el) select(t); };
        t.el.querySelector('.x').onclick = function (e) { e.stopPropagation(); closeTab(t); };
        strip.insertBefore(t.el, $('#plus'));
      }
      t.el.querySelector('.t').textContent = t.title;
      t.el.className = 'tab' + (t === cur ? ' on' : '');
      t.frame.style.display = t === cur && t.started ? 'block' : 'none';
    });
    home.style.display = cur && !cur.started ? 'flex' : 'none';
    if (document.activeElement !== addr) addr.value = cur ? cur.url : '';
  }

  setInterval(function () {
    var changed = false;
    tabs.forEach(function (t) {
      if (!t.started) return;
      try {
        var real = realUrl(t.frame.contentWindow.location.href);
        if (!real) return;
        var title = t.frame.contentDocument.title || host(real);
        if (real !== t.url) { t.url = real; changed = true; }
        if (title !== t.title) { t.title = title; changed = true; }
      } catch (e) {}
    });
    if (changed) draw();
  }, 700);

  $('#plus').onclick = newTab;
  $('#back').onclick = function () { try { cur.frame.contentWindow.history.back(); } catch (e) {} };
  $('#fwd').onclick = function () { try { cur.frame.contentWindow.history.forward(); } catch (e) {} };
  $('#rel').onclick = function () { try { cur.frame.contentWindow.location.reload(); } catch (e) {} };
  addr.onfocus = function () { addr.select(); };
  addr.onkeydown = function (e) { if (e.key === 'Enter' && addr.value.trim()) { visit(cur, addr.value); addr.blur(); } };
  q.onkeydown = function (e) { if (e.key === 'Enter' && q.value.trim()) { visit(cur, q.value); q.value = ''; } };
  $('#cloak').onchange = function () { if (this.value === '__new') openDialog(); else applyCloak(this.value); };

  // Pages inside tabs call this to open links and pop-ups as new tabs here.
  window.__relayOpen = function (href) { load(newTab(), href); };

  loadCustoms(); fillSelect();
  var saved = 'Inbox';
  try { saved = localStorage.getItem('relay-cloak') || 'Inbox'; } catch (e) {}
  applyCloak(saved);
  newTab();
})();
</script>
</body></html>
`;

// ---------- URL rewriting ----------
function toProxy(raw, base) {
  if (raw == null) return raw;
  const s = String(raw).trim();
  if (!s || SKIP.test(s)) return raw;
  let u;
  try { u = new URL(s, base); } catch { return raw; }
  if (!/^https?:$/.test(u.protocol)) return raw;
  const hash = u.hash;
  u.hash = '';
  return PREFIX + encodeURIComponent(u.href) + hash;
}

function rewriteSrcset(v, base) {
  return v.split(',').map((part) => {
    const [u, ...d] = part.trim().split(/\s+/);
    return [toProxy(u, base), ...d].join(' ');
  }).join(', ');
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${toProxy(u, base)}${q})`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${toProxy(u, base)}${q}`);
}

// Runs inside the proxied page: catches URLs that scripts build at runtime.
function clientPatch(PREFIX, BASE) {
  const skip = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;
  const px = (raw) => {
    try {
      const s = String(raw).trim();
      if (!s || skip.test(s) || s.startsWith(PREFIX) || s.startsWith(location.origin + PREFIX)) return raw;
      const u = new URL(s, BASE);
      if (!/^https?:$/.test(u.protocol)) return raw;
      const hash = u.hash;
      u.hash = '';
      return PREFIX + encodeURIComponent(u.href) + hash;
    } catch { return raw; }
  };

  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    if (typeof input === 'string' || input instanceof URL) input = px(input);
    return _fetch.call(this, input, init);
  };

  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u, ...rest) { return _open.call(this, m, px(u), ...rest); };

  const attrs = new Set(['src', 'href', 'action', 'poster', 'data-src']);
  const _set = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    return _set.call(this, n, attrs.has(String(n).toLowerCase()) ? px(v) : v);
  };

  const props = [
    [HTMLAnchorElement, 'href'], [HTMLLinkElement, 'href'], [HTMLImageElement, 'src'],
    [HTMLScriptElement, 'src'], [HTMLIFrameElement, 'src'], [HTMLSourceElement, 'src'],
    [HTMLMediaElement, 'src'], [HTMLFormElement, 'action'],
  ];
  for (const [C, p] of props) {
    const d = Object.getOwnPropertyDescriptor(C.prototype, p);
    if (d && d.set) Object.defineProperty(C.prototype, p, { ...d, set(v) { d.set.call(this, px(v)); } });
  }

  let T = null;
  try { if (window.top !== window && window.top.__relayOpen) T = window.top; } catch { /* not inside the tab shell */ }
  const _win = window.open;
  window.open = function (u, ...rest) {
    if (T && u) { T.__relayOpen(new URL(px(u), location.href).href); return null; }
    return _win.call(window, u ? px(u) : u, ...rest);
  };
  document.addEventListener('click', (e) => {
    const a = T && e.target.closest ? e.target.closest('a[target="_blank"]') : null;
    if (a && a.href) { e.preventDefault(); T.__relayOpen(a.href); }
  }, true);
  for (const k of ['pushState', 'replaceState']) {
    const f = history[k];
    history[k] = function (s, t, u) { return f.call(this, s, t, u == null ? u : px(u)); };
  }
}
const CLIENT_TEMPLATE = `(${clientPatch.toString()})(${JSON.stringify(PREFIX)}, __BASE__)`;

const URL_ATTRS = ['href', 'src', 'action', 'poster', 'data-src'];
const URL_SELECTOR = '[href],[src],[action],[poster],[data-src],[srcset]';

function rewriteHtml(html, pageUrl) {
  const $ = cheerio.load(html);
  const baseHref = $('base[href]').first().attr('href');
  const base = baseHref ? new URL(baseHref, pageUrl).href : pageUrl;
  $('base').remove();

  $('meta[http-equiv]').each((_, el) => {
    const kind = ($(el).attr('http-equiv') || '').toLowerCase();
    if (kind === 'content-security-policy') $(el).remove();
    if (kind === 'refresh') {
      $(el).attr('content', ($(el).attr('content') || '').replace(
        /(url=)\s*(.+)$/i, (m, p, u) => p + toProxy(u.replace(/^['"]|['"]$/g, ''), base)));
    }
  });

  $(URL_SELECTOR).each((_, el) => {
    const $el = $(el);
    for (const a of URL_ATTRS) {
      const v = $el.attr(a);
      if (v != null) $el.attr(a, toProxy(v, base));
    }
    const ss = $el.attr('srcset');
    if (ss) $el.attr('srcset', rewriteSrcset(ss, base));
    $el.removeAttr('integrity').removeAttr('nonce');
  });

  // A GET form replaces the action's query string on submit, which would drop ?url=.
  // Carry the real destination in a hidden field instead and rebuild it in proxy().
  $('form').each((_, el) => {
    const $f = $(el);
    if (($f.attr('method') || 'get').toLowerCase() !== 'get') return;
    const a = $f.attr('action') || '';
    const dest = a === '' ? pageUrl
      : a.startsWith(PREFIX) ? decodeURIComponent(a.slice(PREFIX.length).split('#')[0]) : null;
    if (!dest) return;
    const safe = dest.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
    $f.attr('action', PATH).prepend(`<input type="hidden" name="__pxform" value="${safe}">`);
  });

  $('style').each((_, el) => { $(el).text(rewriteCss($(el).text(), base)); });
  $('[style]').each((_, el) => { $(el).attr('style', rewriteCss($(el).attr('style'), base)); });

  const baseJson = JSON.stringify(base).replace(/</g, '\\u003c');
  const script = CLIENT_TEMPLATE.replace('__BASE__', () => baseJson);
  $('head').prepend(`<script>${script}</script>`);
  return $.html();
}

// ---------- safety: don't let the proxy reach private networks ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) {
    const rest = v.slice(7);
    return net.isIPv4(rest) ? isPrivateIp(rest) : true;
  }
  return v === '::1' || v === '::' || /^f[cd]/.test(v) || v.startsWith('fe80');
}

async function assertPublic(hostname) {
  if (ALLOW_PRIVATE) return;
  const host = hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('Blocked: private or local address');
}

// ---------- helpers ----------
function getJar(req, res) {
  const m = /(?:^|;\s*)__pxsid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  let id = m && m[1];
  if (!id || !jars.has(id)) {
    id = crypto.randomBytes(16).toString('hex');
    jars.set(id, new CookieJar());
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `__pxsid=${id}; Path=/; HttpOnly; SameSite=Lax${secure}`);
  }
  return jars.get(id);
}

function realFromProxyUrl(ref) {
  try {
    const u = new URL(ref);
    return u.pathname === PATH ? u.searchParams.get('url') : null;
  } catch { return null; }
}

function decode(buf, type) {
  const label = /charset=["']?([\w-]+)/i.exec(type)?.[1] || 'utf-8';
  try { return new TextDecoder(label).decode(buf); } catch { return new TextDecoder().decode(buf); }
}

function page(res, status, text) {
  if (res.headersSent) return res.end();
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<body style="font:17px system-ui;max-width:560px;margin:15vh auto;padding:0 20px">
<h2>Could not open that page</h2><p>${text.replace(/[<>&]/g, '')}</p><p><a href="/">Back to start</a></p></body>`);
}

const DROP = new Set([
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'set-cookie',
  'content-encoding', 'transfer-encoding', 'connection', 'strict-transport-security',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'permissions-policy', 'report-to', 'nel', 'clear-site-data',
]);

// ---------- routes ----------
function go(url, res) {
  const q = (url.searchParams.get('q') || '').trim();
  if (!q) { res.writeHead(302, { Location: '/' }); return res.end(); }
  let target;
  if (/^https?:\/\//i.test(q)) target = q;
  else if (/^[^\s/]+\.[^\s/]+(\/\S*)?$/.test(q)) target = `https://${q}`;
  else target = `https://duckduckgo.com/html/?q=${encodeURIComponent(q)}`;
  res.writeHead(302, { Location: PREFIX + encodeURIComponent(target) });
  res.end();
}

async function proxy(req, res, url) {
  let raw = url.searchParams.get('url');
  if (url.searchParams.has('__pxform')) {
    try {
      const dest = new URL(url.searchParams.get('__pxform'));
      url.searchParams.delete('__pxform');
      dest.search = url.searchParams.toString();
      raw = dest.href;
    } catch { /* falls through to the invalid-address page */ }
  }
  let target;
  try { target = new URL(raw); } catch { return page(res, 400, 'That is not a valid web address.'); }
  if (!/^https?:$/.test(target.protocol)) return page(res, 400, 'Only http and https addresses work.');
  await assertPublic(target.hostname);

  const jar = getJar(req, res);
  const headers = {};
  for (const h of ['user-agent', 'accept', 'accept-language', 'content-type', 'range']) {
    if (req.headers[h]) headers[h] = req.headers[h];
  }
  const realRef = realFromProxyUrl(req.headers.referer);
  if (realRef) {
    headers.referer = realRef;
    if (req.headers.origin) headers.origin = new URL(realRef).origin;
  } else if (req.headers.origin) {
    headers.origin = target.origin;
  }
  const cookie = await jar.getCookieString(target.href);
  if (cookie) headers.cookie = cookie;

  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = Buffer.concat(chunks);
  }

  const ac = new AbortController();
  res.on('close', () => ac.abort());
  const timer = setTimeout(() => ac.abort(), 30000);
  const up = await fetch(target, { method: req.method, headers, body, redirect: 'manual', signal: ac.signal });
  clearTimeout(timer);

  for (const c of up.headers.getSetCookie()) await jar.setCookie(c, target.href, { ignoreError: true });

  const out = {};
  up.headers.forEach((v, k) => { if (!DROP.has(k)) out[k] = v; });
  if (out.location) out.location = toProxy(out.location, target.href);
  if (up.headers.get('content-encoding')) delete out['content-length'];

  const type = (up.headers.get('content-type') || '').toLowerCase();
  const dest = req.headers['sec-fetch-dest'];
  const isDocument = !dest || dest === 'document' || dest === 'iframe' || dest === 'frame';
  const isHtml = type.includes('text/html') && isDocument;
  const isCss = type.includes('text/css');

  if (req.method !== 'HEAD' && up.body && (isHtml || isCss)) {
    const text = decode(await up.arrayBuffer(), type);
    const result = isHtml ? rewriteHtml(text, target.href) : rewriteCss(text, target.href);
    delete out['content-length'];
    out['content-type'] = `${isHtml ? 'text/html' : 'text/css'}; charset=utf-8`;
    res.writeHead(up.status, out);
    return res.end(result);
  }

  res.writeHead(up.status, out);
  if (!up.body || req.method === 'HEAD') return res.end();
  await pipeline(Readable.fromWeb(up.body), res).catch(() => {});
}

http.createServer(async (req, res) => {
  try {
    if (!authorized(req)) {
      res.writeHead(401, { 'www-authenticate': 'Basic realm="Relay", charset="UTF-8"', 'content-type': 'text/plain' });
      return res.end('Login required');
    }
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(LANDING);
    }
    if (url.pathname === '/go') return go(url, res);
    if (url.pathname === PATH) return await proxy(req, res, url);
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  } catch (err) {
    page(res, 502, String(err.message || err));
  }
}).listen(PORT, HOST, () => console.log(`Relay running on http://${HOST}:${PORT}`));
