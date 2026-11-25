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

// ---------- landing page ----------
const LANDING = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relay</title>
<style>
:root{--bg:#eef1f6;--ink:#14213d;--muted:#56627d;--line:#c9d1e2;--accent:#2b59ff;--onaccent:#fff;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1522;--ink:#e7ecf7;--muted:#98a4c0;--line:#2a3550;--accent:#7ea2ff;--onaccent:#0f1522;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font:17px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}
main{width:min(680px,100%)}
h1{font:600 clamp(2rem,6vw,3.2rem)/1.1 ui-serif,Georgia,"Times New Roman",serif;letter-spacing:-.02em;margin:0 0 28px}
form{display:flex;border:2px solid var(--ink);border-radius:14px;overflow:hidden;background:var(--bg)}
form:focus-within{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 25%,transparent)}
input{flex:1;min-width:0;border:0;background:transparent;color:var(--ink);font:inherit;font-size:1.15rem;padding:18px 20px;outline:0}
input::placeholder{color:var(--muted)}
button{border:0;background:var(--accent);color:var(--onaccent);font:inherit;font-weight:600;padding:0 28px;cursor:pointer}
button:focus-visible{outline:3px solid var(--ink);outline-offset:-3px}
p{color:var(--muted);margin:18px 2px 0;max-width:60ch;font-size:.95rem}
</style></head>
<body><main>
<h1>Open any page through this server.</h1>
<form action="/go" method="get">
<input name="q" type="text" placeholder="Enter a web address or search" autocomplete="off" autofocus aria-label="Web address or search">
<button type="submit">Open</button>
</form>
<p>Works for most pages. Sites that rely on WebSockets, DRM video, or strict bot checks may not load.</p>
</main></body></html>`;

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

  const _win = window.open;
  window.open = function (u, ...rest) { return _win.call(window, u ? px(u) : u, ...rest); };
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
