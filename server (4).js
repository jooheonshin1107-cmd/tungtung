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

const AUTH_ON = Boolean(AUTH_USER && AUTH_PASS);
const SECRET = crypto.createHash('sha256').update(`relay:${AUTH_USER}:${AUTH_PASS}`).digest();
const sign = (exp) => crypto.createHmac('sha256', SECRET).update(String(exp)).digest('hex');
const hash = (s) => crypto.createHash('sha256').update(s).digest();
const failures = new Map(); // ip -> times of recent failed sign-ins
const WEEK30 = 30 * 24 * 3600;

// A signed cookie proves you signed in. It is derived from your password, so it survives restarts.
function authorized(req) {
  if (!AUTH_ON) return true;
  const m = /(?:^|;\s*)__pxauth=(\d+)\.([a-f0-9]{64})/.exec(req.headers.cookie || '');
  if (!m || Number(m[1]) < Date.now()) return false;
  return crypto.timingSafeEqual(Buffer.from(sign(m[1])), Buffer.from(m[2]));
}

function loginPage(msg) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inbox</title>
<style>
:root{--bg:#fff;--ink:#202124;--line:#dadce0;--accent:#1a73e8;--onacc:#fff;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#202124;--ink:#e8eaed;--line:#4a4c50;--accent:#8ab4f8;--onacc:#202124;color-scheme:dark}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}
form{width:min(340px,100%);display:grid;gap:12px}
h1{margin:0 0 4px;font-size:24px;font-weight:600}
input{height:42px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;padding:0 12px}
input:focus{outline:2px solid var(--accent);border-color:transparent}
button{height:42px;border:0;border-radius:21px;background:var(--accent);color:var(--onacc);font:inherit;font-weight:600;cursor:pointer}
p{margin:0;color:#d93025}
</style></head><body>
<form method="post" action="/login"><h1>Sign in</h1>${msg ? `<p>${msg}</p>` : ''}
<input name="user" placeholder="Username" autocomplete="username" autofocus aria-label="Username">
<input name="pass" type="password" placeholder="Password" autocomplete="current-password" aria-label="Password">
<button type="submit">Sign in</button></form></body></html>`;
}

async function login(req, res) {
  const send = (status, msg) => { res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' }); res.end(loginPage(msg)); };
  if (req.method !== 'POST') return send(200, '');
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
  const now = Date.now();
  const recent = (failures.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  if (recent.length >= 8) return send(429, 'Too many attempts. Try again in a few minutes.');
  let raw = '';
  for await (const c of req) { raw += c; if (raw.length > 4096) return send(413, 'Request too large.'); }
  const f = new URLSearchParams(raw);
  if (!crypto.timingSafeEqual(hash(`${f.get('user') || ''}:${f.get('pass') || ''}`), hash(`${AUTH_USER}:${AUTH_PASS}`))) {
    if (failures.size > 5000) failures.clear();
    recent.push(now);
    failures.set(ip, recent);
    return send(401, 'Wrong username or password.');
  }
  failures.delete(ip);
  const exp = now + WEEK30 * 1000;
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.writeHead(302, { Location: '/', 'Set-Cookie': `__pxauth=${exp}.${sign(exp)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${WEEK30}${secure}` });
  res.end();
}
const PATH = '/proxy';
const PREFIX = `${PATH}?url=`;
const SKIP = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;
const jars = new Map(); // session id -> CookieJar (in memory)

// ---------- browser shell (tabs, themes, address bar, tab disguise) ----------
const LANDING = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inbox</title>
<link rel="icon" id="fav" href="data:,">
<script>try{var p=localStorage.getItem('relay-theme')||'auto';document.documentElement.setAttribute('data-theme',p==='auto'?(matchMedia('(prefers-color-scheme: dark)').matches?'night':'daylight'):p)}catch(e){}</script>
<style>
:root,[data-theme=daylight]{--font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;--display:var(--font);color-scheme:light;--strip:#dee1e6;--bar:#fff;--ink:#202124;--muted:#5f6368;--pill:#f1f3f4;--line:#dadce0;--accent:#1a73e8;--onacc:#fff}
[data-theme=night]{color-scheme:dark;--strip:#1e1f22;--bar:#2b2d31;--ink:#e8eaed;--muted:#a0a4ab;--pill:#1e1f22;--line:#43464c;--accent:#8ab4f8;--onacc:#1e1f22}
[data-theme=paper]{--display:ui-serif,"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;--strip:#e6dfd0;--bar:#f6f1e6;--ink:#2b2620;--muted:#5e564b;--pill:#ece5d6;--line:#cfc6b3;--accent:#9b2c1f;--onacc:#f6f1e6}
[data-theme=sage]{--display:ui-serif,Georgia,serif;--strip:#d5ddd2;--bar:#f1f4ef;--ink:#1f2a22;--muted:#4f5d52;--pill:#e4eae1;--line:#bcc8b9;--accent:#2f6b3f;--onacc:#f1f4ef}
[data-theme=dusk]{color-scheme:dark;--strip:#131a26;--bar:#1c2536;--ink:#e6ebf5;--muted:#9aa6bd;--pill:#131a26;--line:#34425c;--accent:#f0b35a;--onacc:#131a26}
[data-theme=terminal]{color-scheme:dark;--font:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--display:var(--font);--strip:#050805;--bar:#0c110c;--ink:#c8f0c8;--muted:#7fae7f;--pill:#050805;--line:#1f3a1f;--accent:#39d65f;--onacc:#050805}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;background:var(--bar);color:var(--ink);font:14px/1.4 var(--font);transition:background-color .2s,color .2s}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.i{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
#strip{display:flex;align-items:flex-end;gap:2px;flex:none;padding:8px 8px 0;background:var(--strip);overflow-x:auto;scrollbar-width:none;transition:background-color .2s}
.tab{position:relative;display:flex;align-items:center;gap:8px;flex:0 1 220px;min-width:96px;height:36px;padding:0 6px 0 10px;border-radius:10px 10px 0 0;color:var(--muted);cursor:pointer;animation:tin .18s ease-out;transition:background-color .15s,color .15s,opacity .12s}
.tab:hover{background:color-mix(in srgb,var(--bar) 50%,transparent)}
.tab.on{background:var(--bar);color:var(--ink);box-shadow:inset 0 2px 0 var(--accent)}
.tab:not(.on)+.tab:not(.on)::before{content:"";position:absolute;left:-2px;top:10px;bottom:10px;width:1px;background:var(--line)}
.tab.out{opacity:0}
@keyframes tin{from{opacity:0;transform:translateY(5px)}}
.fi{position:relative;display:grid;place-items:center;width:16px;height:16px;flex:none;border-radius:4px;background:var(--pill);overflow:hidden}
.fi b{font:700 10px/1 var(--font);color:var(--muted)}
.fi img{position:absolute;inset:0;width:16px;height:16px;opacity:0}
.fi.ok img{opacity:1}
.t{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.x{display:grid;place-items:center;width:24px;height:24px;border:0;border-radius:50%;background:transparent;cursor:pointer;opacity:.75}
.x:hover{background:var(--line);opacity:1}
.x .i{width:12px;height:12px}
.nav{display:grid;place-items:center;width:36px;height:36px;border:0;border-radius:50%;background:transparent;cursor:pointer;transition:background-color .15s}
.nav:hover{background:var(--pill)}
.nav:disabled{opacity:.4;cursor:default}
.nav:disabled:hover{background:transparent}
#pin.on{color:var(--accent)}
#pin.on .i{fill:currentColor}
#plus{width:32px;height:32px;margin-bottom:2px;flex:none;color:var(--muted)}
#plus:hover{background:color-mix(in srgb,var(--bar) 50%,transparent)}
#bar{position:relative;display:flex;align-items:center;gap:4px;flex:none;padding:6px 10px;background:var(--bar);border-bottom:1px solid var(--line);transition:background-color .2s}
#addr{flex:1;min-width:0;height:36px;margin:0 4px;padding:0 16px;border:2px solid transparent;border-radius:18px;background:var(--pill);outline:0;transition:border-color .15s,background-color .15s}
#addr:focus{border-color:var(--accent);background:var(--bar)}
#prog{position:absolute;left:0;right:0;bottom:-1px;height:2px;background:var(--accent);transform:scaleX(0);transform-origin:left;opacity:0}
#prog.on{opacity:1;animation:prog 1.1s ease-in-out infinite}
@keyframes prog{0%{transform:scaleX(0)}70%{transform:scaleX(.85)}100%{transform:scaleX(1);opacity:.2}}
#view{position:relative;flex:1;min-height:0}
iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#fff}
#home{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;gap:22px;padding:24px 24px 12vh;background:var(--bar)}
#home>*{animation:rise .35s ease-out both}
#home>:nth-child(2){animation-delay:.06s}
#home>:nth-child(3){animation-delay:.12s}
#home>:nth-child(4){animation-delay:.18s}
@keyframes rise{from{opacity:0;transform:translateY(8px)}}
#home h1{margin:0;font:600 clamp(2.4rem,9vw,4.2rem)/1 var(--display);letter-spacing:-.035em}
.sb{position:relative;width:min(600px,100%)}
.sb .i{position:absolute;left:18px;top:16px;color:var(--muted)}
#q{width:100%;height:50px;padding:0 22px 0 50px;border:1px solid var(--line);border-radius:25px;background:var(--bar);font-size:16px;outline:0;box-shadow:0 1px 3px color-mix(in srgb,var(--ink) 14%,transparent);transition:box-shadow .15s,border-color .15s}
#q:hover{box-shadow:0 2px 8px color-mix(in srgb,var(--ink) 18%,transparent)}
#q:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 25%,transparent)}
#eng{margin:0;color:var(--muted);font-size:13px}
.pins{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:6px;width:min(600px,100%)}
.pins:empty{display:none}
.pin{position:relative}
.pb{display:grid;justify-items:center;gap:8px;width:100%;padding:14px 8px 10px;border:0;border-radius:14px;background:transparent;cursor:pointer;transition:background-color .15s}
.pb:hover{background:var(--pill)}
.pb span:last-child{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.pb .fi{width:44px;height:44px;border-radius:50%}
.pb .fi b{font-size:17px}
.pb .fi img{inset:10px;width:24px;height:24px}
.pin .x{position:absolute;top:4px;right:4px;opacity:0}
.pin:hover .x,.pin:focus-within .x{opacity:.75}
.pin .x:hover{opacity:1}
dialog{width:min(520px,94vw);max-height:90vh;overflow:auto;padding:0;border:1px solid var(--line);border-radius:14px;background:var(--bar);color:var(--ink);box-shadow:0 12px 40px rgba(0,0,0,.3)}
dialog[open]{animation:pop .2s ease-out}
dialog::backdrop{background:rgba(0,0,0,.45);animation:fade .2s ease-out}
@keyframes pop{from{opacity:0;transform:translateY(8px) scale(.98)}}
@keyframes fade{from{opacity:0}}
.dh{display:flex;align-items:center;justify-content:space-between;padding:12px 12px 12px 20px;border-bottom:1px solid var(--line)}
.dh h2{margin:0;font:600 20px/1.2 var(--display)}
.db{padding:4px 20px 20px}
.sec{padding:16px 0;border-bottom:1px solid var(--line)}
.sec:last-child{border:0;padding-bottom:0}
.sec h3{margin:0 0 12px;font:600 12px/1 var(--font);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.themes{display:grid;grid-template-columns:repeat(auto-fill,minmax(92px,1fr));gap:8px}
.swb{display:grid;gap:6px;justify-items:center;padding:6px;border:2px solid transparent;border-radius:12px;background:transparent;cursor:pointer}
.swb:hover{background:var(--pill)}
.swb[aria-checked=true]{border-color:var(--accent)}
.sw{position:relative;display:block;width:100%;height:46px;border:1px solid var(--line);border-radius:8px;background:var(--bar) linear-gradient(var(--muted),var(--muted)) 40px 33px/22px 3px no-repeat;overflow:hidden}
.sw::before{content:"";position:absolute;inset:0 0 auto;height:15px;background:var(--strip)}
.sw::after{content:"";position:absolute;left:8px;bottom:8px;width:26px;height:8px;border-radius:4px;background:var(--accent)}
.fld{display:block;width:100%;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:var(--pill)}
input[type=file].fld{height:auto;padding:8px 12px}
details{margin-top:12px}
summary{cursor:pointer;color:var(--accent);font-weight:600}
.lab{display:block;margin-top:12px}
.lab .fld{margin-top:6px}
.prev{display:flex;align-items:center;justify-content:space-between;margin-top:12px}
.btn{height:38px;padding:0 16px;border:1px solid var(--line);border-radius:19px;background:transparent;cursor:pointer}
.btn:hover{background:var(--pill)}
.btn.pri{border-color:var(--accent);background:var(--accent);color:var(--onacc)}
.crow{display:flex;align-items:center;gap:10px;margin-top:10px}
.crow span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (min-width:641px){[data-density=compact] .tab{height:32px}[data-density=compact] .nav{width:32px;height:32px}[data-density=compact] #plus{width:28px;height:28px}[data-density=compact] #addr{height:32px}[data-density=compact] #bar{padding:3px 8px}}
@media (max-width:640px){.nav{width:44px;height:44px}#addr{height:44px}.tab{flex-basis:160px;min-width:84px;height:40px}}
@media (prefers-reduced-motion:reduce){*,::before,::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
</style></head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-back" viewBox="0 0 24 24"><path d="M15 5l-7 7 7 7"/></symbol>
<symbol id="i-fwd" viewBox="0 0 24 24"><path d="M9 5l7 7-7 7"/></symbol>
<symbol id="i-rel" viewBox="0 0 24 24"><path d="M20 12a8 8 0 1 1-2.5-5.8M20 4v5h-5"/></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></symbol>
<symbol id="i-set" viewBox="0 0 24 24"><path d="M4 7h9M19 7h1M4 17h1M11 17h9"/><circle cx="16" cy="7" r="2.5"/><circle cx="8" cy="17" r="2.5"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/></symbol>
<symbol id="i-pin" viewBox="0 0 24 24"><path d="M7 4h10v16l-5-4-5 4z"/></symbol>
</defs></svg>
<div id="strip" role="tablist" aria-label="Tabs"><button id="plus" class="nav" title="New tab" aria-label="New tab"><svg class="i"><use href="#i-plus"/></svg></button></div>
<div id="bar">
<button class="nav" id="back" title="Back" aria-label="Back"><svg class="i"><use href="#i-back"/></svg></button>
<button class="nav" id="fwd" title="Forward" aria-label="Forward"><svg class="i"><use href="#i-fwd"/></svg></button>
<button class="nav" id="rel" title="Reload" aria-label="Reload"><svg class="i"><use href="#i-rel"/></svg></button>
<input id="addr" placeholder="Search or enter a web address" autocomplete="off" aria-label="Address">
<button class="nav" id="pin" title="Pin this page to the start page" aria-label="Pin this page" aria-pressed="false" disabled><svg class="i"><use href="#i-pin"/></svg></button>
<button class="nav" id="gear" title="Settings" aria-label="Settings"><svg class="i"><use href="#i-set"/></svg></button>
<div id="prog"></div>
</div>
<div id="view"><div id="home"><h1>Relay</h1><div class="sb"><svg class="i"><use href="#i-search"/></svg><input id="q" placeholder="Search or enter a web address" autocomplete="off" aria-label="Search"></div><p id="eng"></p><div id="pins" class="pins"></div></div></div>
<dialog id="dlg" aria-labelledby="dt">
<div class="dh"><h2 id="dt">Settings</h2><button class="nav" id="dx" aria-label="Close settings"><svg class="i"><use href="#i-x"/></svg></button></div>
<div class="db">
<section class="sec"><h3>Theme</h3><div class="themes" id="themes" role="radiogroup" aria-label="Theme"></div></section>
<section class="sec"><h3>Browser tab disguise</h3>
<select id="cloak" class="fld" aria-label="Tab disguise"></select>
<div id="clist"></div>
<details><summary>Add your own</summary>
<label class="lab">Tab title<input id="ctitle" class="fld" maxlength="60" placeholder="For example: Inbox (3)" autocomplete="off"></label>
<label class="lab">Icon (optional)<input id="cicon" class="fld" type="file" accept="image/*"></label>
<div class="prev"><img id="cprev" alt="Icon preview" width="32" height="32"><button class="btn pri" id="csave" type="button">Save and use</button></div>
</details></section>
<section class="sec"><h3>Search engine</h3><select id="engine" class="fld" aria-label="Search engine"></select></section>
<section class="sec"><h3>Layout</h3><select id="dens" class="fld" aria-label="Density"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></section>
</div></dialog>
<script>
(function () {
  var PRE = '/proxy?url=';
  var $ = function (s) { return document.querySelector(s); };
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };
  var root = document.documentElement, strip = $('#strip'), view = $('#view'), home = $('#home'), addr = $('#addr'), q = $('#q'), fav = $('#fav'), dlg = $('#dlg'), prog = $('#prog');
  var tabs = [], cur = null;

  var THEMES = [['auto', 'Auto'], ['daylight', 'Daylight'], ['night', 'Night'], ['paper', 'Paper'], ['sage', 'Sage'], ['dusk', 'Dusk'], ['terminal', 'Terminal']];
  var dark = window.matchMedia('(prefers-color-scheme: dark)');
  var themePref = store.get('relay-theme', 'auto');
  function resolved(p) { return p === 'auto' ? (dark.matches ? 'night' : 'daylight') : p; }
  function applyTheme(p) {
    themePref = p; store.set('relay-theme', p);
    root.setAttribute('data-theme', resolved(p));
    var bs = $('#themes').children;
    for (var i = 0; i < bs.length; i++) {
      bs[i].setAttribute('aria-checked', String(THEMES[i][0] === p));
      bs[i].firstChild.setAttribute('data-theme', resolved(THEMES[i][0]));
    }
  }
  function buildThemes() {
    THEMES.forEach(function (th) {
      var b = document.createElement('button'), s = document.createElement('span'), l = document.createElement('span');
      b.type = 'button'; b.className = 'swb'; b.setAttribute('role', 'radio');
      s.className = 'sw'; l.textContent = th[1];
      b.appendChild(s); b.appendChild(l);
      b.onclick = function () { applyTheme(th[0]); };
      $('#themes').appendChild(b);
    });
  }
  dark.addEventListener('change', function () { if (themePref === 'auto') applyTheme('auto'); });

  var ENGINES = { DuckDuckGo: 'https://duckduckgo.com/html/?q=', Bing: 'https://www.bing.com/search?q=' };
  function engine() { var e = store.get('relay-engine', 'DuckDuckGo'); return ENGINES[e] ? e : 'DuckDuckGo'; }
  function showEngine() { $('#eng').textContent = 'Searching with ' + engine(); }
  function fillEngines() {
    var s = $('#engine'), o;
    Object.keys(ENGINES).forEach(function (n) { o = document.createElement('option'); o.textContent = n; o.value = n; s.appendChild(o); });
    s.value = engine(); showEngine();
  }
  $('#engine').onchange = function () { store.set('relay-engine', this.value); showEngine(); };

  var ICONS = {
    Inbox: '<rect x="2" y="5" width="20" height="14" rx="2" fill="#d93025"/><path d="M3 7l9 6 9-6" stroke="#fff" stroke-width="2" fill="none"/>',
    Documents: '<rect x="5" y="2" width="14" height="20" rx="2" fill="#1a73e8"/><path d="M8 8h8M8 12h8M8 16h5" stroke="#fff" stroke-width="2"/>',
    Calendar: '<rect x="3" y="4" width="18" height="17" rx="2" fill="#188038"/><path d="M3 9h18M8 13h3M13 13h3M8 17h3" stroke="#fff" stroke-width="2"/>',
    Notes: '<rect x="4" y="3" width="16" height="18" rx="2" fill="#f9ab00"/><path d="M8 9h8M8 13h8" stroke="#fff" stroke-width="2"/>'
  };
  var customs = [], pendingIcon = '';
  function loadCustoms() { try { customs = JSON.parse(store.get('relay-customs', '[]')); } catch (e) { customs = []; } }
  function saveCustoms() { store.set('relay-customs', JSON.stringify(customs)); }
  function svgIcon(body) { return 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' + body + '</svg>'); }
  function findCustom(name) { for (var i = 0; i < customs.length; i++) if (customs[i].name === name) return customs[i]; return null; }
  function applyCloak(name) {
    var c = findCustom(name);
    if (!c && !ICONS[name]) name = 'Inbox';
    document.title = name;
    fav.href = c && c.icon ? c.icon : svgIcon(ICONS[c ? 'Inbox' : name]);
    $('#cloak').value = name;
    store.set('relay-cloak', name);
  }
  function fillCloaks() {
    var s = $('#cloak'), o;
    s.innerHTML = '';
    Object.keys(ICONS).concat(customs.map(function (c) { return c.name; })).forEach(function (n) {
      o = document.createElement('option'); o.textContent = n; o.value = n; s.appendChild(o);
    });
  }
  function readIcon(file, done) {
    var r = new FileReader();
    r.onload = function () {
      var img = new Image();
      img.onload = function () {
        try {
          var w = img.naturalWidth || 64, h = img.naturalHeight || 64, s = Math.min(w, h), c = document.createElement('canvas');
          c.width = c.height = 64;
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
      sp.textContent = c.name; b.type = 'button'; b.className = 'btn'; b.textContent = 'Remove';
      b.onclick = function () {
        customs = customs.filter(function (x) { return x !== c; });
        saveCustoms(); fillCloaks(); drawList();
        applyCloak(document.title === c.name ? 'Inbox' : document.title);
      };
      row.appendChild(im); row.appendChild(sp); row.appendChild(b); l.appendChild(row);
    });
  }
  $('#cloak').onchange = function () { applyCloak(this.value); };
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
    saveCustoms(); fillCloaks(); drawList(); applyCloak(name);
    pendingIcon = ''; $('#ctitle').value = ''; $('#cicon').value = ''; $('#cprev').removeAttribute('src');
  };

  function target(s) {
    s = s.trim();
    if (/^https?:\/\//i.test(s)) return s;
    if (/^[^\s\/]+\.[^\s\/]+(\/\S*)?$/.test(s)) return 'https://' + s;
    return ENGINES[engine()] + encodeURIComponent(s);
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
    var t = { url: '', title: 'New tab', host: '', started: false, loading: false, frame: document.createElement('iframe'), el: null };
    t.frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-modals allow-downloads');
    t.frame.title = 'Page';
    t.frame.style.display = 'none';
    t.frame.addEventListener('load', function () { t.loading = false; draw(); });
    view.appendChild(t.frame);
    tabs.push(t);
    select(t);
    return t;
  }
  function load(t, src) { t.started = true; t.loading = true; t.title = 'Loading…'; t.frame.src = src; draw(); }
  function visit(t, text) { load(t, PRE + encodeURIComponent(target(text))); }
  function select(t) { cur = t; draw(); if (!t.started) q.focus(); }
  function closeTab(t) {
    var i = tabs.indexOf(t), el = t.el;
    tabs.splice(i, 1);
    t.frame.remove();
    if (el) { el.classList.add('out'); el.style.pointerEvents = 'none'; setTimeout(function () { el.remove(); }, 120); }
    if (!tabs.length) { newTab(); return; }
    if (cur === t) cur = tabs[Math.max(0, i - 1)];
    draw();
  }
  function faviconInto(fi, real) {
    var img = fi.querySelector('img');
    fi.querySelector('b').textContent = (host(real).charAt(0) || '•').toUpperCase();
    fi.classList.remove('ok');
    img.onload = function () { fi.classList.add('ok'); };
    img.onerror = function () { fi.classList.remove('ok'); };
    try { img.src = PRE + encodeURIComponent(new URL(real).origin + '/favicon.ico'); } catch (e) {}
  }
  function setIcon(t, real) { var fi = t.el && t.el.querySelector('.fi'); if (fi) faviconInto(fi, real); }

  var pins = [];
  function loadPins() { try { pins = JSON.parse(store.get('relay-pins', '[]')); } catch (e) { pins = []; } }
  function isPinned(u) { return pins.some(function (p) { return p.url === u; }); }
  function savePins() { store.set('relay-pins', JSON.stringify(pins)); drawPins(); draw(); }
  function drawPins() {
    var box = $('#pins');
    box.innerHTML = '';
    pins.forEach(function (p) {
      var w = document.createElement('div'), b = document.createElement('button'), x = document.createElement('button'), n = document.createElement('span');
      w.className = 'pin';
      b.type = 'button'; b.className = 'pb';
      b.innerHTML = '<span class="fi"><b>•</b><img alt=""></span>';
      n.textContent = p.title || host(p.url); b.appendChild(n);
      x.type = 'button'; x.className = 'x'; x.setAttribute('aria-label', 'Remove ' + (p.title || host(p.url)));
      x.innerHTML = '<svg class="i"><use href="#i-x"/></svg>';
      b.onclick = function () { visit(cur, p.url); };
      x.onclick = function () { pins = pins.filter(function (z) { return z !== p; }); savePins(); };
      w.appendChild(b); w.appendChild(x); box.appendChild(w);
      faviconInto(b.firstChild, p.url);
    });
  }

  function draw() {
    tabs.forEach(function (t) {
      if (!t.el) {
        t.el = document.createElement('div');
        t.el.className = 'tab';
        t.el.setAttribute('role', 'tab');
        t.el.tabIndex = 0;
        t.el.innerHTML = '<span class="fi"><b>•</b><img alt=""></span><span class="t"></span><button class="x" aria-label="Close tab"><svg class="i"><use href="#i-x"/></svg></button>';
        t.el.onclick = function () { select(t); };
        t.el.onkeydown = function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target === t.el) { e.preventDefault(); select(t); } };
        t.el.querySelector('.x').onclick = function (e) { e.stopPropagation(); closeTab(t); };
        strip.insertBefore(t.el, $('#plus'));
      }
      t.el.querySelector('.t').textContent = t.title;
      t.el.classList.toggle('on', t === cur);
      t.el.setAttribute('aria-selected', String(t === cur));
      t.frame.style.display = t === cur && t.started ? 'block' : 'none';
    });
    home.style.display = cur && !cur.started ? 'flex' : 'none';
    prog.className = cur && cur.loading ? 'on' : '';
    var pb = $('#pin');
    pb.disabled = !(cur && cur.url);
    pb.classList.toggle('on', Boolean(cur && cur.url && isPinned(cur.url)));
    pb.setAttribute('aria-pressed', String(pb.classList.contains('on')));
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
        if (host(real) !== t.host) { t.host = host(real); setIcon(t, real); }
        if (title !== t.title) { t.title = title; changed = true; }
      } catch (e) {}
    });
    if (changed) draw();
  }, 700);

  $('#plus').onclick = newTab;
  $('#back').onclick = function () { try { cur.frame.contentWindow.history.back(); } catch (e) {} };
  $('#fwd').onclick = function () { try { cur.frame.contentWindow.history.forward(); } catch (e) {} };
  $('#rel').onclick = function () { try { cur.frame.contentWindow.location.reload(); } catch (e) {} };
  $('#pin').onclick = function () {
    if (!cur || !cur.url) return;
    if (isPinned(cur.url)) pins = pins.filter(function (p) { return p.url !== cur.url; });
    else if (pins.length < 12) pins.push({ url: cur.url, title: cur.title });
    savePins();
  };
  function applyDensity(v) { root.setAttribute('data-density', v); store.set('relay-density', v); $('#dens').value = v; }
  $('#dens').onchange = function () { applyDensity(this.value); };
  $('#gear').onclick = function () { dlg.showModal(); };
  $('#dx').onclick = function () { dlg.close(); };
  dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
  addr.onfocus = function () { addr.select(); };
  addr.onkeydown = function (e) { if (e.key === 'Enter' && addr.value.trim()) { visit(cur, addr.value); addr.blur(); } };
  q.onkeydown = function (e) { if (e.key === 'Enter' && q.value.trim()) { visit(cur, q.value); q.value = ''; } };

  window.__relayOpen = function (href) { load(newTab(), href); };

  loadCustoms(); fillCloaks(); drawList(); buildThemes(); fillEngines(); loadPins(); drawPins();
  applyDensity(store.get('relay-density', 'comfortable') === 'compact' ? 'compact' : 'comfortable');
  applyTheme(themePref);
  applyCloak(store.get('relay-cloak', 'Inbox'));
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
    const url = new URL(req.url, 'http://localhost');
    if (AUTH_ON && url.pathname === '/login') return await login(req, res);
    if (!authorized(req)) {
      if (req.method === 'GET') { res.writeHead(302, { Location: '/login' }); return res.end(); }
      res.writeHead(401, { 'content-type': 'text/plain' });
      return res.end('Login required');
    }
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
