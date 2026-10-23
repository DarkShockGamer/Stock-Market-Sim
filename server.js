// Zero-dependency server (works on Railway, which provides PORT).
// Serves the game and, for the "Live Market" mode, a small cached proxy for real stock quotes.
//
// Live quotes come from Finnhub (https://finnhub.io, free API key). Set it as an environment variable:
//   FINNHUB_API_KEY=your_key node server.js
// The key stays on the server and is never sent to the browser. All players share one cache, so the
// free tier (60 calls/min) is enough: the server refreshes about 1 symbol per 1.1 seconds, and only
// while somebody is actually playing a Live game.
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const PUB = path.join(__dirname, 'public');
const TYPES = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };

const KEY = (process.env.FINNHUB_API_KEY || '').trim(); // never hardcode this: set it in Railway -> Variables
const BASE = process.env.FINNHUB_BASE || 'https://finnhub.io/api/v1';
// Game ticker -> real ticker, where they differ (GLD and BND are the same in both).
const MAP = { IDX:'SPY', TECH:'QQQ', DIV:'SCHD', BRKB:'BRK.B', SQ:'XYZ' };
// Fictional or unpriceable in this mode: Starlink is a SpaceX subsidiary (not listed), crypto is not supported yet.
const NOQUOTE = new Set(['STRL','BTC','ETH','SOL','DOGE']);

const CACHE_FILE = path.join(os.tmpdir(), 'idle-stocks-quotes.json');
let cache = {};                       // game ticker -> { c, pc, t, at, none? }
try { cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')) || {}; } catch (e) {}
const want = new Map();               // game ticker -> last time a player asked for it
let hot = new Set(), lastReq = 0, backoff = 0, n = 0, dirty = false, authErr = 0;

async function pollOne() {
  const now = Date.now();
  if (!KEY || now < backoff || now - lastReq > 5 * 60e3) return;   // idle when nobody is playing Live
  const syms = [...want.keys()].filter(s => now - want.get(s) < 5 * 60e3);
  if (!syms.length) return;
  const age = s => { const q = cache[s]; return !q ? 0 : q.none ? q.at + 3600e3 : q.at; }; // never fetched first; unpriceable ones retried hourly
  const pool = (n++ % 3 === 0 && [...hot].some(s => syms.includes(s))) ? syms.filter(s => hot.has(s)) : syms;
  const sym = pool.reduce((a, b) => age(b) < age(a) ? b : a);
  try {
    const r = await fetch(BASE + '/quote?symbol=' + encodeURIComponent(MAP[sym] || sym) + '&token=' + KEY, { signal: AbortSignal.timeout(8000) });
    if (r.status === 429) { backoff = Date.now() + 20000; return; }
    if (r.status === 401 || r.status === 403) { authErr = r.status; backoff = Date.now() + 15000; console.log('Finnhub rejected the API key (HTTP ' + r.status + '). Check FINNHUB_API_KEY.'); return; } // bad key: do NOT mark stocks as unpriceable
    if (!r.ok) { cache[sym] = { c: 0, pc: 0, t: 0, at: Date.now(), none: true }; return; }
    authErr = 0;
    const j = await r.json();
    cache[sym] = j && j.c > 0 ? { c: j.c, pc: j.pc || j.c, t: j.t || 0, at: Date.now() } : { c: 0, pc: 0, t: 0, at: Date.now(), none: true };
    dirty = true;
  } catch (e) { backoff = Date.now() + 5000; }
}
setInterval(pollOne, +process.env.POLL_MS || 1100);
setInterval(() => { if (dirty) { dirty = false; try { fs.writeFileSync(CACHE_FILE, JSON.stringify(cache)); } catch (e) {} } }, 30000);

// ---- History for Live mode charts: whole lifetime per stock = weekly closes for the old years + daily closes for the last year
// (Yahoo Finance chart API, Stooq as fallback; no key needed) ----
// Cached in memory + a temp file, refreshed every 12 h, and only fetched while somebody is playing a Live game.
const HFILE = path.join(os.tmpdir(), 'idle-stocks-history.json');
const YAHOO = process.env.YAHOO_BASE || 'https://query1.finance.yahoo.com';
const STOOQ = process.env.STOOQ_BASE || 'https://stooq.com';
const HMAP = { IDX:'SPY', TECH:'QQQ', DIV:'SCHD', BRKB:'BRK-B', SQ:'XYZ' };
const UA = { 'User-Agent': 'Mozilla/5.0 (compatible; IdleStocks/1.0)' };
let hist = {};                        // game ticker -> { t:[days since epoch], c:[closes], at } or { none:true, at }
try { hist = JSON.parse(fs.readFileSync(HFILE, 'utf8')) || {}; } catch (e) {}
const hwant = new Map();              // game ticker -> last time a player asked for its history
let hbusy = false, hback = 0, lastHReq = 0, hdirty = false;

async function yahooSeries(sym, range, interval) {
  const r = await fetch(YAHOO + '/v8/finance/chart/' + encodeURIComponent(HMAP[sym] || sym) + '?range=' + range + '&interval=' + interval, { headers: UA, signal: AbortSignal.timeout(15000) });
  if (r.status === 404) return null;                 // unknown ticker
  if (!r.ok) throw new Error('yahoo ' + r.status);   // rate limit / outage: retry later
  const j = await r.json(), res = j && j.chart && j.chart.result && j.chart.result[0];
  if (!res) return null;
  const ts = res.timestamp || [], cl = ((res.indicators || {}).quote || [{}])[0].close || [], t = [], c = [];
  ts.forEach((x, i) => { if (cl[i] > 0) { t.push(Math.round(x / 86400)); c.push(+cl[i].toFixed(2)); } });
  return c.length > 1 ? { t, c } : null;
}
async function yahooHist(sym) {
  const wk = await yahooSeries(sym, 'max', '1wk');   // since the first day it traded
  if (!wk) return null;
  let dy = null; try { dy = await yahooSeries(sym, '1y', '1d'); } catch (e) {}   // daily detail for the last year (optional)
  if (!dy) return wk;
  const i = wk.t.findIndex(x => x >= dy.t[0]), n = i < 0 ? wk.t.length : i;
  return { t: wk.t.slice(0, n).concat(dy.t), c: wk.c.slice(0, n).concat(dy.c) };
}
async function stooqHist(sym) {
  const r = await fetch(STOOQ + '/q/d/l/?s=' + encodeURIComponent((HMAP[sym] || sym).toLowerCase()) + '.us&i=d', { headers: UA, signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error('stooq ' + r.status);
  const txt = await r.text();
  if (!/^Date,/i.test(txt)) return null;
  const all = txt.trim().split('\n').slice(1), cut = Math.max(0, all.length - 252), t = [], c = [];
  const rows = all.filter((_, i) => i >= cut || i % 5 === 0);   // daily for the last year, every 5th day (about weekly) before that
  rows.forEach(l => { const f = l.split(','), d = Date.parse(f[0] + 'T00:00:00Z'), v = parseFloat(f[4]); if (d && v > 0) { t.push(Math.round(d / 86400e3)); c.push(+v.toFixed(2)); } });
  return c.length > 1 ? { t, c } : null;
}
async function histOne() {
  const now = Date.now();
  if (hbusy || now < hback || now - lastHReq > 5 * 60e3) return;
  const age = s => { const q = hist[s]; return !q ? 0 : q.at + (q.none ? 3600e3 : 12 * 3600e3); };   // missing first; stale ones refreshed; unpriceable retried hourly
  const due = [...hwant.keys()].filter(s => now - hwant.get(s) < 5 * 60e3 && age(s) <= now);
  if (!due.length) return;
  const sym = due.reduce((a, b) => age(b) < age(a) ? b : a);
  hbusy = true;
  try {
    let d = null, failed = false;
    try { d = await yahooHist(sym); } catch (e) { failed = true; }
    if (!d) { try { d = await stooqHist(sym); failed = false; } catch (e) { failed = true; } }
    if (d) { hist[sym] = { t: d.t, c: d.c, at: Date.now() }; hdirty = true; }
    else if (failed) hback = Date.now() + 15000;      // sources unreachable: do not mark the stock as having no data
    else { hist[sym] = { none: true, at: Date.now() }; hdirty = true; }
  } finally { hbusy = false; }
}
setInterval(histOne, +process.env.HPOLL_MS || 700);
setInterval(() => { if (hdirty) { hdirty = false; try { fs.writeFileSync(HFILE, JSON.stringify(hist)); } catch (e) {} } }, 30000);

function history(req, res) {
  const u = new URL(req.url, 'http://x');
  const ok = s => /^[A-Z0-9]{1,6}$/.test(s) && !NOQUOTE.has(s);
  const s = (u.searchParams.get('s') || '').split(',').filter(ok).slice(0, 150);
  const have = new Set((u.searchParams.get('have') || '').split(','));   // the browser already has these: do not resend
  const now = Date.now(); lastHReq = now;
  const out = {}; let pending = 0;
  s.forEach(x => { hwant.set(x, now); const q = hist[x];
    if (q && q.c) { if (!have.has(x)) out[x] = { t: q.t, c: q.c }; } else if (!q) pending++; });
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ ok: true, pending, hist: out }));
}

function quotes(req, res) {
  const u = new URL(req.url, 'http://x');
  const ok = s => /^[A-Z0-9]{1,6}$/.test(s) && !NOQUOTE.has(s);
  const s = (u.searchParams.get('s') || '').split(',').filter(ok).slice(0, 150);
  const h = (u.searchParams.get('h') || '').split(',').filter(ok).slice(0, 50);
  const now = Date.now(); lastReq = now; hot = new Set(h);
  s.forEach(x => want.set(x, now));
  const out = {}; let ready = 0;
  s.forEach(x => { const q = cache[x]; if (q && q.c > 0) { out[x] = { c: q.c, pc: q.pc, t: q.t }; ready++; } });
  const body = !KEY ? { ok: false, error: 'nokey', now, quotes: {} }
    : (authErr && !ready) ? { ok: false, error: 'badkey', now, quotes: {} }
    : { ok: true, now, total: s.length, ready, quotes: out };
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/api/quotes') return quotes(req, res);
  if (p === '/api/history') return history(req, res);
  if (p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUB, p));
  if (!f.startsWith(PUB)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' });
    res.end(d);
  });
}).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Running on ' + (process.env.PORT || 3000) + (KEY ? '' : ' (no FINNHUB_API_KEY set: Live Market mode is disabled)')));
