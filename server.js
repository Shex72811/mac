// mac-server — فحص ماك على بورتال Stalker/MAG (Node.js, جاهز لـ Render)
const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const UA =
  'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';

function isBlockedHost(h) {
  h = h.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (/^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) return true;
  if (h === '[::1]' || h.startsWith('[fc') || h.startsWith('[fd') || h.startsWith('[fe80')) return true;
  return false;
}

async function call(url, mac, origin, token = '') {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12000);
  const r = { url, data: null, status: 0, snippet: '', err: '' };
  try {
    const headers = {
      Cookie: `mac=${mac}; stb_lang=en; timezone=GMT`,
      'User-Agent': UA,
      'X-User-Agent': 'Model: MAG250; Link: WiFi',
      Referer: origin + '/c/',
      Accept: '*/*',
    };
    if (token) headers.Authorization = 'Bearer ' + token;
    const res = await fetch(url, { headers, redirect: 'follow', signal: ctrl.signal });
    r.status = res.status;
    const text = await res.text();
    r.snippet = text.replace(/\s+/g, ' ').slice(0, 140);
    const clean = text.replace(/^\uFEFF/, '').trim();
    const start = clean.indexOf('{');
    if (start >= 0) {
      try {
        const j = JSON.parse(clean.slice(start));
        r.data = j && typeof j === 'object' ? (j.js !== undefined ? j.js : j) : null;
      } catch (e) {
        r.err = 'الرد ليس JSON صالحاً';
      }
    } else r.err = 'الرد ليس JSON';
  } catch (e) {
    r.err = e.name === 'AbortError' ? 'انتهت المهلة' : String(e.message || e);
  } finally {
    clearTimeout(timer);
  }
  return r;
}

app.get('/', async (req, res) => {
  const portal = String(req.query.portal || '').trim();
  const hex = String(req.query.mac || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (hex.length !== 12) return res.json({ ok: false, error: 'عنوان الماك غير صحيح.' });
  const mac = hex.match(/.{2}/g).join(':');

  let u;
  try { u = new URL(portal); } catch (e) { return res.json({ ok: false, error: 'رابط البورتال غير صحيح.' }); }
  if (!['http:', 'https:'].includes(u.protocol)) return res.json({ ok: false, error: 'رابط البورتال غير صحيح.' });
  if (isBlockedHost(u.hostname)) return res.json({ ok: false, error: 'عنوان السيرفر غير مسموح.' });

  const origin = u.origin;
  const path = u.pathname || '';
  const base = path.replace(/\/+$/, '').replace(/\/c$/, '');

  const eps = [...new Set([
    origin + base + '/portal.php',
    origin + base + '/server/load.php',
    origin + base + '/stalker_portal/server/load.php',
    origin + base + '/load.php',
    origin + '/portal.php',
    origin + '/server/load.php',
    origin + '/stalker_portal/server/load.php',
  ])];
  if (path.toLowerCase().includes('stalker_portal')) eps.unshift(origin + base + '/server/load.php');
  const list = [...new Set(eps)];

  const hs = await Promise.all(
    list.map((ep) => call(ep + '?type=stb&action=handshake&token=&prehash=0&JsHttpRequest=1-xml', mac, origin))
  );
  const debug = hs.map((h) => `${h.url.replace(origin, '')} → ${h.status || '-'} ${h.err || ''} ${h.data ? '' : h.snippet}`.trim());

  let idx = hs.findIndex((h) => h.data && h.data.token);
  let token = idx >= 0 ? hs[idx].data.token : '';
  if (idx < 0) idx = hs.findIndex((h) => h.data && typeof h.data === 'object' && !Array.isArray(h.data) && h.status === 200);
  if (idx < 0) {
    return res.json({ ok: false, error: 'لم يتم الحصول على استجابة صالحة من البورتال.', debug });
  }
  const used = list[idx];

  const profileUrl =
    used +
    '?type=stb&action=get_profile&hd=1&ver=&num_banks=2&sn=&stb_type=MAG250&client_type=STB&image_version=218&video_out=hdmi&device_id=&device_id2=&signature=&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0&metrics=&hw_version_2=&api_signature=262&prehash=&JsHttpRequest=1-xml';
  const [p, a] = await Promise.all([
    call(profileUrl, mac, origin, token),
    call(used + '?type=account_info&action=get_main_info&JsHttpRequest=1-xml', mac, origin, token),
  ]);
  const profile = p.data && typeof p.data === 'object' ? p.data : null;
  const info = a.data && typeof a.data === 'object' ? a.data : null;

  if (!profile && !info) {
    debug.push('get_profile → ' + p.status + ' ' + (p.err || p.snippet));
    debug.push('account_info → ' + a.status + ' ' + (a.err || a.snippet));
    return res.json({ ok: false, error: 'تم الاتصال بالبورتال لكن لم تُرجع بيانات الحساب (قد يكون الماك غير مسجل).', debug });
  }
  res.json({ ok: true, portal_url: used, token_received: !!token, profile: profile || {}, info: info || {} });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('mac-server running on port ' + port));
  
