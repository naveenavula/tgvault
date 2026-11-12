// Password-locked, self-decrypting share file.
// Output is ONE .html file that contains the encrypted payload plus a tiny viewer. Anyone can open it in a browser,
// enter the password, and download the original file. Nothing is fetched from a server; the password never leaves their browser.
//
// Crypto: PBKDF2-SHA256 (600k iterations, random 16-byte salt) -> AES-256-GCM key.
//   line 0 : header JSON {v, salt, iter, iv(8-byte nonce prefix), chunk, n}
//   line 1 : encrypted metadata {name, type, size}   (iv = prefix||0xFFFFFFFF, aad "meta")
//   line 2+: 1 MiB plaintext chunks (iv = prefix||index, aad = index||finalFlag) -> truncation/reordering fails

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
export const SHARE_MAX = 150 * 1024 * 1024;
const CH = 1024 * 1024;
const ITER = 600000;

const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; };
const cat = (...a) => { const o = new Uint8Array(a.reduce((x, y) => x + y.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

export function randomPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const r = rand(20); let out = '';
  for (let i = 0; i < 16; i++) { out += alphabet[r[i] % alphabet.length]; if (i % 4 === 3 && i < 15) out += '-'; }
  return out;
}

const VIEWER_JS = String.raw`
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var te = new TextEncoder(), td = new TextDecoder();
  function b64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  function u32(n) { var b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; }
  function cat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
  function fmt(n) { var u = ['B', 'KB', 'MB', 'GB'], i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; }
  if (!(window.crypto && crypto.subtle)) { $('err').textContent = 'This browser cannot decrypt here (Web Crypto unavailable). Open this file in an up-to-date Chrome, Edge, Firefox or Safari.'; $('go').disabled = true; return; }
  var lines = $('d').textContent.trim().split('\n'), H = JSON.parse(lines[0]), key, meta, prefix = b64(H.iv);
  async function unlock(pw) {
    var base = await crypto.subtle.importKey('raw', te.encode(pw.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
    key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(H.salt), iterations: H.iter }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var m = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: cat(prefix, u32(0xFFFFFFFF)), additionalData: te.encode('meta') }, key, b64(lines[1]));
    meta = JSON.parse(td.decode(m));
  }
  $('f').onsubmit = async function (e) {
    e.preventDefault(); $('err').textContent = ''; $('go').disabled = true; $('go').textContent = 'Checking…';
    try { await unlock($('pw').value); } catch (x) { $('err').textContent = 'Wrong password.'; $('go').disabled = false; $('go').textContent = 'Unlock'; return; }
    $('lock').hidden = true; $('ok').hidden = false; $('fn').textContent = meta.name; $('fs').textContent = fmt(meta.size);
  };
  $('dl').onclick = async function () {
    $('dl').disabled = true; $('prog').hidden = false; var parts = [];
    try {
      for (var i = 0; i < H.n; i++) {
        var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: cat(prefix, u32(i)), additionalData: cat(u32(i), new Uint8Array([i === H.n - 1 ? 1 : 0])) }, key, b64(lines[2 + i]));
        parts.push(new Uint8Array(pt)); $('bar').style.width = Math.round(((i + 1) / H.n) * 100) + '%';
      }
    } catch (x) { $('err2').textContent = 'The file is damaged or incomplete.'; $('dl').disabled = false; return; }
    var url = URL.createObjectURL(new Blob(parts, { type: meta.type || 'application/octet-stream' }));
    var a = document.createElement('a'); a.href = url; a.download = meta.name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 60000); $('dl').disabled = false; $('dl').textContent = 'Download again';
  };
})();
`;

const HEAD = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="robots" content="noindex"><title>Password-protected file</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#14181f;--muted:#6b7380;--line:#e3e6ea;--accent:#1f8fe0}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--fg:#e8ecf1;--muted:#8b95a3;--line:#262d37;--accent:#3ba0ee}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.p{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;width:100%;max-width:420px}
h1{margin:0 0 6px;font-size:20px}p{color:var(--muted);margin:4px 0 16px}
input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:disabled{opacity:.6;cursor:default}.err{color:#d64545;min-height:1.3em;margin-top:10px;font-size:14px}
.n{font-weight:600;word-break:break-all}.bar{height:6px;background:var(--bg);border-radius:3px;margin-top:12px;overflow:hidden}.bar i{display:block;height:100%;width:0;background:var(--accent)}
.f{font-size:12px;color:var(--muted);margin-top:18px}
</style></head><body><div class="p">
<div id="lock"><h1>🔒 Password-protected file</h1><p>Enter the password you were given to unlock and download this file. Decryption happens in your browser — nothing is uploaded.</p>
<form id="f"><input id="pw" type="password" placeholder="Password" autocomplete="off" autofocus required><button id="go" type="submit">Unlock</button></form><div class="err" id="err"></div></div>
<div id="ok" hidden><h1>🔓 Unlocked</h1><p class="n" id="fn"></p><p id="fs"></p><button id="dl" type="button">Download</button>
<div class="bar" id="prog" hidden><i id="bar"></i></div><div class="err" id="err2"></div></div>
<div class="f">Encrypted with AES-256-GCM · made with TGVault</div></div>
<script type="text/plain" id="d">`;
const TAIL = `</script>
<script>${VIEWER_JS}</script></body></html>`;

async function pbkdf2Key(password, salt) {
  const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
}

/** @param {Blob} file  @returns {Promise<Blob>} the self-decrypting .html */
export async function buildShareHtml(file, name, mime, password, onProgress) {
  if (file.size > SHARE_MAX) throw new Error('File is too large for a share file (limit 150 MB).');
  if (!password || password.length < 8) throw new Error('Use a password of at least 8 characters.');
  const salt = rand(16), prefix = rand(8), key = await pbkdf2Key(password, salt);
  const n = Math.max(1, Math.ceil(file.size / CH));
  const header = { v: 1, salt: b64(salt), iter: ITER, iv: b64(prefix), chunk: CH, n };
  const metaCt = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: cat(prefix, u32(0xFFFFFFFF)), additionalData: enc.encode('meta') }, key,
    enc.encode(JSON.stringify({ name: String(name).slice(0, 255), type: mime || 'application/octet-stream', size: file.size }))));
  const parts = [HEAD, JSON.stringify(header), '\n', b64(metaCt)];
  for (let i = 0; i < n; i++) {
    const pt = new Uint8Array(await file.slice(i * CH, (i + 1) * CH).arrayBuffer());
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: cat(prefix, u32(i)), additionalData: cat(u32(i), new Uint8Array([i === n - 1 ? 1 : 0])) }, key, pt));
    parts.push('\n', b64(ct));
    onProgress && onProgress((i + 1) / n);
  }
  parts.push(TAIL);
  return new Blob(parts, { type: 'text/html' });
}
