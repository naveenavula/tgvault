import { TG } from './tg.js';
import { deriveMasterKey, keyCheck, MAX_THUMB } from './crypto.js';
import { buildShareHtml, randomPassword, SHARE_MAX } from './share.js';

const $root = document.getElementById('root');
const tg = new TG();
const store = chrome.storage.local;
let state = { filter: 'all', q: '', path: '' };

// ---------- tiny helpers ----------
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstChild; };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtSize = (n) => { const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };
const fmtDate = (d) => new Date(d * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
const toastEl = document.getElementById('toast'); let toastT;
function toast(msg) { toastEl.textContent = msg; toastEl.classList.add('show'); clearTimeout(toastT); toastT = setTimeout(() => toastEl.classList.remove('show'), 3500); }
const errMsg = (e) => (e && (e.errorMessage || e.message)) || String(e);

// ---------- IndexedDB: holds the non-extractable master key until you lock/log out ----------
const idb = {
  open: () => new Promise((res, rej) => { const r = indexedDB.open('tgvault', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }),
  async get(k) { const db = await this.open(); return new Promise((res, rej) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); },
  async set(k, v) { const db = await this.open(); return new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = res; t.onerror = () => rej(t.error); }); },
  async del(k) { const db = await this.open(); return new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').delete(k); t.oncomplete = res; t.onerror = () => rej(t.error); }); },
  async clear() { const db = await this.open(); return new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').clear(); t.oncomplete = res; t.onerror = () => rej(t.error); }); },
};

// ---------- screens ----------
function screen(html) { $root.replaceChildren(h(html)); return $root.firstChild; }

function showLoading(msg) { screen(`<div class="center"><div style="text-align:center"><div class="spinner"></div><p class="sub">${esc(msg)}</p></div></div>`); }

/** Step-by-step Telegram login. Returns when authorised. */
async function loadBaked() {
  try { const c = await (await fetch('credentials.json')).json(); const id = String(c.api_id || '').trim(), hash = String(c.api_hash || '').trim();
    if (/^\d+$/.test(id) && /^[0-9a-f]{32}$/i.test(hash)) return { api_id: id, api_hash: hash }; } catch { /* not provided */ }
  return null;
}
async function loginFlow(prefill = {}) {
  prefill = (await loadBaked()) || prefill;
  const el = screen(`<div class="center"><form class="panel" id="f">
    <h1>🔐 TGVault</h1>
    <p>Encrypted photo &amp; file storage on your Telegram account (Saved Messages).</p>
    <div id="step"></div>
    <div class="err" id="err"></div>
  </form></div>`);
  const step = el.querySelector('#step'), err = el.querySelector('#err'), form = el.querySelector('#f');
  const ask = (html, focusSel) => new Promise((resolve) => {
    step.innerHTML = html + '<div class="row" style="margin-top:16px"><button class="btn primary" type="submit">Continue</button></div>';
    err.textContent = ''; const inp = step.querySelector(focusSel); inp && inp.focus();
    form.onsubmit = (e) => { e.preventDefault(); resolve(Object.fromEntries(new FormData(form))); };
  });

  let creds = prefill;
  for (;;) {
    if (!creds.api_id || !creds.api_hash) {
      for (;;) {
        creds = await ask(`
          <label>Telegram API ID</label><input type="text" name="api_id" inputmode="numeric" autocomplete="off" required>
          <label>Telegram API hash</label><input type="text" name="api_hash" autocomplete="off" required>
          <div class="hint">One-time setup: sign in at <a href="https://my.telegram.org/apps" target="_blank" rel="noreferrer">my.telegram.org/apps</a>, create an app, and paste the <b>api_id</b> and <b>api_hash</b> here. They stay on this device.</div>`, '[name=api_id]');
        if (/^\d+$/.test(creds.api_id.trim()) && /^[0-9a-f]{32}$/i.test(creds.api_hash.trim())) break;
        err.textContent = 'API ID must be digits and API hash a 32-character hex string.';
      }
      creds = { api_id: creds.api_id.trim(), api_hash: creds.api_hash.trim() };
    }
    step.innerHTML = '<div class="row"><span class="spinner"></span><span>Connecting to Telegram…</span></div>'; err.textContent = '';
    try {
      await Promise.race([tg.connect(creds.api_id, creds.api_hash, ''), new Promise((_, rej) => setTimeout(() => rej(new Error('timed out — check your internet connection')), 30000))]);
      break;
    } catch (e) { try { await tg.client.disconnect(); } catch { /* */ } err.textContent = 'Could not connect: ' + errMsg(e); creds = {}; }
  }
  await tg.login({
    phone: async () => (await ask('<label>Phone number (with country code)</label><input type="tel" name="v" placeholder="+64 21 123 4567" autocomplete="tel" required>', '[name=v]')).v.trim(),
    code: async () => (await ask('<label>Login code</label><input type="text" name="v" inputmode="numeric" autocomplete="one-time-code" required><div class="hint">Sent to your Telegram app (or by SMS).</div>', '[name=v]')).v.trim(),
    password: async () => (await ask('<label>Two-step verification password</label><input type="password" name="v" autocomplete="current-password" required>', '[name=v]')).v,
    onError: (e) => { err.textContent = errMsg(e); },
  });
  await store.set({ api_id: creds.api_id, api_hash: creds.api_hash, session: tg.saveSession() });
}

/** Ask for the encryption passphrase; derive + persist the key. */
async function unlockFlow(hasVault) {
  const check = (await store.get('keycheck_' + tg.userId))['keycheck_' + tg.userId];
  const first = !check && !hasVault;   // brand-new vault: choose a passphrase; otherwise just enter the existing one
  const el = screen(`<div class="center"><form class="panel" id="f">
    <h1>${first ? 'Create your encryption passphrase' : 'Unlock your vault'}</h1>
    <p>${first ? 'Your files are encrypted in this browser with a key derived from this passphrase. Telegram only ever sees ciphertext.' : 'Enter your encryption passphrase.'}</p>
    <label>Passphrase</label><input type="password" name="p" autocomplete="${first ? 'new-password' : 'current-password'}" required minlength="${first ? 10 : 1}">
    ${first ? '<label>Repeat passphrase</label><input type="password" name="p2" autocomplete="new-password" required minlength="10">' : ''}
    ${first ? '<div class="warn"><b>Write it down.</b> There is no recovery: if you forget it, every file you stored is permanently unreadable. Use the <u>same</u> passphrase on every device. (Min. 10 characters — use a long phrase.)</div>' : ''}
    <div class="row" style="margin-top:16px"><button class="btn primary" type="submit">${first ? 'Create &amp; continue' : 'Unlock'}</button>
    <button class="btn danger" type="button" id="lo">Log out</button></div>
    <div class="err" id="err"></div>
  </form></div>`);
  const err = el.querySelector('#err');
  el.querySelector('#lo').onclick = () => doLogout();
  await new Promise((resolve) => {
    el.querySelector('#f').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target); const p = fd.get('p');
      if (first && p.length < 10) { err.textContent = 'Use at least 10 characters (a long phrase is best).'; return; }
      if (first && p !== fd.get('p2')) { err.textContent = 'Passphrases do not match.'; return; }
      const btn = el.querySelector('button.primary'); btn.disabled = true; err.textContent = ''; btn.textContent = 'Deriving key…';
      try {
        const master = await deriveMasterKey(p, tg.userId);
        const kc = await keyCheck(master);
        if (check && check !== kc) throw new Error('That is not the passphrase you set on this device.');
        await tg.setMaster(master);
        if (!check) {
          // New device / first time: make sure it actually opens existing vault files.
          btn.textContent = 'Checking vault…';
          if (!(await tg.verifyAgainstVault())) throw new Error('Wrong passphrase: it cannot decrypt files already in your vault.');
          await store.set({ ['keycheck_' + tg.userId]: kc });
        }
        await idb.set('master', { uid: tg.userId, key: master });
        resolve();
      } catch (ex) { tg.master = null; err.textContent = errMsg(ex); btn.disabled = false; btn.textContent = first ? 'Create & continue' : 'Unlock'; }
    };
  });
}

// ---------- thumbnails ----------
async function makeThumb(file) {
  try {
    let bmp;
    if (file.type.startsWith('image/') && file.type !== 'image/svg+xml') bmp = await createImageBitmap(file);
    else if (file.type.startsWith('video/')) bmp = await videoFrame(file);
    else return null;
    const s = Math.min(1, 192 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * s)), hh = Math.max(1, Math.round(bmp.height * s));
    const c = new OffscreenCanvas(w, hh); c.getContext('2d').drawImage(bmp, 0, 0, w, hh);
    for (const q of [0.72, 0.56, 0.42, 0.3, 0.2]) {
      const b = await c.convertToBlob({ type: 'image/jpeg', quality: q });
      if (b.size <= MAX_THUMB) return new Uint8Array(await b.arrayBuffer());
    }
  } catch { /* no thumbnail */ }
  return null;
}
function videoFrame(file) {
  return new Promise((resolve, reject) => {
    const v = document.createElement('video'), url = URL.createObjectURL(file);
    const done = (fn, a) => { URL.revokeObjectURL(url); fn(a); };
    v.muted = true; v.preload = 'metadata'; v.src = url;
    v.onloadeddata = () => { v.currentTime = Math.min(1, (v.duration || 1) / 2); };
    v.onseeked = () => createImageBitmap(v).then((b) => done(resolve, b), (e) => done(reject, e));
    v.onerror = () => done(reject, new Error('video'));
    setTimeout(() => done(reject, new Error('timeout')), 6000);
  });
}
const thumbCache = new Map(); // id -> object URL
let thumbBusy = 0; const thumbQueue = [];
function requestThumb(it, imgEl) {
  if (thumbCache.has(it.id)) { imgEl.src = thumbCache.get(it.id); return; }
  thumbQueue.push({ it, imgEl }); pumpThumbs();
}
function pumpThumbs() {
  while (thumbBusy < 3 && thumbQueue.length) {
    const { it, imgEl } = thumbQueue.shift(); thumbBusy++;
    tg.thumbnail(it).then((blob) => {
      if (!blob) return; const url = URL.createObjectURL(blob); thumbCache.set(it.id, url); imgEl.src = url; imgEl.hidden = false;
    }).catch(() => {}).finally(() => { thumbBusy--; pumpThumbs(); });
  }
}

// ---------- library ----------
function kindOf(it) {
  const t = it.enc ? (it.meta && it.meta.t) || '' : it.plainMime || '';
  if (t.startsWith('image/')) return 'media';
  if (t.startsWith('video/')) return 'media';
  return 'file';
}
function nameOf(it) { return it.enc ? (it.meta ? it.meta.n : '🔒 (cannot decrypt)') : it.plainName; }
function sizeOf(it) { return it.enc ? (it.meta ? it.meta.s : it.size) : it.size; }
const isMarker = (it) => !!(it.enc && it.meta && it.meta.k === 'folder');
const pathOf = (it) => (it.enc && it.meta && it.meta.p) || '';
const parentOf = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const baseName = (p) => p.slice(p.lastIndexOf('/') + 1);
function allFolders() {
  const set = new Set();
  for (const it of tg.items.values()) { const p = pathOf(it); if (!p) continue; const parts = p.split('/'); for (let i = 1; i <= parts.length; i++) set.add(parts.slice(0, i).join('/')); }
  return [...set].sort((a, b) => a.localeCompare(b));
}
const flatView = () => state.filter !== 'all' || state.q !== '';
function visibleItems() {
  const q = state.q.toLowerCase();
  return [...tg.items.values()].sort((a, b) => b.id - a.id).filter((it) => {
    if (isMarker(it)) return false;
    if (state.filter === 'media' && kindOf(it) !== 'media') return false;
    if (state.filter === 'file' && kindOf(it) !== 'file') return false;
    if (state.filter === 'plain' && it.enc) return false;
    if (q && !nameOf(it).toLowerCase().includes(q)) return false;
    if (!flatView() && pathOf(it) !== state.path) return false;
    return true;
  });
}
const countIn = (path) => [...tg.items.values()].filter((it) => !isMarker(it) && (pathOf(it) === path || pathOf(it).startsWith(path + '/'))).length;

function pickFolder(title, exclude) {
  return new Promise((resolve) => {
    const opts = ['', ...allFolders().filter((f) => !exclude || !(f === exclude || f.startsWith(exclude + '/')))];
    const m = h(`<div class="modal"><div class="panel"><h1 style="font-size:18px">${esc(title)}</h1>
      <select id="sel" style="width:100%;padding:10px;margin:12px 0;border-radius:8px;border:1px solid var(--line);background:var(--bg)">${opts.map((o) => `<option value="${esc(o)}">${o ? '📁 ' + esc(o) : '🏠 Home (top level)'}</option>`).join('')}</select>
      <div class="row"><button class="btn primary" id="ok">Move here</button><button class="btn" id="no">Cancel</button></div></div></div>`);
    document.body.append(m); m.querySelector('#sel').value = state.path in opts ? state.path : (opts.includes(state.path) ? state.path : '');
    const done = (v) => { m.remove(); resolve(v); };
    m.querySelector('#ok').onclick = () => done(m.querySelector('#sel').value); m.querySelector('#no').onclick = () => done(null);
  });
}
function askFolderName(title, initial = '') {
  const n = prompt(title, initial); if (n == null) return null;
  const name = n.trim().replace(/\s+/g, ' ');
  if (!name || name.includes('/') || name.length > 60) { toast('Folder names can\'t be empty, contain “/”, or exceed 60 characters.'); return null; }
  return name;
}
async function newFolder() {
  const name = askFolderName('New folder name'); if (!name) return;
  const path = state.path ? state.path + '/' + name : name;
  if (path.length > 180) return toast('Folder path too long.');
  if (allFolders().includes(path)) return toast('That folder already exists.');
  try { await tg.createFolder(path); toast('Folder created'); } catch (e) { toast('Failed: ' + errMsg(e)); }
}
async function renameFolder(path) {
  const name = askFolderName('Rename folder', baseName(path)); if (!name || name === baseName(path)) return;
  const np = parentOf(path) ? parentOf(path) + '/' + name : name;
  if (allFolders().includes(np)) return toast('A folder with that name already exists.');
  try { toast('Renaming…'); await tg.renameFolder(path, np); if (state.path === path || state.path.startsWith(path + '/')) state.path = np + state.path.slice(path.length); tg.onChange(); } catch (e) { toast('Failed: ' + errMsg(e)); }
}
async function deleteFolder(path) {
  const n = countIn(path);
  if (!confirm(`Delete folder “${baseName(path)}” and the ${n} file(s) inside it from Telegram Saved Messages? This cannot be undone.`)) return;
  try { await tg.deleteFolder(path); if (state.path === path || state.path.startsWith(path + '/')) state.path = parentOf(path); tg.onChange(); } catch (e) { toast('Failed: ' + errMsg(e)); }
}
async function moveItem(it) {
  if (!it.enc) return toast('Encrypt this file first, then you can put it in a folder.');
  const dest = await pickFolder(`Move “${nameOf(it)}” to…`); if (dest == null || dest === pathOf(it)) return;
  try { await tg.moveItems([it], dest); toast('Moved'); } catch (e) { toast('Failed: ' + errMsg(e)); }
}

const io = new IntersectionObserver((entries) => {
  for (const e of entries) if (e.isIntersecting) {
    io.unobserve(e.target);
    const it = tg.items.get(Number(e.target.dataset.id)); const img = e.target.querySelector('img');
    if (it && img && (it.isPhoto || (it.enc && it.meta && it.meta.th))) requestThumb(it, img);
  }
}, { rootMargin: '200px' });

function renderCrumbs() {
  const c = document.getElementById('crumbs'); if (!c) return;
  c.replaceChildren();
  if (flatView()) { c.append(h('<span class="sub">Showing matches from all folders</span>')); return; }
  const parts = state.path ? state.path.split('/') : [];
  const add = (label, path) => { const b = h(`<button class="crumb">${label}</button>`); b.onclick = () => { state.path = path; tg.onChange(); }; c.append(b); };
  add('🏠 Home', ''); parts.forEach((_, i) => { c.append(h('<span class="sub">/</span>')); add(esc(parts[i]), parts.slice(0, i + 1).join('/')); });
}
function renderGrid() {
  renderCrumbs();
  const old = document.getElementById('grid'); if (!old) return;
  const grid = h('<div id="grid" class="grid"></div>'); old.replaceWith(grid);
  const folders = flatView() ? [] : allFolders().filter((f) => parentOf(f) === state.path);
  const items = visibleItems();
  if (!folders.length && !items.length) {
    grid.className = 'empty'; grid.textContent = tg.items.size ? (flatView() ? 'No matches.' : 'This folder is empty — drop files here, paste an image, or press Upload.') : 'Nothing here yet — drop files anywhere, paste an image, or press Upload.'; return;
  }
  for (const f of folders) {
    const card = h(`<div class="card folder" data-path="${esc(f)}"><div class="thumb"><span class="big">📁</span></div>
      <div class="meta"><div class="name" title="${esc(baseName(f))}">${esc(baseName(f))}</div><div class="sub">${countIn(f)} file(s)</div></div>
      <div class="acts"><button class="btn small" data-a="rn">Rename</button><button class="btn small danger" data-a="rm">Delete</button></div></div>`);
    card.querySelector('.thumb').onclick = () => { state.path = f; tg.onChange(); };
    card.querySelector('[data-a=rn]').onclick = () => renameFolder(f);
    card.querySelector('[data-a=rm]').onclick = () => deleteFolder(f);
    card.ondragover = (e) => { if (e.dataTransfer.types.includes('application/x-tgv-id')) { e.preventDefault(); card.classList.add('over'); } };
    card.ondragleave = () => card.classList.remove('over');
    card.ondrop = async (e) => {
      const id = e.dataTransfer.getData('application/x-tgv-id'); if (!id) return; e.preventDefault(); e.stopPropagation(); card.classList.remove('over');
      const it = tg.items.get(Number(id)); if (!it || !it.enc) return toast('Encrypt this file first.');
      try { await tg.moveItems([it], f); toast('Moved to ' + baseName(f)); } catch (er) { toast('Failed: ' + errMsg(er)); }
    };
    grid.append(card);
  }
  for (const it of items) {
    const name = nameOf(it), ext = (name.split('.').pop() || '').slice(0, 4).toUpperCase();
    const hasThumb = it.isPhoto || (it.enc && it.meta && it.meta.th);
    const where = flatView() && pathOf(it) ? ' · 📁 ' + esc(pathOf(it)) : '';
    const card = h(`<div class="card" data-id="${it.id}" ${it.enc ? 'draggable="true"' : ''}>
      <div class="thumb" title="Open">${hasThumb ? '<img hidden alt="" draggable="false">' : ''}<span class="ext">${esc(ext)}</span>
        <span class="badge ${it.enc ? '' : 'plain'}">${it.enc ? '🔒 E2EE' : 'not encrypted'}</span></div>
      <div class="meta"><div class="name" title="${esc(name)}">${esc(name)}</div><div class="sub">${fmtSize(sizeOf(it))} · ${fmtDate(it.date)}${where}</div></div>
      <div class="acts"><button class="btn small" data-a="dl">Download</button><button class="btn small" data-a="sh" title="Make a password-locked file you can send to anyone">Share</button>${it.enc ? '<button class="btn small" data-a="mv">Move</button>' : '<button class="btn small" data-a="enc" title="Encrypt this file and replace the original">Encrypt</button>'}<button class="btn small danger" data-a="rm">Delete</button></div>
    </div>`);
    card.ondragstart = (e) => { e.dataTransfer.setData('application/x-tgv-id', String(it.id)); e.dataTransfer.effectAllowed = 'move'; };
    const img = card.querySelector('img');
    if (img) img.onload = () => { img.hidden = false; card.querySelector('.ext').hidden = true; };
    card.querySelector('.thumb').onclick = () => openPreview(it);
    card.querySelector('[data-a=dl]').onclick = () => downloadItem(it);
    card.querySelector('[data-a=sh]').onclick = () => shareItem(it);
    const mv = card.querySelector('[data-a=mv]'); if (mv) mv.onclick = () => moveItem(it);
    const enc = card.querySelector('[data-a=enc]'); if (enc) enc.onclick = () => encryptExisting(it);
    card.querySelector('[data-a=rm]').onclick = () => removeItem(it);
    if (thumbCache.has(it.id) && img) { img.src = thumbCache.get(it.id); } else io.observe(card);
    grid.append(card);
  }
}

function showLibrary() {
  screen(`<div>
    <div class="top">
      <div class="logo"><img src="icon48.png" alt="">TGVault</div>
      <input class="grow" type="search" id="q" placeholder="Search file names…" autocomplete="off">
      <div class="tabs" id="tabs">
        <button class="tab on" data-f="all">All</button><button class="tab" data-f="media">Photos &amp; videos</button>
        <button class="tab" data-f="file">Files</button><button class="tab" data-f="plain">Not encrypted</button>
      </div>
      <button class="btn primary" id="up">Upload</button>
      <button class="btn" id="nf">New folder</button>
      <button class="btn" id="rf" title="Re-sync with Saved Messages">↻</button>
      <button class="btn" id="lk" title="Forget the key on this device">Lock</button>
      <button class="btn danger" id="lo">Log out</button>
      <input type="file" id="pick" multiple hidden>
    </div>
    <main>
      <div id="crumbs" class="crumbs"></div>
      <div class="drop">Drag &amp; drop files here · everything is encrypted in your browser, then stored in your Telegram <b>Saved Messages</b></div>
      <div id="grid" class="grid"></div>
      <div class="row" style="justify-content:center;margin:18px"><button class="btn" id="more" hidden>Load more</button></div>
    </main>
    <div id="queue"></div>
  </div>`);
  const $ = (s) => document.querySelector(s);
  $('#q').oninput = (e) => { state.q = e.target.value; renderGrid(); };
  $('#tabs').onclick = (e) => { const b = e.target.closest('.tab'); if (!b) return; state.filter = b.dataset.f; document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('on', t === b)); renderGrid(); };
  $('#up').onclick = () => $('#pick').click();
  $('#nf').onclick = newFolder;
  $('#pick').onchange = (e) => { enqueue([...e.target.files]); e.target.value = ''; };
  $('#rf').onclick = () => syncNow(true);
  $('#lk').onclick = async () => { await idb.del('master'); tg.master = null; for (const it of tg.items.values()) it.meta = null; location.reload(); };
  $('#lo').onclick = () => doLogout();
  $('#more').onclick = async () => { $('#more').disabled = true; try { await tg.loadMore(); } finally { $('#more').disabled = false; } };
  tg.onChange = () => { if (state.path && !allFolders().includes(state.path)) state.path = ''; renderGrid(); const m = $('#more'); if (m) m.hidden = !tg.hasMore; };
  tg.onChange();
}

// drag & drop + paste (registered once)
let dragDepth = 0;
addEventListener('dragenter', (e) => { if (tg.master && e.dataTransfer.types.includes('Files')) { dragDepth++; document.body.classList.add('dragging'); e.preventDefault(); } });
addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
addEventListener('dragover', (e) => e.preventDefault());
addEventListener('drop', (e) => { e.preventDefault(); dragDepth = 0; document.body.classList.remove('dragging'); if (tg.master && e.dataTransfer.files.length && !e.dataTransfer.types.includes('application/x-tgv-id')) enqueue([...e.dataTransfer.files]); });
addEventListener('paste', (e) => { if (!tg.master || e.target.tagName === 'INPUT') return; const fs = [...(e.clipboardData?.files || [])]; if (fs.length) { enqueue(fs.map((f, i) => (f.name === 'image.png' ? new File([f], `pasted-${Date.now()}-${i}.png`, { type: f.type }) : f))); } });
addEventListener('beforeunload', (e) => { if (activeJobs > 0) { e.preventDefault(); e.returnValue = ''; } });

// ---------- upload queue ----------
let activeJobs = 0; const pending = []; let running = false;
function enqueue(files) { for (const f of files) pending.push({ file: f, path: state.path }); runQueue(); }
async function runQueue() {
  if (running) return; running = true;
  while (pending.length) {
    const { file, path } = pending.shift();
    const q = document.getElementById('queue');
    const job = h(`<div class="job"><div class="name">${esc(file.name)}</div><div class="sub" data-s>Preparing…</div><div class="bar"><i></i></div></div>`);
    q && q.append(job); activeJobs++;
    const setP = (label, f) => { job.querySelector('[data-s]').textContent = label; job.querySelector('i').style.width = Math.round(f * 100) + '%'; };
    try {
      const thumb = await makeThumb(file);
      await tg.uploadFile(file, thumb, path ? { p: path } : {}, (stage, f) => setP(stage === 'encrypt' ? 'Encrypting…' : 'Uploading to Telegram…', stage === 'encrypt' ? f * 0.3 : 0.3 + f * 0.7));
      setP('Done ✓', 1); setTimeout(() => job.remove(), 1500);
    } catch (e) { setP('Failed: ' + errMsg(e), 0); job.querySelector('i').style.background = 'var(--danger)'; setTimeout(() => job.remove(), 9000); }
    activeJobs--;
  }
  running = false;
}

// ---------- item actions ----------
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000);
}
async function downloadItem(it) {
  const t = document.querySelector(`.card[data-id="${it.id}"] [data-a=dl]`); const label = t && t.textContent;
  try {
    const blob = await tg.downloadDecrypted(it, (f) => { if (t) t.textContent = Math.round(f * 100) + '%'; });
    saveBlob(blob, nameOf(it));
  } catch (e) { toast('Download failed: ' + errMsg(e)); } finally { if (t) t.textContent = label; }
}
async function shareItem(it) {
  const size = sizeOf(it), name = nameOf(it), mime = it.enc ? (it.meta && it.meta.t) || '' : it.plainMime || '';
  if (it.enc && !it.meta) return toast('Cannot decrypt this file.');
  if (size > SHARE_MAX) return toast('Share files are limited to 150 MB (this one is ' + fmtSize(size) + ').');
  const m = h(`<div class="modal"><form class="panel" style="color:var(--fg)">
    <h1 style="font-size:18px">Share “${esc(name)}”</h1>
    <p>Creates one <b>.html</b> file locked with a password. Send it to anyone (Telegram, email, …): they open it in a browser, enter the password, and download the file. No account or extension needed.</p>
    <label>Password for the recipient</label>
    <div class="row"><input type="text" name="pw" autocomplete="off" required minlength="8" style="flex:1"><button type="button" class="btn small" id="gen">Generate</button></div>
    <div class="hint">At least 8 characters. Send the password <b>separately</b> from the file (e.g. a different chat).</div>
    <div class="bar" id="bar" hidden><i></i></div><div class="err" id="err"></div>
    <div class="row" style="margin-top:14px"><button class="btn primary" type="submit" id="mk">Create locked file</button><button class="btn" type="button" id="no">Close</button></div>
  </form></div>`);
  document.body.append(m);
  const pw = m.querySelector('[name=pw]'), err = m.querySelector('#err'), bar = m.querySelector('#bar'), mk = m.querySelector('#mk');
  m.querySelector('#gen').onclick = () => { pw.value = randomPassword(); pw.select(); };
  m.querySelector('#no').onclick = () => m.remove();
  m.querySelector('form').onsubmit = async (e) => {
    e.preventDefault(); err.textContent = '';
    if (pw.value.length < 8) { err.textContent = 'Use at least 8 characters.'; return; }
    mk.disabled = true; bar.hidden = false; const set = (f) => { bar.firstChild.style.width = Math.round(f * 100) + '%'; };
    try {
      mk.textContent = 'Downloading…';
      const blob = await tg.downloadDecrypted(it, (f) => set(f * 0.5));
      mk.textContent = 'Locking…';
      const out = await buildShareHtml(blob, name, mime, pw.value, (f) => set(0.5 + f * 0.5));
      saveBlob(out, name.replace(/[\\/:*?"<>|]+/g, '_') + '.locked.html');
      mk.textContent = 'Done ✓'; err.style.color = 'var(--ok)';
      err.textContent = 'Saved to your Downloads. Password: ' + pw.value;
    } catch (ex) { err.textContent = errMsg(ex); mk.disabled = false; mk.textContent = 'Create locked file'; }
  };
  pw.focus();
}
async function removeItem(it) {
  if (!confirm(`Delete “${nameOf(it)}” from Telegram Saved Messages? This cannot be undone.`)) return;
  try { await tg.remove([it.id]); } catch (e) { toast('Delete failed: ' + errMsg(e)); }
}
async function encryptExisting(it) {
  try {
    toast('Encrypting “' + nameOf(it) + '”…');
    const blob = await tg.downloadPlain(it);
    const file = new File([blob], it.plainName, { type: it.plainMime, lastModified: it.date * 1000 });
    const thumb = await makeThumb(file);
    await tg.uploadFile(file, thumb, state.path ? { p: state.path } : {});
    await tg.remove([it.id]); toast('Encrypted ✓ — original removed');
  } catch (e) { toast('Failed: ' + errMsg(e)); }
}
async function openPreview(it) {
  const k = it.enc ? (it.meta && it.meta.t) || '' : it.plainMime || '';
  if (!(k.startsWith('image/') || k.startsWith('video/') || k.startsWith('audio/'))) return downloadItem(it);
  const m = h(`<div class="modal"><div class="box"><div class="spinner"></div><div>Loading…</div></div></div>`);
  document.body.append(m); let url;
  const close = () => { m.remove(); url && URL.revokeObjectURL(url); document.removeEventListener('keydown', esc_); };
  const esc_ = (e) => { if (e.key === 'Escape') close(); }; document.addEventListener('keydown', esc_);
  m.onclick = (e) => { if (e.target === m) close(); };
  try {
    const blob = await tg.downloadDecrypted(it); url = URL.createObjectURL(blob);
    const tag = k.startsWith('image/') ? `<img src="${url}" alt="">` : k.startsWith('video/') ? `<video src="${url}" controls autoplay></video>` : `<audio src="${url}" controls autoplay></audio>`;
    m.firstChild.replaceChildren(h(tag), h(`<div class="row"><span>${esc(nameOf(it))}</span><button class="btn small">Download</button><button class="btn small">Close</button></div>`));
    const [dl, cl] = m.querySelectorAll('button'); dl.onclick = () => saveBlob(blob, nameOf(it)); cl.onclick = close;
  } catch (e) { toast('Preview failed: ' + errMsg(e)); close(); }
}

// ---------- sync / logout ----------
let lastSync = 0;
async function syncNow(manual) {
  if (Date.now() - lastSync < 4000 && !manual) return; lastSync = Date.now();
  try { await tg.refresh(); if (manual) toast('Synced with Saved Messages'); } catch (e) { if (manual) toast('Sync failed: ' + errMsg(e)); }
}
async function doLogout() {
  if (!confirm('Log out of Telegram and remove the session and encryption key from this browser?\n\nYour files stay in Saved Messages; you will need your passphrase to read them again.')) return;
  showLoading('Logging out…');
  try { if (tg.client) await tg.logout(); } catch { /* ignore */ }
  await store.clear(); await idb.clear();
  location.reload();
}

// ---------- boot ----------
(async function main() {
  try {
    showLoading('Connecting to Telegram…');
    const cfg = await store.get(['api_id', 'api_hash', 'session']);
    if (cfg.api_id && cfg.api_hash && cfg.session) {
      await tg.connect(cfg.api_id, cfg.api_hash, cfg.session);
      if (!(await tg.isAuthorized())) { try { await tg.client.disconnect(); } catch { /* */ } await store.remove('session'); await loginFlow({ api_id: cfg.api_id, api_hash: cfg.api_hash }); }
    } else {
      await loginFlow({ api_id: cfg.api_id, api_hash: cfg.api_hash });
    }
    await tg.init();
    await store.set({ session: tg.saveSession(), uid: tg.userId });

    showLoading('Loading your vault…');
    const saved = await idb.get('master');
    if (saved && saved.uid === tg.userId) { await tg.setMaster(saved.key); }
    else { await tg.loadMore(); await unlockFlow([...tg.items.values()].some((i) => i.enc)); }

    tg.startLive();
    showLibrary();
    await tg.loadMore();
    addEventListener('focus', () => syncNow(false));
    setInterval(() => store.set({ session: tg.saveSession() }), 60000);
  } catch (e) {
    screen(`<div class="center"><div class="panel"><h1>Something went wrong</h1><p>${esc(errMsg(e))}</p>
      <div class="row"><button class="btn primary" id="r">Retry</button><button class="btn danger" id="lo">Log out</button></div></div></div>`);
    document.getElementById('r').onclick = () => location.reload();
    document.getElementById('lo').onclick = () => doLogout();
  }
})();
