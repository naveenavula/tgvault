// Thin wrapper around GramJS (MTProto, browser build): login, Saved Messages listing, streaming upload/download.
import { TelegramClient, Api } from 'telegram';
import { StringSession } from 'telegram/sessions';
import { NewMessage, Raw } from 'telegram/events';
import { generateRandomLong } from 'telegram/Helpers';
import bigInt from 'big-integer';
import {
  encryptFile, encryptMeta, decryptMeta, saltFromCaption, decryptThumb, Decryptor, isVaultCaption, THUMB_FETCH,
} from './crypto.js';

const PART = 512 * 1024;
const BIG_THRESHOLD = 10 * 1024 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const num = (x) => (x && typeof x.toJSNumber === 'function' ? x.toJSNumber() : Number(x));

export class TG {
  constructor() {
    this.client = null; this.me = null; this.master = null;
    this.items = new Map();                  // id -> item
    this.cursors = { doc: { off: 0, done: false }, photo: { off: 0, done: false } };
    this.onChange = () => {};
  }

  // ---------- session ----------
  async connect(apiId, apiHash, sessionStr = '') {
    this.apiId = Number(apiId); this.apiHash = String(apiHash);
    this.session = new StringSession(sessionStr);
    this.client = new TelegramClient(this.session, this.apiId, this.apiHash, {
      connectionRetries: 10, retryDelay: 1500, autoReconnect: true, useWSS: true, floodSleepThreshold: 60,
      deviceModel: 'Chrome extension', appVersion: 'TGVault 1.0',
    });
    this.client.setLogLevel('error');
    await this.client.connect();
  }
  async isAuthorized() { return this.client.checkAuthorization(); }
  /** callbacks: {phone(), code(), password(), onError(e)} – each returns a Promise<string> */
  async login(cb) {
    await this.client.start({
      phoneNumber: cb.phone, phoneCode: cb.code, password: cb.password,
      onError: async (e) => { cb.onError(e); return false; },
    });
  }
  saveSession() { return this.session.save(); }
  async init() {
    this.me = await this.client.getMe();
    this.userId = String(this.me.id);
    this.premium = !!this.me.premium;
    this.maxSize = this.premium ? 4000 * 1024 * 1024 : 2000 * 1024 * 1024;
  }
  async logout() {
    try { await this.client.invoke(new Api.auth.LogOut()); } catch { /* ignore */ }
    try { await this.client.disconnect(); } catch { /* ignore */ }
  }

  // ---------- listing / sync ----------
  _ingest(msg) {
    if (!msg || !msg.media) return null;
    const doc = msg.document, photo = msg.photo;
    if (!doc && !photo) return null;
    const cap = msg.message || '';
    const enc = !!doc && isVaultCaption(cap);
    const prev = this.items.get(msg.id);
    const it = prev || { id: msg.id };
    if (prev && prev.cap !== cap) { it.meta = null; it.metaErr = false; }
    Object.assign(it, {
      msg, date: msg.date, enc, cap,
      size: doc ? num(doc.size) : 0,
      isPhoto: !!photo,
      plainName: doc ? (doc.attributes.find((a) => a.fileName) || {}).fileName || 'file' : 'photo_' + msg.id + '.jpg',
      plainMime: doc ? doc.mimeType : 'image/jpeg',
    });
    this.items.set(msg.id, it);
    return it;
  }
  async _page(kind) {
    const c = this.cursors[kind];
    if (c.done) return 0;
    const filter = kind === 'doc' ? new Api.InputMessagesFilterDocument() : new Api.InputMessagesFilterPhotos();
    const msgs = await this.client.getMessages('me', { limit: 100, offsetId: c.off, filter });
    for (const m of msgs) this._ingest(m);
    if (msgs.length < 100) c.done = true;
    if (msgs.length) c.off = msgs[msgs.length - 1].id;
    return msgs.length;
  }
  async loadMore() {
    await Promise.all([this._page('doc'), this._page('photo')]);
    await this._decryptMetas();
    this.onChange();
  }
  get hasMore() { return !(this.cursors.doc.done && this.cursors.photo.done); }
  async refresh() {
    // pull newest page, then drop anything deleted elsewhere (phone/desktop)
    const [d, p] = await Promise.all([
      this.client.getMessages('me', { limit: 100, filter: new Api.InputMessagesFilterDocument() }),
      this.client.getMessages('me', { limit: 100, filter: new Api.InputMessagesFilterPhotos() }),
    ]);
    for (const m of [...d, ...p]) this._ingest(m);
    const ids = [...this.items.keys()];
    for (let i = 0; i < ids.length; i += 100) {
      const slice = ids.slice(i, i + 100);
      const got = await this.client.getMessages('me', { ids: slice });
      const alive = new Set(got.filter((m) => m && !m.className?.includes('Empty')).map((m) => m.id));
      for (const id of slice) if (!alive.has(id)) this.items.delete(id);
    }
    await this._decryptMetas();
    this.onChange();
  }
  async _decryptMetas() {
    if (!this.master) return;
    for (const it of this.items.values()) {
      if (it.enc && !it.meta && !it.metaErr) {
        try { it.meta = await decryptMeta(this.master, it.cap); } catch { it.metaErr = true; }
      }
    }
  }
  /** After (re)unlock: retry metas that failed */
  async setMaster(master) {
    this.master = master;
    for (const it of this.items.values()) { it.metaErr = false; it.meta = null; }
    await this._decryptMetas();
  }
  /** Used right after unlock on a fresh device: true if the passphrase decrypts an existing vault file (or none exist) */
  async verifyAgainstVault() {
    const first = [...this.items.values()].find((i) => i.enc);
    if (!first) return true;
    try { await decryptMeta(this.master, first.cap); return true; } catch { return false; }
  }
  startLive() {
    const me = this.me.id;
    const isSaved = (m) => m && m.peerId && num(m.peerId.userId) === num(me);
    this.client.addEventHandler(async (ev) => {
      if (isSaved(ev.message) && this._ingest(ev.message)) { await this._decryptMetas(); this.onChange(); }
    }, new NewMessage({}));
    this.client.addEventHandler(async (u) => {
      if (u instanceof Api.UpdateDeleteMessages) {
        let ch = false; for (const id of u.messages) ch = this.items.delete(id) || ch; if (ch) this.onChange();
      }
    }, new Raw({ types: [Api.UpdateDeleteMessages] }));
  }

  // ---------- upload ----------
  async _uploadBlob(blob, name, onProgress) {
    const total = Math.ceil(blob.size / PART), big = blob.size > BIG_THRESHOLD;
    const fileId = generateRandomLong();
    let next = 0, sent = 0;
    const worker = async () => {
      for (;;) {
        const i = next++; if (i >= total) return;
        const bytes = Buffer.from(await blob.slice(i * PART, (i + 1) * PART).arrayBuffer());
        for (let attempt = 0; ; attempt++) {
          try {
            await this.client.invoke(big
              ? new Api.upload.SaveBigFilePart({ fileId, filePart: i, fileTotalParts: total, bytes })
              : new Api.upload.SaveFilePart({ fileId, filePart: i, bytes }));
            break;
          } catch (e) { if (attempt >= 5) throw e; await sleep(800 * (attempt + 1)); }
        }
        sent += bytes.length; onProgress && onProgress(sent / blob.size);
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, total) }, worker));
    return big ? new Api.InputFileBig({ id: fileId, parts: total, name })
      : new Api.InputFile({ id: fileId, parts: total, name, md5Checksum: '' });
  }
  /**
   * Encrypt in the browser, upload as an opaque .bin document into Saved Messages.
   * @param {File} file  @param {Uint8Array|null} thumb  @param {{w?:number,h?:number}} extra
   * @param {(stage:'encrypt'|'upload', frac:number)=>void} onProgress
   */
  async uploadFile(file, thumb, extra, onProgress) {
    if (file.size > this.maxSize) throw new Error(`File too large for Telegram (${this.premium ? '4' : '2'} GB limit)`);
    const { blob, salt } = await encryptFile(this.master, file, thumb, (f) => onProgress && onProgress('encrypt', f));
    const meta = { n: (file.name || 'file').slice(0, 200), t: file.type || 'application/octet-stream', s: file.size, m: file.lastModified || Date.now(), th: thumb ? 1 : 0, ...extra };
    const caption = await encryptMeta(this.master, meta, salt);
    const rnd = Array.from(crypto.getRandomValues(new Uint8Array(6))).map((b) => b.toString(16).padStart(2, '0')).join('');
    const fname = `tgv-${rnd}.bin`;
    const handle = await this._uploadBlob(blob, fname, (f) => onProgress && onProgress('upload', f));
    const res = await this.client.invoke(new Api.messages.SendMedia({
      peer: new Api.InputPeerSelf(),
      media: new Api.InputMediaUploadedDocument({
        file: handle, mimeType: 'application/octet-stream', forceFile: true,
        attributes: [new Api.DocumentAttributeFilename({ fileName: fname })],
      }),
      message: caption, randomId: generateRandomLong(),
    }));
    let id = null;
    for (const u of res.updates || []) { if (u.message && u.message.id && u.className.includes('NewMessage')) id = u.message.id; }
    if (id) { const [m] = await this.client.getMessages('me', { ids: [id] }); this._ingest(m); await this._decryptMetas(); this.onChange(); }
    else await this.refresh();
    this.saveSession();
  }

  // ---------- download ----------
  async _fresh(it) {
    const [m] = await this.client.getMessages('me', { ids: [it.id] });
    if (!m || !m.media) throw new Error('Message no longer exists');
    this._ingest(m); return this.items.get(it.id);
  }
  async *_stream(it, requestSize = PART) {
    it = await this._fresh(it);
    for await (const chunk of this.client.iterDownload({ file: it.msg.media, requestSize, fileSize: bigInt(it.size) })) yield chunk;
  }
  /** Decrypt-while-downloading; returns a Blob of plaintext. */
  async downloadDecrypted(it, onProgress) {
    if (!it.enc) return this.downloadPlain(it, onProgress);
    if (!it.meta) throw new Error('Cannot decrypt: wrong passphrase or damaged metadata');
    const dec = new Decryptor(this.master, it.size); const parts = []; let got = 0;
    for await (const chunk of this._stream(it)) {
      for (const p of await dec.feed(chunk)) parts.push(p);
      got += chunk.length; onProgress && onProgress(got / it.size);
    }
    dec.finish();
    return new Blob(parts, { type: it.meta.t || 'application/octet-stream' });
  }
  async downloadPlain(it, onProgress) {
    const parts = []; let got = 0;
    if (it.isPhoto) {
      const buf = await this.client.downloadMedia((await this._fresh(it)).msg);
      return new Blob([buf], { type: 'image/jpeg' });
    }
    for await (const chunk of this._stream(it)) { parts.push(new Uint8Array(chunk)); got += chunk.length; onProgress && onProgress(got / it.size); }
    return new Blob(parts, { type: it.plainMime });
  }
  /** Small preview image blob (decrypted JPEG) for the grid, or null */
  async thumbnail(it) {
    if (it.isPhoto) return this.downloadPlain(it);
    if (!it.enc || !it.meta || !it.meta.th) return null;
    const fresh = await this._fresh(it);
    let head = new Uint8Array(0);
    for await (const chunk of this.client.iterDownload({ file: fresh.msg.media, offset: bigInt.zero, requestSize: THUMB_FETCH, limit: 1, fileSize: bigInt(it.size) })) {
      head = new Uint8Array(chunk); break;
    }
    const t = await decryptThumb(this.master, head);
    return t ? new Blob([t], { type: 'image/jpeg' }) : null;
  }

  // ---------- folders (stored encrypted as meta.p on each file; empty folders = tiny hidden marker file) ----------
  async _setMeta(it, mutate) {
    const meta = { ...it.meta }; mutate(meta);
    const cap = await encryptMeta(this.master, meta, saltFromCaption(it.cap));
    await this.client.editMessage('me', { message: it.id, text: cap });
    it.cap = cap; it.meta = meta;
  }
  _inFolder(it, path) { const p = it.enc && it.meta && it.meta.p; return !!p && (p === path || p.startsWith(path + '/')); }
  async createFolder(path) { await this.uploadFile(new File([], '.folder'), null, { k: 'folder', p: path }); }
  async moveItems(its, path) {
    for (const it of its) if (it.enc && it.meta) await this._setMeta(it, (m) => { if (path) m.p = path; else delete m.p; });
    this.onChange();
  }
  async renameFolder(oldP, newP) {
    for (const it of [...this.items.values()]) if (this._inFolder(it, oldP)) await this._setMeta(it, (m) => { m.p = newP + m.p.slice(oldP.length); });
    this.onChange();
  }
  async deleteFolder(path) { await this.remove([...this.items.values()].filter((it) => this._inFolder(it, path)).map((it) => it.id)); }

  async remove(ids) {
    await this.client.deleteMessages('me', ids, { revoke: true });
    for (const id of ids) this.items.delete(id);
    this.onChange();
  }
}
