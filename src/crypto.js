// TGVault E2EE layer. Pure WebCrypto – runs in browser and Node 20+ (for tests).
//
// Key hierarchy
//   passphrase --PBKDF2-SHA256(600k, per-user salt)--> 256-bit secret
//   secret --import as non-extractable HKDF key--> "master" (stored in IndexedDB, never leaves the browser as raw bytes)
//   master --HKDF(per-file random salt, info)--> AES-256-GCM file key / metadata key
//
// File format (what Telegram stores)
//   "TGV1" | chunkSize u32 | fileSalt 32B | ivPrefix 8B | thumbLen u32 | thumbCipher | chunk0 | chunk1 | ...
//   chunk i  = AES-GCM(key, iv = ivPrefix||i,  aad = i||finalFlag)    (plain size = chunkSize, last chunk shorter)
//   thumb    = AES-GCM(key, iv = ivPrefix||0xFFFFFFFF, aad = "thumb")  (optional small JPEG, so grid previews need only the first ~16 KB)
// The final-chunk flag in the AAD makes truncation / reordering / splicing detectable.
//
// Metadata (name, mime, size, ...) is kept in the Telegram message caption:
//   "TGV1:" + base64url( fileSalt | iv | AES-GCM(metaKey, json) )

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const MAGIC = 'TGV1';
export const CHUNK = 512 * 1024;
export const HEADER_LEN = 4 + 4 + 32 + 8 + 4; // 52
export const THUMB_FETCH = 16384; // bytes fetched from the start of a file to get header + thumbnail
export const MAX_THUMB = 12000;
const TAG = 16;
const PBKDF2_ITER = 600000;

const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function b64u(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; }
function ivFor(prefix8, counter) { return concat(prefix8, u32(counter)); }
function chunkAad(i, final) { return concat(u32(i), new Uint8Array([final ? 1 : 0])); }

// ---------- keys ----------
export async function deriveMasterKey(passphrase, userId) {
  const salt = new Uint8Array(await subtle.digest('SHA-256', enc.encode('TGVault/v1/salt/' + userId)));
  const base = await subtle.importKey('raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, base, 256);
  return subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey', 'deriveBits']); // non-extractable
}
async function subKey(master, salt, info, usages) {
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
    master, { name: 'AES-GCM', length: 256 }, false, usages);
}
/** short fingerprint to detect typos in the passphrase on the same device (not secret-bearing) */
export async function keyCheck(master) {
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('tgvault/check/v1') }, master, 64);
  return b64u(new Uint8Array(bits));
}

// ---------- metadata ----------
export function isVaultCaption(s) { return typeof s === 'string' && s.startsWith(MAGIC + ':'); }

export async function encryptMeta(master, meta, salt) {
  salt = salt || rand(32);
  const key = await subKey(master, salt, 'tgvault/meta/v1', ['encrypt']);
  const iv = rand(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode('meta') }, key, enc.encode(JSON.stringify(meta))));
  return MAGIC + ':' + b64u(concat(salt, iv, ct));
}
export function saltFromCaption(caption) { return unb64u(caption.slice(MAGIC.length + 1)).slice(0, 32); }
export async function decryptMeta(master, caption) {
  const raw = unb64u(caption.slice(MAGIC.length + 1));
  const salt = raw.subarray(0, 32), iv = raw.subarray(32, 44), ct = raw.subarray(44);
  const key = await subKey(master, salt, 'tgvault/meta/v1', ['decrypt']);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode('meta') }, key, ct);
  return JSON.parse(dec.decode(pt));
}

// ---------- file encryption ----------
/**
 * @param {Blob} file
 * @param {Uint8Array|null} thumbBytes small JPEG (<= MAX_THUMB) or null
 * @returns {{blob: Blob, salt: Uint8Array}} blob = ciphertext file; salt is needed for the caption
 */
export async function encryptFile(master, file, thumbBytes, onProgress) {
  const salt = rand(32), ivPrefix = rand(8);
  const key = await subKey(master, salt, 'tgvault/file/v1', ['encrypt']);
  let thumbCt = new Uint8Array(0);
  if (thumbBytes && thumbBytes.length) {
    if (thumbBytes.length > MAX_THUMB) throw new Error('thumbnail too large');
    thumbCt = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: ivFor(ivPrefix, 0xFFFFFFFF), additionalData: enc.encode('thumb') }, key, thumbBytes));
  }
  const header = concat(enc.encode(MAGIC), u32(CHUNK), salt, ivPrefix, u32(thumbCt.length));
  const parts = [header, thumbCt];
  const n = Math.max(1, Math.ceil(file.size / CHUNK));
  for (let i = 0; i < n; i++) {
    const pt = new Uint8Array(await file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer());
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv: ivFor(ivPrefix, i), additionalData: chunkAad(i, i === n - 1) }, key, pt);
    parts.push(new Uint8Array(ct));
    onProgress && onProgress((i + 1) / n);
  }
  return { blob: new Blob(parts, { type: 'application/octet-stream' }), salt };
}

function parseHeader(u8) {
  if (u8.length < HEADER_LEN || dec.decode(u8.subarray(0, 4)) !== MAGIC) throw new Error('Not a TGVault file');
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const chunk = dv.getUint32(4);
  if (chunk < 1024 || chunk > 8 * 1024 * 1024) throw new Error('Bad chunk size');
  const thumbLen = dv.getUint32(4 + 4 + 32 + 8);
  return { chunk, salt: u8.slice(8, 40), ivPrefix: u8.slice(40, 48), thumbLen };
}

/** Decrypt the thumbnail from the first THUMB_FETCH bytes of a file. Returns Uint8Array or null. */
export async function decryptThumb(master, head) {
  const h = parseHeader(head);
  if (!h.thumbLen) return null;
  if (head.length < HEADER_LEN + h.thumbLen) throw new Error('thumbnail not fully fetched');
  const key = await subKey(master, h.salt, 'tgvault/file/v1', ['decrypt']);
  const ct = head.subarray(HEADER_LEN, HEADER_LEN + h.thumbLen);
  return new Uint8Array(await subtle.decrypt(
    { name: 'AES-GCM', iv: ivFor(h.ivPrefix, 0xFFFFFFFF), additionalData: enc.encode('thumb') }, key, ct));
}

/** Streaming decryptor: feed() raw ciphertext pieces in order, get plaintext pieces back. */
export class Decryptor {
  constructor(master, totalLen) {
    this.master = master; this.total = totalLen;
    this.buf = new Uint8Array(0); this.consumed = 0; this.i = 0; this.state = 'header'; this.done = false;
  }
  async feed(u8) {
    this.buf = this.buf.length ? concat(this.buf, u8) : u8;
    const out = [];
    for (;;) {
      if (this.state === 'header') {
        if (this.buf.length < HEADER_LEN) break;
        const h = parseHeader(this.buf);
        this.h = h;
        this.key = await subKey(this.master, h.salt, 'tgvault/file/v1', ['decrypt']);
        this.skip = HEADER_LEN + h.thumbLen; // header + thumb are skipped
        this.state = 'skip';
      }
      if (this.state === 'skip') {
        if (this.buf.length < this.skip) break;
        this.buf = this.buf.subarray(this.skip); this.consumed += this.skip; this.state = 'chunks';
      }
      const remaining = this.total - this.consumed;
      const frameLen = Math.min(this.h.chunk + TAG, remaining);
      if (frameLen <= 0 || this.buf.length < frameLen) break;
      const final = remaining <= this.h.chunk + TAG;
      const frame = this.buf.subarray(0, frameLen);
      let pt;
      try {
        pt = await subtle.decrypt(
          { name: 'AES-GCM', iv: ivFor(this.h.ivPrefix, this.i), additionalData: chunkAad(this.i, final) }, this.key, frame);
      } catch { throw new Error('Decryption failed (wrong passphrase, or the file was modified)'); }
      out.push(new Uint8Array(pt));
      this.buf = this.buf.subarray(frameLen); this.consumed += frameLen; this.i++;
      if (final) { this.done = true; break; }
    }
    return out;
  }
  finish() { if (!this.done) throw new Error('Decryption failed: file is truncated'); }
}

export async function decryptWhole(master, u8) {
  const d = new Decryptor(master, u8.length);
  const parts = await d.feed(u8);
  d.finish();
  return concat(...parts);
}
