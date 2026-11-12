import assert from 'node:assert/strict';
import { deriveMasterKey, encryptFile, Decryptor, decryptThumb, encryptMeta, decryptMeta, keyCheck, CHUNK, THUMB_FETCH, decryptWhole } from './src/crypto.js';
const master = await deriveMasterKey('correct horse', '12345');
const wrong = await deriveMasterKey('wrong horse', '12345');
const blobToU8 = async (b) => new Uint8Array(await b.arrayBuffer());
async function roundtrip(size, thumb) {
  const pt = new Uint8Array(size); for (let i = 0; i < size; i += 65536) crypto.getRandomValues(pt.subarray(i, Math.min(size, i + 65536)));
  const { blob } = await encryptFile(master, new Blob([pt]), thumb);
  const ct = await blobToU8(blob);
  // feed in awkward piece sizes
  const d = new Decryptor(master, ct.length); const parts = [];
  for (let o = 0; o < ct.length; o += 100003) parts.push(...await d.feed(ct.subarray(o, Math.min(ct.length, o + 100003))));
  d.finish();
  const out = new Uint8Array(parts.reduce((a, b) => a + b.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  assert.deepEqual(out, pt);
  return ct;
}
for (const s of [0, 1, 1000, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 77]) await roundtrip(s, null);
console.log('roundtrip sizes ok');
// thumbnail
const thumb = new Uint8Array(5000).map((_, i) => i % 251);
const ct = await roundtrip(2 * CHUNK + 5, thumb);
assert.deepEqual(await decryptThumb(master, ct.subarray(0, THUMB_FETCH)), thumb);
console.log('thumb ok');
// tamper: flip a bit
const t = ct.slice(); t[t.length - 20] ^= 1;
await assert.rejects(async () => { const d = new Decryptor(master, t.length); await d.feed(t); d.finish(); });
// truncation (drop last chunk) must fail
const trunc = ct.subarray(0, ct.length - (5 + 16));
await assert.rejects(async () => { const d = new Decryptor(master, trunc.length); await d.feed(trunc); d.finish(); });
// chunk reorder: swap chunk 0 and 1
const hdr = 52 + thumb.length + 16; const f = CHUNK + 16;
const sw = ct.slice(); sw.set(ct.subarray(hdr + f, hdr + 2 * f), hdr); sw.set(ct.subarray(hdr, hdr + f), hdr + f);
await assert.rejects(async () => { const d = new Decryptor(master, sw.length); await d.feed(sw); d.finish(); });
// wrong key
await assert.rejects(async () => { const d = new Decryptor(wrong, ct.length); await d.feed(ct); d.finish(); });
console.log('tamper/truncate/reorder/wrong-key rejected');
// meta
const cap = await encryptMeta(master, { n: 'ünï.png', t: 'image/png', s: 42 });
assert.ok(cap.length < 600, 'caption len ' + cap.length);
assert.deepEqual(await decryptMeta(master, cap), { n: 'ünï.png', t: 'image/png', s: 42 });
await assert.rejects(decryptMeta(wrong, cap));
assert.equal(await keyCheck(master), await keyCheck(await deriveMasterKey('correct horse', '12345')));
assert.notEqual(await keyCheck(master), await keyCheck(wrong));
console.log('meta ok, caption length', cap.length);
console.log('ALL PASS');
