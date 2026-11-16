import assert from 'node:assert/strict';
import { deriveMasterBits, importMaster, sealString, openString, fitMeta, metaFits, utf8Len, META_JSON_MAX, deriveMasterKey, encryptFile, Decryptor, decryptThumb, encryptMeta, decryptMeta, keyCheck, CHUNK, THUMB_FETCH, decryptWhole } from './src/crypto.js';
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
// key bits -> same key as the one-step derivation (the bits are what is remembered in browser memory)
assert.equal(await keyCheck(await importMaster(await deriveMasterBits('correct horse', '12345'))), await keyCheck(master));
// saved Telegram session: round-trip, wrong key, tamper
const sealed = await sealString(master, '1BQANOTAREALSESSION-ü');
assert.ok(!sealed.includes('NOTAREAL'));
assert.equal(await openString(master, sealed), '1BQANOTAREALSESSION-ü');
await assert.rejects(openString(wrong, sealed));
await assert.rejects(openString(master, sealed.slice(0, -3) + (sealed.endsWith('AAA') ? 'BBB' : 'AAA')));
console.log('session seal ok');
// caption limit: long non-Latin names and deep folders must still fit Telegram's 1024-character caption
const telugu = 'తెలుగు'.repeat(40);
const big = fitMeta({ n: telugu + '.pdf', t: 'application/pdf', s: 5e9, m: Date.now(), th: 1, p: 'ఫోల్డర్/'.repeat(15) + 'x' });
assert.ok(metaFits(big) && big.n.endsWith('….pdf') && big.n.length < telugu.length, 'name shortened, extension kept');
assert.ok((await encryptMeta(master, big)).length <= 1024, 'caption within limit');
assert.ok((await encryptMeta(master, { n: 'x'.repeat(META_JSON_MAX - 8) })).length <= 1024, 'largest allowed meta fits');
const small = { n: 'holiday.jpg', t: 'image/jpeg', s: 1, m: 1, th: 1 };
assert.deepEqual(fitMeta(small), small);
assert.throws(() => fitMeta({ n: 'a.txt', t: 'text/plain', s: 1, m: 1, th: 0, p: 'p'.repeat(800) }));
assert.equal(utf8Len('తె'), 6);
console.log('caption limit ok');
console.log('ALL PASS');
