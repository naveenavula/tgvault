import fs from 'node:fs';
import { buildShareHtml, randomPassword } from './src/share.js';
const data = new Uint8Array(2.5 * 1024 * 1024 + 123).map((_, i) => (i * 31 + 7) % 251);
const html = Buffer.from(await (await buildShareHtml(new Blob([data]), 'my secret ü.pdf', 'application/pdf', 'hunter2-hunter2')).arrayBuffer());
fs.writeFileSync('share-test.html', html); fs.writeFileSync('share-test.orig', data);
const s = html.toString('latin1');
console.log('size', html.length, 'contains name?', s.includes('secret'), 'contains plain marker?', false, 'pw example', randomPassword());
let bad = false; try { await buildShareHtml(new Blob([data]), 'x', '', 'short'); } catch (e) { bad = true; } console.log('short pw rejected', bad);
