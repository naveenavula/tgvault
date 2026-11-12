import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve('.');
const nm = (p) => path.join(root, 'node_modules', p);
const out = process.argv[2] || 'dist';
const mock = process.argv[3] === 'mock';
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
await build({
  entryPoints: ['src/app.js'],
  bundle: true,
  outfile: path.join(out, 'app.js'),
  format: 'iife',
  platform: 'browser',
  target: 'chrome110',
  minify: false,
  sourcemap: false,
  legalComments: 'none',
  inject: ['src/shim.js'],
  define: { global: 'globalThis', 'process.env.NODE_ENV': '"production"' },
  alias: {
    crypto: nm('crypto-browserify'),
    stream: nm('stream-browserify'),
    path: nm('path-browserify'),
    os: path.join(root, 'stubs/os.js'),
    net: path.join(root, 'stubs/empty.js'),
    socks: path.join(root, 'stubs/empty.js'),
    fs: path.join(root, 'stubs/empty.js'),
    'node-localstorage': path.join(root, 'stubs/empty.js'),
    util: nm('util'),
    events: nm('events'),
    buffer: nm('buffer'),
    assert: nm('assert'),
  },
  plugins: mock ? [{ name: 'mock', setup(b) { b.onResolve({ filter: /^\.\/tg\.js$/ }, () => ({ path: path.join(root, 'src/tg.mock.js') })); } }] : [],
  logLevel: 'info',
});
for (const f of fs.readdirSync('static')) fs.copyFileSync(path.join('static', f), path.join(out, f));
console.log('built ->', out);
