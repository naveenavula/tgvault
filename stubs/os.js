module.exports = { type: () => 'Chrome', release: () => (navigator.userAgent.match(/Chrome\/([\d.]+)/) || [])[1] || '1', platform: () => 'browser', arch: () => 'wasm', EOL: '\n' };
