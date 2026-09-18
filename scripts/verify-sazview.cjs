'use strict';

// Exercise the unmodified SAZView loader and link handlers with synthetic captures.
// The archive's HTML is treated as data; it is never executed.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

async function main() {
  const [archivePath, viewerDirectory] = process.argv.slice(2);
  assert(archivePath && viewerDirectory,
    'Usage: node scripts\\verify-sazview.cjs <synthetic.saz> <SAZView-source-directory>');

  const blobs = new Map();
  const handlers = new Map();
  let navigation;
  let inspected;
  let failure;
  const window = {
    addEventListener: (name, handler) => handlers.set(name, handler),
    URL: {
      createObjectURL: blob => {
        const id = `blob:synthetic-${blobs.size}`;
        blobs.set(id, blob);
        return id;
      },
    },
    open: url => inspected?.(url),
  };
  const context = vm.createContext({
    window,
    document: {
      location: { href: 'https://sazview.invalid/' },
      addEventListener() {},
    },
    Blob, URL, Promise, ArrayBuffer, Uint8Array, DataView,
    TextEncoder, TextDecoder, setTimeout, clearTimeout, setImmediate,
    console: {
      log: message => {
        if (String(message).startsWith('ZIP load failed')) failure?.(new Error(message));
      },
    },
    alert: message => failure?.(new Error(message)),
    inputFile_: { value: null },
  });
  vm.runInContext(fs.readFileSync(path.join(viewerDirectory, 'third_party', 'jszip', 'jszip.min.js'), 'utf8'),
    context, { timeout: 5000 });
  context.JSZip = context.JSZip || window.JSZip;
  assert.equal(typeof context.JSZip, 'function', 'The reference JSZip library did not load');
  vm.runInContext(fs.readFileSync(path.join(viewerDirectory, 'sazview.js'), 'utf8'),
    context, { timeout: 5000 });
  context.navSessionList_ = url => {
    if (url.startsWith('blob:')) navigation?.(url);
  };
  let timeout;
  const loaded = new Promise((resolve, reject) => {
    navigation = resolve;
    failure = reject;
    timeout = setTimeout(() => reject(new Error('SAZView load timed out')), 5000);
  });
  context.onLoadBytes({ target: { result: Uint8Array.from(fs.readFileSync(archivePath)) } });
  let indexUrl;
  try { indexUrl = await loaded; } finally { clearTimeout(timeout); }
  const html = await blobs.get(indexUrl).text();
  assert(html.includes('https://sazview.invalid/sessionlist.js'), 'SAZView did not inject its index handler');
  const names = [...html.matchAll(/<a\b[^>]*\bhref=(['"])(raw[^'"]+)\1/gi)].map(match => match[2]);
  assert(names.length >= 3, 'The index has no session resource links');
  const zip = vm.runInContext('zip', context);
  const links = names.map(name => ({
    getAttribute: attribute => attribute === 'href' ? name : null,
    onclick: null,
  }));
  const posted = [];
  vm.runInNewContext(fs.readFileSync(path.join(viewerDirectory, 'sessionlist.js'), 'utf8'), {
    document: {
      getElementsByTagName: name => name === 'a' ? links : [],
      addEventListener: (name, callback) => { if (name === 'DOMContentLoaded') callback(); },
    },
    window: { top: { postMessage: data => posted.push(data) } },
    console: { log() {} },
  }, { timeout: 5000 });
  for (const link of links) {
    assert.equal(link.onclick({ target: link }), false);
    const request = posted.pop();
    assert.equal(request.op, 'inspect');
    assert(zip.files[request.item], `Broken SAZView index link: ${request.item}`);
    let inspectionTimeout;
    const opened = new Promise((resolve, reject) => {
      inspected = resolve;
      inspectionTimeout = setTimeout(() => reject(new Error('SAZView inspector timed out')), 5000);
    });
    handlers.get('message')({ data: request });
    let url;
    try { url = await opened; } finally { clearTimeout(inspectionTimeout); }
    const bytes = new Uint8Array(await blobs.get(url).arrayBuffer());
    assert(bytes.length > 0, `SAZView displayed an empty fixture resource: ${request.item}`);
  }
  console.log(`SAZView loaded the archive and opened all ${links.length} index resources.`);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
