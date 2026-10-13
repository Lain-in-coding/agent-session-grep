// Execute the shipped inline script with a small DOM boundary and controllable
// fetch promises. Deliberately ignore abort in fetch so late completions also
// exercise the request-identity guard. No packages, browser, or network needed.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = readFileSync(join(__dirname, '../src/web/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const flush = () => new Promise(resolve => setImmediate(resolve));

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.className = '';
    this.value = '';
    this.checked = false;
    this.hidden = false;
    this.disabled = false;
    this.dataset = {};
    this._text = '';
    this.classList = {
      add: value => this.setClass(value, true),
      remove: value => this.setClass(value, false),
      toggle: (value, force) => this.setClass(value, force ?? !this.className.split(' ').includes(value)),
    };
  }
  setClass(value, on) {
    const values = new Set(this.className.split(' ').filter(Boolean));
    if (on) values.add(value); else values.delete(value);
    this.className = [...values].join(' ');
    return on;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.append(child); return child; }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }
  dispatch(type, extra = {}) {
    return (this.listeners.get(type) || []).map(handler => handler({ target: this, ...extra }));
  }
  matches(selector) { return selector.split(',').some(tag => tag.trim().toUpperCase() === this.tagName); }
  checkValidity() {
    if (this.attributes.get('type') !== 'number') return true;
    if (!this.value) return !this.attributes.has('required');
    const number = Number(this.value);
    return Number.isInteger(number) && number >= Number(this.attributes.get('min') || '-Infinity')
      && number <= Number(this.attributes.get('max') || 'Infinity');
  }
  reportValidity() { return this.checkValidity(); }
}

async function page() {
  const nodes = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    const node = new Element(match[1]);
    for (const attribute of match[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) {
      node.setAttribute(attribute[1], attribute[2] || '');
    }
    node.value = node.getAttribute('value') || '';
    node.hidden = node.attributes.has('hidden');
    node.disabled = node.attributes.has('disabled');
    nodes.set(match[3], node);
  }
  for (const match of html.matchAll(/<select\b[^>]*id="([^"]+)"[^>]*>\s*<option value="([^"]*)"/g)) {
    nodes.get(match[1]).value = match[2];
  }
  const document = new Element('document');
  document.documentElement = new Element('html');
  document.activeElement = new Element('body');
  document.getElementById = id => {
    assert.ok(nodes.has(id), `missing markup id ${id}`);
    return nodes.get(id);
  };
  document.createElement = tag => new Element(tag);
  document.querySelectorAll = () => [];
  for (const node of nodes.values()) node.focus = () => { document.activeElement = node; };
  const storage = new Map([['asg-web-token', 'a'.repeat(32)], ['asg-web-lang', 'en']]);
  const localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  };
  const window = new Element('window');
  window.location = { href: 'http://127.0.0.1:8080/' };
  window.history = { replaceState() {} };
  window.matchMedia = () => ({ matches: false });
  const pending = [];
  const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  const fetch = (url, options) => {
    if (url === '/api/status') return Promise.resolve(response({ data: {
      generation: 1, catalog_count: 4, web_capabilities: { provider_values: ['claude-code', 'codex', 'opencode'] },
    } }));
    if (url === '/api/providers') return Promise.resolve(response({ data: {
      providers: ['claude-code', 'codex', 'opencode', 'deferred-provider'].map(provider_id => ({ provider_id })),
    } }));
    return new Promise((resolve, reject) => pending.push({
      url, options, done: false,
      resolve(body, status) { this.done = true; resolve(response(body, status)); },
      reject(error) { this.done = true; reject(error); },
    }));
  };
  const ui = vm.createContext({ document, window, localStorage, navigator: { language: 'en' },
    URL, URLSearchParams, AbortController, DOMException, fetch, console });
  vm.runInContext(script, ui, { filename: 'embedded-web-ui.js' });
  await flush();
  return { ui, nodes, document, storage, pending,
    request(prefix) {
      const request = pending.find(item => !item.done && item.url.startsWith(prefix));
      assert.ok(request, `no pending request for ${prefix}`);
      return request;
    },
  };
}

function searchBody(id, cursor = null) {
  return { data: { hits: [{ id, session_id: `ses_${id}`, text: id, score: 1 }], retrieval_mode: 'lexical' },
    page: { has_more: Boolean(cursor), next_cursor: cursor } };
}
function contextBody(text) {
  return { data: { messages: [{ message_id: `msg_${text}`, payload: { role: 'user', text } }] } };
}
async function search(p, id = 'first', cursor = null) {
  p.nodes.get('query').value = 'needle';
  const task = p.ui.doSearch();
  p.request('/api/search?').resolve(searchBody(id, cursor));
  await task;
}

test('all visible filters reach the API and providers use the capability registry', async () => {
  const p = await page();
  const fields = { query: 'needle', mode: 'hybrid', limit: '3', maxBytes: '4096', provider: 'opencode',
    repo: 'owner/repo', since: '2026-01-01T00:00:00Z', until: '2027-01-01T00:00:00Z',
    sidechain: 'subagent_only', toolKind: 'command', toolName: 'shell' };
  for (const [id, value] of Object.entries(fields)) p.nodes.get(id).value = value;
  p.nodes.get('includeSystem').checked = true;
  p.nodes.get('groupBySession').checked = true;
  const task = p.ui.doSearch();
  const request = p.request('/api/search?');
  assert.deepEqual(Object.fromEntries(new URL(request.url, 'http://localhost').searchParams), {
    q: 'needle', mode: 'hybrid', limit: '3', max_bytes: '4096', provider: 'opencode', repo: 'owner/repo',
    since: fields.since, until: fields.until, sidechain: 'subagent_only', tool_kind: 'command',
    tool_name: 'shell', include_system: 'true', group_by_session: 'true',
  });
  assert.ok(!p.nodes.get('provider').children.some(option => option.value === 'deferred-provider'));
  assert.equal(p.nodes.get('results').getAttribute('aria-busy'), 'true');
  request.resolve(searchBody('filtered'));
  await task;
  assert.equal(p.nodes.get('results').getAttribute('aria-busy'), 'false');
});

for (const failure of [false, true]) test(`late search ${failure ? 'failure' : 'success'} cannot replace a newer result`, async () => {
  const p = await page();
  p.nodes.get('query').value = 'old';
  const oldTask = p.ui.doSearch();
  const old = p.request('/api/search?');
  p.nodes.get('query').value = 'new';
  const newTask = p.ui.doSearch();
  const newer = p.pending.at(-1);
  assert.equal(old.options.signal.aborted, true);
  newer.resolve(searchBody('new-result', 'new-page'));
  await newTask;
  if (failure) old.reject(new Error('old failure')); else old.resolve(searchBody('old-result', 'old-page'));
  await oldTask;
  assert.match(p.nodes.get('results').textContent, /new-result/);
  assert.doesNotMatch(p.nodes.get('results').textContent, /old-result|old failure/);
  assert.equal(p.nodes.get('loadMore').disabled, false);
});

test('each search input invalidates its cursor and both change events retain feedback', async () => {
  const ids = ['query', 'provider', 'mode', 'limit', 'maxBytes', 'repo', 'since', 'until',
    'sidechain', 'toolKind', 'toolName', 'includeSystem', 'groupBySession'];
  for (const id of ids) {
    const p = await page();
    await search(p, 'first', 'page-two');
    p.nodes.get(id).dispatch('input');
    p.nodes.get(id).dispatch('change');
    assert.equal(p.nodes.get('loadMore').disabled, true, id);
    assert.equal(p.nodes.get('handoff').disabled, true, id);
    assert.equal(p.nodes.get('results').children.length, 0, id);
    assert.match(p.nodes.get('searchFeedback').textContent, /criteria changed/, id);
    const count = p.pending.length;
    p.nodes.get('loadMore').dispatch('click');
    assert.equal(p.pending.length, count, id);
  }
});

test('cursor guard also rejects programmatic input changes and duplicate page loads', async () => {
  const p = await page();
  await search(p, 'first', 'page-two');
  const firstPage = p.ui.doSearch('page-two');
  await p.ui.doSearch('page-two');
  assert.equal(p.pending.filter(item => !item.done).length, 1);
  p.request('/api/search?').resolve(searchBody('second', 'page-three'));
  await firstPage;
  assert.match(p.nodes.get('resultMeta').textContent, /2$/);
  p.nodes.get('repo').value = 'different/repo';
  const count = p.pending.length;
  await p.ui.doSearch('page-three');
  assert.equal(p.pending.length, count);
  assert.equal(p.nodes.get('loadMore').disabled, true);
});

test('clearing a query or failing a request resets paging, busy state and visible results', async () => {
  const p = await page();
  await search(p, 'first', 'page-two');
  const task = p.ui.doSearch('page-two');
  const old = p.request('/api/search?');
  p.nodes.get('query').value = '';
  await p.ui.doSearch();
  old.resolve(searchBody('obsolete', 'obsolete-page'));
  await task;
  assert.equal(p.nodes.get('results').textContent, '');
  assert.match(p.nodes.get('searchFeedback').textContent, /Enter a search query/);
  assert.equal(p.nodes.get('loadMore').disabled, true);
  p.nodes.get('query').value = 'failed';
  const failing = p.ui.doSearch();
  p.request('/api/search?').resolve({ error: { message: 'synthetic error' } }, 400);
  await failing;
  assert.match(p.nodes.get('searchFeedback').textContent, /synthetic error/);
  assert.equal(p.nodes.get('results').getAttribute('aria-busy'), 'false');
  assert.equal(p.nodes.get('loadMore').disabled, true);
});

for (const failure of [false, true]) test(`late context ${failure ? 'failure' : 'success'} cannot overwrite a new session`, async () => {
  const p = await page();
  const first = p.ui.loadContext('ses_a');
  const old = p.request('/api/context?');
  const second = p.ui.loadContext('ses_b');
  assert.equal(p.nodes.get('contextMessages').textContent, '');
  p.pending.at(-1).resolve(contextBody('new-session'));
  await second;
  if (failure) old.reject(new Error('old error')); else old.resolve(contextBody('old-session'));
  await first;
  assert.match(p.nodes.get('contextMessages').textContent, /new-session/);
  assert.doesNotMatch(p.nodes.get('contextMessages').textContent, /old-session|old error/);
  assert.equal(p.nodes.get('contextMessages').getAttribute('aria-busy'), 'false');
});

test('context policy changes reload and closing prevents context or preview resurrection', async () => {
  const p = await page();
  await search(p);
  p.nodes.get('results').children[0].dispatch('click');
  const old = p.request('/api/context?');
  p.nodes.get('contextPolicy').value = 'full';
  p.nodes.get('contextPolicy').dispatch('change');
  const current = p.pending.at(-1);
  assert.match(current.url, /policy=full/);
  current.resolve(contextBody('full-context'));
  await flush();
  const previewTask = p.ui.previewResume();
  const preview = p.request('/api/resume?');
  p.nodes.get('closeContext').dispatch('click');
  old.resolve(contextBody('late-context'));
  preview.resolve({ data: { command: 'synthetic resume' } });
  await previewTask;
  await flush();
  assert.equal(p.nodes.get('contextMessages').textContent, '');
  assert.equal(p.nodes.get('previewOutput').hidden, true);
  assert.equal(p.nodes.get('contextPanel').hidden, true);
  assert.ok(!p.nodes.get('results').children[0].className.includes('active'));
});

test('an old unauthorized response cannot discard a newly accepted token', async () => {
  const p = await page();
  p.nodes.get('query').value = 'old';
  const task = p.ui.doSearch();
  const old = p.request('/api/search?');
  p.ui.acceptToken('b'.repeat(32));
  await flush();
  old.resolve({}, 401);
  await task;
  assert.equal(p.storage.get('asg-web-token'), 'b'.repeat(32));
  assert.equal(p.nodes.get('gate').hidden, true);
});

test('slash stays editable in filter inputs and a language switch preserves all loaded hits', async () => {
  const p = await page();
  for (const id of ['repo', 'since', 'toolName', 'mode']) {
    p.nodes.get(id).focus();
    let prevented = false;
    p.document.dispatch('keydown', { key: '/', preventDefault() { prevented = true; } });
    assert.equal(prevented, false, id);
    assert.equal(p.document.activeElement, p.nodes.get(id));
  }
  await search(p, 'first', 'page-two');
  const task = p.ui.doSearch('page-two');
  p.request('/api/search?').resolve(searchBody('second'));
  await task;
  p.nodes.get('langToggle').dispatch('click');
  await flush();
  assert.equal(p.nodes.get('results').children.length, 2);
  assert.match(p.nodes.get('resultMeta').textContent, /2$/);
});
