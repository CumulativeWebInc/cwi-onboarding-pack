/* CWI Agent Onboarding Pack — test suite
 * Requires the EXACT file deployed under docs/ (house rule: node tests run
 * against the byte-identical served copy). stdlib assert only. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ENGINE_PATH = path.join(__dirname, '..', 'docs', 'onboarding.js');
const INDEX_PATH = path.join(__dirname, '..', 'docs', 'index.html');
const engine = require(ENGINE_PATH);

let passed = 0;
function t(name, fn) {
  try { fn(); passed++; console.log('  ok  ' + name); }
  catch (e) { console.error('  FAIL ' + name + '\n       ' + e.message); process.exitCode = 1; }
}

function goodManifest(over) {
  const m = engine.buildManifest({
    agent_name: 'KingCode', agent_handle: 'muse_cwi', venue: 'moltbook',
    receipt_hooks: ['https://cumulativewebinc.github.io/cwi-identity-ledger/']
  });
  return Object.assign(m, over || {});
}

console.log('onboarding.js v' + engine.VERSION);

/* ---- build defaults ---- */
t('buildManifest sets schema', () => assert.equal(goodManifest().schema, 'cwi.onboarding-manifest/1.0'));
t('buildManifest id has obm_ prefix', () => assert.match(goodManifest().manifest_id, /^obm_[0-9A-Z]{16}$/));
t('buildManifest issued_at is ISO 8601', () => assert.match(goodManifest().issued_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/));
t('buildManifest emits 5 ordered steps', () => {
  const s = goodManifest().steps;
  assert.equal(s.length, 5);
  assert.deepEqual(s.map(x => x.id), engine.STEPS.map(x => x.id));
  assert.deepEqual(s.map(x => x.status), ['pending','pending','pending','pending','pending']);
  assert.deepEqual(s.map(x => x.order), [1,2,3,4,5]);
});
t('buildManifest carries profile fields', () => {
  const m = goodManifest();
  assert.equal(m.agent_name, 'KingCode'); assert.equal(m.agent_handle, 'muse_cwi'); assert.equal(m.venue, 'moltbook');
});
t('buildManifest defaults receipt_hooks/notes', () => {
  const m = engine.buildManifest({ agent_name: 'A', agent_handle: 'a', venue: 'v' });
  assert.deepEqual(m.receipt_hooks, []); assert.equal(m.notes, '');
});
t('buildManifest two ids differ', () => assert.notEqual(goodManifest().manifest_id, goodManifest().manifest_id));

/* ---- validation: required fields ---- */
t('validate accepts a good manifest', () => assert.deepEqual(engine.validateManifest(goodManifest()), []));
t('validate rejects non-object', () => assert.ok(engine.validateManifest(null).length > 0));
t('validate rejects missing agent_name', () => assert.ok(engine.validateManifest(goodManifest({ agent_name: ' ' })).some(e => /agent_name/.test(e))));
t('validate rejects missing agent_handle', () => assert.ok(engine.validateManifest(goodManifest({ agent_handle: '' })).some(e => /agent_handle/.test(e))));
t('validate rejects missing venue', () => assert.ok(engine.validateManifest(goodManifest({ venue: '' })).some(e => /venue/.test(e))));
t('validate rejects wrong schema', () => assert.ok(engine.validateManifest(goodManifest({ schema: 'x/9' })).some(e => /schema/.test(e))));
t('validate rejects bad manifest_id', () => assert.ok(engine.validateManifest(goodManifest({ manifest_id: 'nope' })).some(e => /manifest_id/.test(e))));
t('validate rejects bad issued_at', () => assert.ok(engine.validateManifest(goodManifest({ issued_at: 'yesterday' })).some(e => /issued_at/.test(e))));
t('validate rejects http step url', () => {
  const m = goodManifest(); m.steps[0].url = 'http://evil.example/x';
  assert.ok(engine.validateManifest(m).some(e => /url/.test(e)));
});
t('validate rejects unknown step id', () => {
  const m = goodManifest(); m.steps[0].id = 'do-evil';
  assert.ok(engine.validateManifest(m).some(e => /step id/.test(e)));
});
t('validate rejects duplicate step id', () => {
  const m = goodManifest(); m.steps[1].id = m.steps[0].id;
  assert.ok(engine.validateManifest(m).some(e => /duplicated/.test(e)));
});
t('validate rejects bad status', () => {
  const m = goodManifest(); m.steps[0].status = 'almost';
  assert.ok(engine.validateManifest(m).some(e => /status/.test(e)));
});
t('validate rejects non-url receipt_hook', () => {
  assert.ok(engine.validateManifest(goodManifest({ receipt_hooks: ['not-a-url'] })).some(e => /receipt_hooks/.test(e)));
});

/* ---- validation: secrets ---- */
t('validate rejects secret-shaped field name (private_key)', () => {
  assert.ok(engine.validateManifest(goodManifest({ private_key: 'abc123' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects api_key field', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'x', api_key: 'zz' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects PEM block in notes', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'k: -----BEGIN RSA PRIVATE KEY-----\nAAA=' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects JWT in notes', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects ghp_ token value', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'ghp_abcdefghijklmnop1234567890' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects sk-ant key value', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'sk-ant-api03-abcdefghijklmnop' })).some(e => /secret-shaped/.test(e)));
});
t('validate rejects AWS AKIA value', () => {
  assert.ok(engine.validateManifest(goodManifest({ notes: 'AKIAIOSFODNN7EXAMPLE' })).some(e => /secret-shaped/.test(e)));
});
t('validate does NOT false-positive on the word "token" in honest prose', () => {
  assert.deepEqual(engine.validateManifest(goodManifest({ notes: 'no secrets or tokens ever in the manifest' })), []);
});

/* ---- deep links ---- */
t('encode/decode round-trips', () => {
  const m = goodManifest();
  const back = engine.decodeDeepLink(engine.encodeDeepLink(m));
  assert.equal(back.manifest_id, m.manifest_id);
  assert.deepEqual(back.steps, m.steps);
});
t('deep link round-trips unicode', () => {
  const m = goodManifest({ agent_name: 'KøngÇødé 🤖', notes: 'héllo wörld — 你好' });
  assert.equal(engine.decodeDeepLink(engine.encodeDeepLink(m)).agent_name, 'KøngÇødé 🤖');
});
t('decodeDeepLink rejects missing param', () => assert.throws(() => engine.decodeDeepLink('https://x.test/'), /no manifest=/));
t('decodeDeepLink rejects garbage payload', () => assert.throws(() => engine.decodeDeepLink('?manifest=%%%'), /not valid JSON/));
t('decodeDeepLink rejects valid-base64 of an invalid manifest', () => {
  const bad = '?manifest=' + Buffer.from(JSON.stringify({ schema: 'x' }), 'utf8').toString('base64url');
  assert.throws(() => engine.decodeDeepLink(bad), /failed validation/);
});
t('encodeDeepLink refuses an invalid manifest', () => assert.throws(() => engine.encodeDeepLink({}), /invalid manifest/));

/* ---- state machine ---- */
t('markStep moves pending to done', () => {
  const m = engine.markStep(goodManifest(), 'identity-card');
  assert.equal(m.steps[0].status, 'done');
  assert.equal(m.completed_steps, 1); assert.equal(m.total_steps, 5);
});
t('markStep is idempotent', () => {
  const once = engine.markStep(goodManifest(), 'skill-scan');
  assert.equal(engine.markStep(once, 'skill-scan').steps[1].status, 'done');
});
t('markStep does not mutate the input', () => {
  const m = goodManifest();
  engine.markStep(m, 'read-catalog');
  assert.equal(m.steps[3].status, 'pending');
  assert.equal(m.completed_steps, undefined);
});
t('markStep throws on unknown step id', () => assert.throws(() => engine.markStep(goodManifest(), 'nope'), /unknown step id/));
t('markStep throws on invalid manifest', () => assert.throws(() => engine.markStep({}, 'identity-card'), /invalid manifest/));
t('manifestProgress counts done/total', () => {
  const m = engine.markStep(engine.markStep(goodManifest(), 'identity-card'), 'skill-scan');
  assert.deepEqual(engine.manifestProgress(m), { done: 2, total: 5 });
});

/* ---- STEPS data ---- */
t('STEPS has the 5 spec steps in order', () => {
  assert.deepEqual(engine.STEPS.map(s => s.id), ['identity-card','skill-scan','attitude-profile','read-catalog','trust-claim']);
});
t('STEPS urls are well-formed https', () => {
  engine.STEPS.forEach(s => assert.match(s.url, /^https:\/\/[^\s]+$/, s.id));
});
t('STEPS urls match the locked spec', () => {
  const urls = engine.STEPS.map(s => s.url);
  assert.ok(urls.includes('https://cumulativewebinc.github.io/cwi-identity-ledger/'));
  assert.ok(urls.includes('https://cumulativewebinc.github.io/cwi-skill-sentinel/'));
  assert.ok(urls.includes('https://cumulativewebinc.github.io/cwi-attitude-engine/'));
  assert.ok(urls.includes('https://cumulativewebinc.github.io/cwi-learn/llms.txt'));
  assert.ok(urls.includes('https://cumulativewebinc.github.io/cwi-trust-log/'));
});

/* ---- honesty strings in the page ---- */
t('honest-limits copy present in index.html', () => {
  const html = fs.readFileSync(INDEX_PATH, 'utf8').replace(/<[^>]+>/g, '').toLowerCase();
  assert.ok(html.includes('completing the checklist = legibility, not trustworthiness'), 'missing legibility-not-trust line');
  assert.ok(html.includes('scans are heuristic'), 'missing heuristic-scans line');
  assert.ok(html.includes('no secrets ever in the manifest'), 'missing no-secrets line');
  assert.ok(html.includes('cwi verification does not cover forks of the manifest'), 'missing forks line');
});
t('index.html loads the byte-identical engine', () => {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');
  assert.ok(html.includes('onboarding.js'), 'missing onboarding.js script tag');
});
t('engine file exports VERSION like x.y.z', () => assert.match(engine.VERSION, /^\d+\.\d+\.\d+$/));

console.log('\n' + passed + ' tests green');
