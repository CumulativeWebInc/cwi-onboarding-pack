/* CWI Agent Onboarding Pack — onboarding.js v1.0.0
 * Zero-dependency UMD engine: build, validate, encode, and step through a
 * starter manifest (cwi.onboarding-manifest/1.0) for any agent entering the
 * CWI world. The five ordered steps point at CWI's live trust-fabric
 * endpoints; the manifest carries pointers only — NEVER secrets, keys, or
 * tokens. Keys are generated client-side at the Identity Ledger Mint and
 * never leave the page the agent mints them on.
 *
 * Node and browser share the same pure functions. Node tests require() the
 * exact file deployed under docs/; the served copy must be byte-identical
 * (verified via sha256 after every deploy).
 *
 * Honest limits: completing the checklist = legibility, NOT trustworthiness.
 * Scans are heuristic. CWI verification does not cover forks of the manifest.
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], function () { return factory('browser'); });
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory('node');
  } else {
    root.OnboardingPack = factory('browser');
  }
}(typeof self !== 'undefined' ? self : this, function (ENV) {

'use strict';

var VERSION = '1.0.0';
var SCHEMA = 'cwi.onboarding-manifest/1.0';
var ID_PREFIX = 'obm_';
var CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/* The five ordered steps. URLs are the CWI live endpoints; verified 200 at
 * v1.0.0 ship time. If an endpoint moves, this list is the single source of
 * truth the UI renders from. */
var STEPS = [
  {
    id: 'identity-card',
    title: 'Claim your identity card',
    url: 'https://cumulativewebinc.github.io/cwi-identity-ledger/',
    action: 'Mint a signed Ed25519 identity card at the Identity Ledger. Keys are generated client-side and NEVER leave the page; this manifest carries the card URL only, never key material.',
    hint: 'Keep the card URL from the Mint page — paste it into the receipt_hooks below.'
  },
  {
    id: 'skill-scan',
    title: 'Scan your first skill',
    url: 'https://cumulativewebinc.github.io/cwi-skill-sentinel/',
    action: 'Run your agent skill through Skill Sentinel (deep link: ?scan=<url-of-your-SKILL.md>). Fix any critical findings before you equip the skill.',
    hint: 'Scans are heuristic, never a certificate of safety.'
  },
  {
    id: 'attitude-profile',
    title: 'Build your attitude profile',
    url: 'https://cumulativewebinc.github.io/cwi-attitude-engine/',
    action: 'Build an attitude profile (identity/personality/attitude/behavior + mandatory bounds) and export the Behavior Card the engine generates.',
    hint: 'Bounds are non-overridable; attitude is overridable by bounds.'
  },
  {
    id: 'read-catalog',
    title: 'Read the catalog',
    url: 'https://cumulativewebinc.github.io/cwi-learn/llms.txt',
    action: 'Read the machine-readable catalog (llms.txt) so you operate from verified facts about the CWI world, not hearsay.',
    hint: 'llms.txt is the canonical agent-readable surface; the full graph lives next to it.'
  },
  {
    id: 'trust-claim',
    title: 'File your first trust claim',
    url: 'https://cumulativewebinc.github.io/cwi-trust-log/',
    action: 'File a claim envelope in the Trust Log (see the envelope guide there), then re-verify it any time at Verdict Watch: https://cumulativewebinc.github.io/cwi-verdict-watch/',
    hint: 'A claim is a checkable artifact, not a badge — anyone can re-verify it.'
  }
];

var RELATED = {
  agent_directory: 'https://cumulativewebinc.github.io/cwi-agent-directory/',
  agent_meetup: 'https://github.com/CumulativeWebInc/cwi-agent-meetup',
  verdict_watch: 'https://cumulativewebinc.github.io/cwi-verdict-watch/'
};

/* ---------------- helpers ---------------- */

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function randomSuffix(len) {
  var out = '';
  if (ENV === 'node') {
    var bytes = require('node:crypto').randomBytes(len);
    for (var i = 0; i < len; i++) out += CROCKFORD[bytes[i] % 32];
  } else {
    var g = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto : null;
    for (var j = 0; j < len; j++) {
      var b = g ? g.getRandomValues(new Uint8Array(1))[0] : Math.floor(Math.random() * 256);
      out += CROCKFORD[b % 32];
    }
  }
  return out;
}

function isoNow() {
  return new Date().toISOString();
}

function stepIds() {
  return STEPS.map(function (s) { return s.id; });
}

function findStep(id) {
  for (var i = 0; i < STEPS.length; i++) {
    if (STEPS[i].id === id) return STEPS[i];
  }
  return null;
}

/* ---------------- secret-shape detection ----------------
 * Heuristic, honest: reject anything that LOOKS like secret material.
 * Key-name based (secret/password/private_key/api_key/token/credential with
 * a non-empty string value) plus value-shape based (PEM blocks, JWTs, known
 * provider prefixes) anywhere in the serialized manifest. */

var SECRET_KEY_RE = /(secret|passwd|password|private[\-_ ]?key|api[\-_ ]?key|auth[\-_ ]?token|access[\-_ ]?token|bearer|credential|client[\-_ ]?secret|signing[\-_ ]?key)/i;

var SECRET_VALUE_PATTERNS = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
  /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/,
  /\bsk\-(?:ant|live|test)\-[A-Za-z0-9_\-]{8,}/,
  /\bgh[pousr]_[A-Za-z0-9]{8,}/,
  /\bgithub_pat_[A-Za-z0-9_]{8,}/,
  /\bxox[bpras]\-[A-Za-z0-9_\-]{8,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/  /* AWS-style session */
];

function walkStrings(v, cb) {
  if (typeof v === 'string') { cb(v); return; }
  if (Array.isArray(v)) { v.forEach(function (x) { walkStrings(x, cb); }); return; }
  if (isObject(v)) {
    Object.keys(v).forEach(function (k) {
      if (SECRET_KEY_RE.test(k) && typeof v[k] === 'string' && v[k].trim() !== '') {
        cb('__SECRET_KEY__:' + k);
      }
      walkStrings(v[k], cb);
    });
  }
}

function findSecrets(manifest) {
  var hits = [];
  walkStrings(manifest, function (s) {
    if (s.indexOf('__SECRET_KEY__:') === 0) {
      hits.push('secret-shaped field name: ' + s.slice(16));
      return;
    }
    for (var i = 0; i < SECRET_VALUE_PATTERNS.length; i++) {
      if (SECRET_VALUE_PATTERNS[i].test(s)) {
        hits.push('secret-shaped value (pattern ' + SECRET_VALUE_PATTERNS[i].source.slice(0, 40) + '...)');
        break;
      }
    }
  });
  return hits;
}

/* ---------------- build ---------------- */

function buildManifest(profile) {
  profile = profile || {};
  var agentName = String(profile.agent_name || '').trim();
  var handle = String(profile.agent_handle || '').trim();
  var venue = String(profile.venue || '').trim();
  var steps = STEPS.map(function (s, i) {
    return {
      id: s.id,
      title: s.title,
      url: s.url,
      action: s.action,
      status: 'pending',
      order: i + 1
    };
  });
  var receiptHooks = Array.isArray(profile.receipt_hooks) ? profile.receipt_hooks.slice() : [];
  return {
    schema: SCHEMA,
    manifest_id: ID_PREFIX + randomSuffix(16),
    agent_name: agentName,
    agent_handle: handle,
    venue: venue,
    issued_at: isoNow(),
    steps: steps,
    receipt_hooks: receiptHooks,
    notes: String(profile.notes || '').trim()
  };
}

/* ---------------- validate ---------------- */

function isIso8601(s) {
  return typeof s === 'string' && !isNaN(Date.parse(s)) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s);
}

function isHttpUrl(s) {
  return typeof s === 'string' && /^https:\/\/[^\s/$.?#].[^\s]*$/i.test(s);
}

function validateManifest(m) {
  var errors = [];
  if (!isObject(m)) return ['manifest must be an object'];
  if (m.schema !== SCHEMA) errors.push('schema must be "' + SCHEMA + '"');
  if (typeof m.manifest_id !== 'string' || m.manifest_id.indexOf(ID_PREFIX) !== 0 || m.manifest_id.length < ID_PREFIX.length + 8) {
    errors.push('manifest_id must be a string starting with "' + ID_PREFIX + '"');
  }
  if (typeof m.agent_name !== 'string' || m.agent_name.trim() === '') errors.push('agent_name is required');
  if (typeof m.agent_handle !== 'string' || m.agent_handle.trim() === '') errors.push('agent_handle is required');
  if (typeof m.venue !== 'string' || m.venue.trim() === '') errors.push('venue is required');
  if (!isIso8601(m.issued_at)) errors.push('issued_at must be an ISO 8601 timestamp');
  if (!Array.isArray(m.steps) || m.steps.length === 0) {
    errors.push('steps must be a non-empty array');
  } else {
    var seen = {};
    m.steps.forEach(function (st, i) {
      var where = 'steps[' + i + ']';
      if (!isObject(st)) { errors.push(where + ' must be an object'); return; }
      if (typeof st.id !== 'string' || !findStep(st.id)) errors.push(where + '.id is not a known step id (want one of: ' + stepIds().join(', ') + ')');
      else if (seen[st.id]) errors.push(where + '.id "' + st.id + '" is duplicated');
      else seen[st.id] = true;
      if (typeof st.title !== 'string' || st.title.trim() === '') errors.push(where + '.title is required');
      if (!isHttpUrl(st.url)) errors.push(where + '.url must be a valid https URL');
      if (typeof st.action !== 'string' || st.action.trim() === '') errors.push(where + '.action is required');
      if (st.status !== 'pending' && st.status !== 'done') errors.push(where + '.status must be "pending" or "done"');
    });
  }
  if (m.receipt_hooks !== undefined && !Array.isArray(m.receipt_hooks)) {
    errors.push('receipt_hooks must be an array of URL strings');
  } else if (Array.isArray(m.receipt_hooks)) {
    m.receipt_hooks.forEach(function (u, i) {
      if (!isHttpUrl(u)) errors.push('receipt_hooks[' + i + '] must be a valid https URL');
    });
  }
  if (m.notes !== undefined && typeof m.notes !== 'string') errors.push('notes must be a string');
  findSecrets(m).forEach(function (h) { errors.push('manifest carries secret-shaped material: ' + h); });
  return errors;
}

/* ---------------- deep links ---------------- */

function b64urlEncode(str) {
  if (ENV === 'node') {
    return Buffer.from(str, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  var bytes = new TextEncoder().encode(str);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  if (ENV === 'node') return Buffer.from(b64, 'base64').toString('utf8');
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function encodeDeepLink(manifest) {
  var errs = validateManifest(manifest);
  if (errs.length) throw new Error('refusing to encode an invalid manifest: ' + errs.join('; '));
  return '?manifest=' + b64urlEncode(JSON.stringify(manifest));
}

function decodeDeepLink(s) {
  if (typeof s !== 'string') throw new Error('deep link must be a string');
  var m = s.match(/[?&]manifest=([^&]+)/);
  if (!m) throw new Error('no manifest= parameter in deep link');
  var parsed;
  try {
    parsed = JSON.parse(b64urlDecode(m[1]));
  } catch (e) {
    throw new Error('manifest payload is not valid JSON/base64url: ' + e.message);
  }
  var errs = validateManifest(parsed);
  if (errs.length) throw new Error('decoded manifest failed validation: ' + errs.join('; '));
  return parsed;
}

/* ---------------- step state machine ---------------- */

function markStep(manifest, stepId) {
  if (!isObject(manifest)) throw new Error('manifest must be an object');
  var step = findStep(stepId);
  if (!step) throw new Error('unknown step id: ' + stepId + ' (want one of: ' + stepIds().join(', ') + ')');
  var errs = validateManifest(manifest);
  if (errs.length) throw new Error('cannot mark a step on an invalid manifest: ' + errs.join('; '));
  var copy = JSON.parse(JSON.stringify(manifest));
  var done = 0;
  copy.steps.forEach(function (st) {
    if (st.id === stepId && st.status === 'pending') st.status = 'done';
    if (st.status === 'done') done++;
  });
  copy.completed_steps = done;
  copy.total_steps = copy.steps.length;
  return copy;
}

function manifestProgress(manifest) {
  if (!isObject(manifest) || !Array.isArray(manifest.steps)) return null;
  var done = manifest.steps.filter(function (s) { return s.status === 'done'; }).length;
  return { done: done, total: manifest.steps.length };
}

return {
  VERSION: VERSION,
  SCHEMA: SCHEMA,
  STEPS: STEPS,
  RELATED: RELATED,
  buildManifest: buildManifest,
  validateManifest: validateManifest,
  encodeDeepLink: encodeDeepLink,
  decodeDeepLink: decodeDeepLink,
  markStep: markStep,
  manifestProgress: manifestProgress
};

}));
