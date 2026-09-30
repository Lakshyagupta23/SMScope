import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateSessions, applyResponse, isVerifiedResponse, mergeSessions, normalizeSession, sessionArray, tlsLabel, triLabel } from '../src/lib/sessions.ts';

const raw = (id, values = {}) => ({ session_id: id, analysis_id: 'case-A', src_ip: '192.0.2.1', dst_ip: '198.51.100.2', email_protocol: 'SMTP', ...values });
const verified = { status: 'VERIFIED', verified: true, analysis_scope_verified: true, is_mitigated: true };

test('raw API fields and aliases converge without losing forensic provenance', () => {
  const s = normalizeSession(raw('stable-1', { capture_sha256: 'abc', evidence_coverage: { percentage: 25 }, risk_factors: ['Selected TLS is deprecated'], status: 'high', score: 70 }));
  assert.equal(s.id, 'stable-1'); assert.equal(s.src, s.src_ip); assert.equal(s.dst, s.dst_ip);
  assert.equal(s.protocol, s.email_protocol); assert.equal(s.reason, 'Selected TLS is deprecated');
  assert.equal(s.capture_sha256, 'abc'); assert.deepEqual(s.evidence_coverage, { percentage: 25 });
});

test('missing or malformed evidence is unknown, never zero, clean, plaintext or secure', () => {
  for (const input of [{}, null, { status: 'secure' }, { status: 'unexpected', score: '100' }, { score: NaN }, { score: Infinity }, { score: 101 }]) {
    const s = normalizeSession(input);
    assert.equal(s.status, 'unknown'); assert.equal(s.score, null);
    assert.equal(s.forward_secrecy.has_forward_secrecy, null); assert.equal(s.trust, null);
    assert.equal(tlsLabel(s), 'Unknown / not visible');
  }
  assert.equal(normalizeSession({ score: 0, status: 'critical' }).score, 0);
  assert.equal(triLabel(null), 'Unknown / not assessed');
});

test('false and true forward-secrecy / trust observations remain distinct from null', () => {
  for (const value of [true, false, null]) {
    const s = normalizeSession(raw('s', { forward_secrecy: { has_forward_secrecy: value }, trust_validation: { trusted: value } }));
    assert.equal(s.forward_secrecy.has_forward_secrecy, value); assert.equal(s.trust, value);
  }
  assert.equal(tlsLabel(normalizeSession(raw('s', { encryption_state: 'plaintext' }))), 'Plaintext (observed)');
  assert.equal(tlsLabel(normalizeSession(raw('s', { email_protocol: 'IMAPS' }))), 'Unknown / not visible');
});

test('initial history, socket snapshot, repeated reconnect and upload receipt are idempotent', () => {
  const records = [raw('one', { score: 20, status: 'critical' }), raw('two', { score: 80, status: 'elevated' })];
  let sessions = mergeSessions([], sessionArray(records));
  for (let i = 0; i < 4; i++) sessions = mergeSessions(sessions, sessionArray({ sessions: records }));
  sessions = mergeSessions(sessions, sessionArray({ results: records }));
  assert.equal(sessions.length, 2);
  const stats = aggregateSessions(sessions);
  assert.equal(stats.total, 2); assert.equal(stats.score, 50); assert.equal(stats.breaches, 2);
  assert.equal(aggregateSessions([...sessions, ...sessions]).total, 2);
});

test('aggregate denominator excludes missing scores and uses all selected unique sessions', () => {
  const sessions = mergeSessions([], [raw('a', { score: 20, status: 'critical', tls_version: 'TLSv1.0' }),
    raw('b', { score: 80, status: 'elevated', tls_version: 'TLSv1.2' }), raw('c')]);
  const stats = aggregateSessions(sessions);
  assert.equal(stats.score, 50); assert.equal(stats.scored, 2); assert.equal(stats.unscored, 1);
  assert.equal(stats.unknown, 1); assert.equal(stats.legacyPercent, 50); assert.equal(stats.knownTls, 2);
  assert.equal(aggregateSessions([]).score, null); assert.equal(aggregateSessions([]).legacyPercent, null);
  assert.equal(aggregateSessions([normalizeSession(raw('elevated', { status: 'elevated', score: 85 }))]).score, 85);
});

test('same stream and endpoints in different analyses do not collide', () => {
  const sessions = mergeSessions([], [raw('run-A:0'), raw('run-B:0', { analysis_id: 'case-B' })]);
  assert.equal(sessions.length, 2);
  assert.equal(aggregateSessions(sessions.filter(s => s.analysis_id === 'case-B')).total, 1);
  const legacy = mergeSessions([], [{ id: 1, stream_index: 0 }, { id: 2, stream_index: 0 }]);
  assert.equal(legacy.length, 2); assert.equal(legacy[0].analysis_id, null);
});

test('requested IPs, failed, dry-run, logged-only and merely executed actions never hide findings', () => {
  const sessions = mergeSessions([], [raw('one', { status: 'critical', score: 20 })]);
  for (const status of ['FAILED', 'DRY_RUN', 'LOGGED_ONLY', 'EXECUTED', 'MITIGATION_FAILED']) {
    const updated = applyResponse(sessions, { analysis_id: 'case-A', ips: ['192.0.2.1'], ips_results: { '192.0.2.1': { status } } });
    assert.equal(updated[0].is_mitigated, false); assert.equal(aggregateSessions(updated).breaches, 1);
  }
  assert.equal(applyResponse(sessions, { type: 'bulk_mitigate', ips: ['192.0.2.1'] })[0].is_mitigated, false);
  assert.equal(normalizeSession(raw('one', { is_mitigated: true })).is_mitigated, false);
  assert.equal(isVerifiedResponse({ status: 'DRY_RUN', verified: true }), false);
});

test('verified host rule presence without verified analysis scope is not session mitigation', () => {
  const sessions = mergeSessions([], [raw('one', { status: 'high', score: 60 })]);
  const updated = applyResponse(sessions, { analysis_id: 'case-A', ips_results: { '192.0.2.1': { status: 'VERIFIED', verified: true, is_mitigated: false, analysis_scope_verified: false } } });
  assert.equal(updated[0].is_mitigated, false);
});

test('a scoped verified receipt affects only its endpoint and analysis, and survives replay', () => {
  const records = [raw('one', { status: 'critical', score: 20 }), raw('two', { analysis_id: 'case-B', status: 'high', score: 60 })];
  let sessions = mergeSessions([], records);
  sessions = applyResponse(sessions, { analysis_id: 'case-A', ips_results: { '192.0.2.1': { status: 'FAILED' }, '198.51.100.2': verified } });
  assert.equal(sessions[0].is_mitigated, true); assert.equal(sessions[1].is_mitigated, false);
  sessions = mergeSessions(sessions, records);
  assert.equal(sessions[0].is_mitigated, true);
  const stats = aggregateSessions(sessions);
  assert.equal(stats.breaches, 1); assert.equal(stats.resolvedBreaches, 1); assert.equal(stats.score, 40);
});
