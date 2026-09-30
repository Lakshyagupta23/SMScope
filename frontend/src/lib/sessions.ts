/** One adapter for history, upload results and WebSocket replay. No inferred security evidence. */
export type JsonRecord = Record<string, unknown>;
export type SessionStatus = 'unknown' | 'secure' | 'elevated' | 'high' | 'critical';
export function statusColor(status: SessionStatus): string {
  return status === 'critical' || status === 'high' ? 'text-red-400' :
    status === 'elevated' ? 'text-amber-400' : status === 'secure' ? 'text-green-400' : 'text-gray-400';
}
export interface Session extends JsonRecord {
  session_id: string;
  analysis_id: string | null;
  id: string;
  src_ip: string;
  dst_ip: string;
  email_protocol: string;
  src: string;
  dst: string;
  protocol: string;
  reason: string;
  status: SessionStatus;
  assessment_status: string;
  score: number | null;
  tls_version: string | null;
  cipher_suite: string | null;
  forward_secrecy: JsonRecord & { has_forward_secrecy: boolean | null; reason: string };
  trust: boolean | null;
  certificates: JsonRecord[];
  risk_factors: string[];
  remediations: string[];
  component_statuses: JsonRecord;
  evidence_coverage: unknown;
  is_mitigated: boolean;
}

export function record(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {};
}
export function text(value: unknown, fallback = 'Unknown'): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}
export function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
export function triState(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}
export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}
export function triLabel(value: boolean | null): string {
  return value === true ? 'Yes' : value === false ? 'No' : 'Unknown / not assessed';
}
export function display(value: unknown): string {
  return value === null || value === undefined || value === '' ? 'Unknown / unavailable' :
    typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
}

export function isVerifiedResponse(value: unknown): boolean {
  const r = record(value);
  const status = text(r.status, '').toUpperCase();
  if (['DRY_RUN', 'FAILED', 'LOGGED_ONLY', 'MITIGATION_FAILED', 'UNVERIFIED'].includes(status)) return false;
  return status === 'VERIFIED' || status === 'MITIGATION_VERIFIED' ||
    (r.verified === true && status === 'EXECUTED');
}

export function isScopedMitigation(value: unknown): boolean {
  const r = record(value);
  return isVerifiedResponse(r) && r.analysis_scope_verified === true && r.is_mitigated === true;
}

export function normalizeSession(value: unknown): Session {
  const r = record(value);
  const analysis_id = text(r.analysis_id, '') || null;
  const src = text(r.src_ip, text(r.src));
  const dst = text(r.dst_ip, text(r.dst));
  const protocol = text(r.email_protocol, text(r.protocol));
  // Legacy rows without provenance are visibly unscoped. Do not invent an analysis run.
  const legacyId = JSON.stringify([analysis_id, r.id ?? r.stream_index ?? null, src, dst,
    r.src_port ?? null, r.dst_port ?? null, r.timestamp ?? r.start_time ?? null]);
  const session_id = text(r.session_id, `legacy:${legacyId}`);
  const n = finiteNumber(r.score);
  const score = n !== null && n >= 0 && n <= 100 ? n : null;
  const statuses: SessionStatus[] = ['unknown', 'secure', 'elevated', 'high', 'critical'];
  let status: SessionStatus = statuses.includes(r.status as SessionStatus) ? r.status as SessionStatus : 'unknown';
  if (status === 'secure' && (score === null || r.assessment_status === 'unknown' || r.assessment_status === 'unassessed')) status = 'unknown';
  const fs = record(r.forward_secrecy);
  const trustResult = record(r.trust_validation ?? r.certificate_trust);
  const risk_factors = strings(r.risk_factors);
  return {
    ...r, session_id, analysis_id, id: session_id, src_ip: src, dst_ip: dst,
    email_protocol: protocol, src, dst, protocol, status, score,
    reason: text(r.reason, risk_factors.join('; ') || 'No finding supplied; evidence may be incomplete'),
    assessment_status: text(r.assessment_status, 'unknown'),
    tls_version: text(r.tls_version, '') || null,
    cipher_suite: text(r.cipher_suite, '') || null,
    forward_secrecy: { ...fs, has_forward_secrecy: triState(fs.has_forward_secrecy), reason: text(fs.reason, 'Insufficient evidence') },
    trust: triState(trustResult.trusted ?? trustResult.is_trusted ?? r.trust),
    certificates: Array.isArray(r.certificates) ? r.certificates.map(record) : [],
    risk_factors, remediations: strings(r.remediations),
    component_statuses: record(r.component_statuses ?? r.components),
    evidence_coverage: r.evidence_coverage ?? null,
    is_mitigated: r.is_mitigated === true && (isScopedMitigation(r.mitigation) || isScopedMitigation(r.response)),
  };
}

export function mergeSessions(existing: Session[], incoming: unknown[]): Session[] {
  const byId = new Map(existing.map(s => [s.session_id, s]));
  for (const raw of incoming) {
    const r = record(raw);
    if (!Object.keys(r).length) continue;
    const s = normalizeSession(raw);
    const previous = byId.get(s.session_id);
    // Replayed analysis records cannot erase a verified response receipt.
    byId.set(s.session_id, previous?.is_mitigated && !s.is_mitigated
      ? { ...s, is_mitigated: true, mitigation: previous.mitigation } : s);
  }
  return [...byId.values()];
}

export function sessionArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  const r = record(value);
  return Array.isArray(r.sessions) ? r.sessions : Array.isArray(r.results) ? r.results : [];
}

export function applyResponse(sessions: Session[], value: unknown): Session[] {
  const r = record(value);
  const analysisId = text(r.analysis_id, '');
  if (!analysisId) return sessions; // Never apply an IP-only event across captures.
  const results = record(r.ips_results);
  return sessions.map(s => {
    const result = [results[s.src_ip], results[s.dst_ip]].find(isScopedMitigation);
    return s.analysis_id === analysisId && result !== undefined
      ? { ...s, is_mitigated: true, mitigation: result } : s;
  });
}

export function tlsLabel(session: Session): string {
  if (session.tls_version) return session.tls_version;
  return session.plaintext_observed === true || session.encryption_status === 'plaintext' || session.encryption_state === 'plaintext'
    ? 'Plaintext (observed)' : 'Unknown / not visible';
}

export function aggregateSessions(input: Session[]) {
  const sessions = [...new Map(input.map(s => [s.session_id, s])).values()];
  const scored = sessions.filter((s): s is Session & { score: number } => s.score !== null);
  const findings = sessions.filter(s => ['critical', 'high', 'elevated'].includes(s.status));
  const legacy = sessions.filter(s => /^(SSL|TLSv?1\.[01]$)/i.test(s.tls_version ?? '')).length;
  const knownTls = sessions.filter(s => s.tls_version !== null).length;
  return {
    total: sessions.length,
    score: scored.length ? scored.reduce((sum, s) => sum + s.score, 0) / scored.length : null,
    scored: scored.length,
    unscored: sessions.length - scored.length,
    unknown: sessions.filter(s => s.status === 'unknown').length,
    breaches: findings.filter(s => !s.is_mitigated).length,
    totalBreaches: findings.length,
    resolvedBreaches: findings.filter(s => s.is_mitigated).length,
    legacy, knownTls,
    legacyPercent: knownTls ? legacy / knownTls * 100 : null,
  };
}
export type SessionStats = ReturnType<typeof aggregateSessions>;
