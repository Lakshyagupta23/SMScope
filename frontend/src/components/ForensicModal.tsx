import { useEffect } from 'react';
import { X } from 'lucide-react';
import { display, record, statusColor, text, tlsLabel, triLabel, triState } from '../lib/sessions';
import type { Session } from '../lib/sessions';
import { ComponentHealth, EvidenceValue } from './Evidence';

export function ForensicModal({ session, onClose }: { session: Session | null; onClose: () => void }) {
  useEffect(() => {
    if (!session) return;
    const close = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', close);
    return () => window.removeEventListener('keydown', close);
  }, [session, onClose]);
  if (!session) return null;
  const intel = record(session.threat_intel);
  const findings = Array.isArray(intel.findings) ? intel.findings : [];
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-6">
    <section role="dialog" aria-modal="true" aria-labelledby="forensic-title" className="bg-surface border border-primary/30 max-w-6xl w-full max-h-[92vh] overflow-y-auto p-6 space-y-6">
      <div className="flex items-start justify-between gap-4"><div><h2 id="forensic-title" className="text-xl">Session evidence</h2><p className="text-xs text-gray-400 break-all">{session.session_id} · analysis: {session.analysis_id ?? 'Unknown / legacy record'}</p></div>
        <button aria-label="Close session evidence" onClick={onClose}><X /></button></div>
      <p className={statusColor(session.status)}>{session.status} · {session.score === null ? 'Unscored' : `Heuristic posture score ${session.score}/100`} · assessment: {session.assessment_status}</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <EvidenceValue label="Source → destination" value={`${session.src} → ${session.dst}`} />
        <EvidenceValue label="Application protocol" value={session.protocol} />
        <EvidenceValue label="Selected TLS version" value={tlsLabel(session)} />
        <EvidenceValue label="Selected cipher suite" value={session.cipher_suite} />
        <EvidenceValue label="Forward secrecy" value={`${triLabel(session.forward_secrecy.has_forward_secrecy)} — ${session.forward_secrecy.reason}`} />
        <EvidenceValue label="Certificate trust verified" value={triLabel(session.trust)} />
        <EvidenceValue label="Evidence coverage (backend assessment)" value={session.evidence_coverage} />
        <EvidenceValue label="Response receipt" value={session.mitigation ?? session.response} />
        <EvidenceValue label="Capture provenance" value={session.provenance ?? session.capture_hash ?? session.capture_sha256} />
      </div>
      <h3 className="text-primary">Analysis components</h3><ComponentHealth components={session.component_statuses} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <EvidenceValue label="Findings (observations, not proof of an attack)" value={session.risk_factors.length ? session.risk_factors : 'No findings supplied. This does not establish safety.'} />
        <EvidenceValue label="Recommendations" value={session.remediations.length ? session.remediations : null} />
        <EvidenceValue label="JA3 fingerprint" value={session.ja3} />
        <EvidenceValue label="Capture / ingestion times" value={{ start: session.start_time ?? null, end: session.end_time ?? null, ingested: session.timestamp ?? null }} />
      </div>
      <h3 className="text-primary">Flow measurements</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">{[
        ['Packets', session.packet_count], ['Bytes', session.total_bytes], ['Duration (s)', session.flow_duration],
        ['Mean inter-arrival time (s)', session.mean_iat], ['Payload entropy', session.payload_entropy],
        ['Indicator match observed', triLabel(triState(session.is_known_malicious))],
      ].map(([label, value]) => <EvidenceValue key={String(label)} label={String(label)} value={value} />)}</div>
      <p className="text-xs text-gray-400">High ciphertext entropy is expected for encrypted data; these measurements alone do not identify malware.</p>
      <h3 className="text-primary">Threat intelligence evidence</h3>
      <EvidenceValue label="Lookup status / coverage" value={intel.status ?? 'Not reported / unknown'} />
      {findings.length ? findings.map((finding, i) => <EvidenceValue key={i} label={`Indicator evidence ${i + 1}`} value={finding} />) :
        <p className="text-xs text-gray-400">No indicator findings supplied. Lookups may be unavailable, disabled, partial or have no match; this is not a clean verdict.</p>}
      <h3 className="text-primary">Extracted X.509 certificates ({session.certificates.length})</h3>
      {!session.certificates.length && <p className="text-xs text-gray-400">No certificates visible in this record. Missing capture data, resumption and encrypted TLS 1.3 handshakes can limit visibility.</p>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">{session.certificates.map((cert, i) => {
        const trust = record(cert.trust_validation);
        const verified = triState(trust.trusted ?? trust.is_trusted ?? cert.trusted);
        const severity = text(cert.severity, 'unknown');
        const color = cert.error || severity === 'error' || severity === 'critical' ? 'border-red-500/40 text-red-300' :
          severity === 'high' || severity === 'elevated' ? 'border-amber-500/40 text-amber-300' :
          verified === true ? 'border-green-500/40 text-green-300' : 'border-gray-500/40 text-gray-300';
        return <div key={i} className={`border p-4 text-xs space-y-2 ${color}`}>
          <h4>Certificate {i + 1} · {severity}</h4>
          <p>Subject: {display(cert.raw_subject ?? cert.subject)}</p><p>Issuer: {display(cert.raw_issuer ?? cert.issuer)}</p>
          <p>Trust verified: {triLabel(verified)}</p>
          <p>Self-issued: {triLabel(triState(cert.is_self_issued))} · Self-signature verified: {triLabel(triState(cert.is_self_signed))}</p>
          <p>Self-issued or self-signed status alone does not determine chain trust.</p>
          <details><summary className="cursor-pointer">Certificate evidence / errors</summary><pre className="whitespace-pre-wrap break-words mt-2">{display(cert)}</pre></details>
        </div>;
      })}</div>
      <EvidenceValue label="Scoped control observations (not a compliance certification)" value={session.compliance} />
      <details className="text-xs text-gray-400"><summary className="cursor-pointer">Full retained forensic record</summary><pre className="whitespace-pre-wrap break-words mt-3">{display(session)}</pre></details>
      <p className="text-xs text-gray-500">TShark-assisted stream metadata. Passive observations do not establish complete decryption, authenticated handshake completion, exploitation or actor identity.</p>
    </section>
  </div>;
}
