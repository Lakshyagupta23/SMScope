import { useState } from 'react';
import { X } from 'lucide-react';
import { apiFetch, errorMessage, getApiToken } from '../lib/api';
import { display, isVerifiedResponse, record, text } from '../lib/sessions';
import type { JsonRecord, Session } from '../lib/sessions';

export function RemediationModal({ onClose, sessions }: { onClose: () => void; sessions: Session[] }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<JsonRecord | null>(null);
  const [error, setError] = useState('');
  const analyses = [...new Set(sessions.map(s => s.analysis_id))];
  const analysisId = analyses.length === 1 ? analyses[0] : null;
  const endpoints = [...new Set(sessions.flatMap(s => [s.src, s.dst]))].filter(ip => ip !== 'Unknown');
  const deploy = async () => {
    if (!analysisId || !selected.length || busy) return;
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await apiFetch('/api/soar/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips: selected, analysis_id: analysisId, confirm: true, scope: 'host_input' }) });
      const data = record(await response.json());
      setResult(data);
      // The per-IP result and analysis scope are required; requested addresses are never receipts.
      window.dispatchEvent(new CustomEvent('response-result', { detail: { ...data, analysis_id: data.analysis_id ?? analysisId } }));
    } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };
  return <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6">
    <section role="dialog" aria-modal="true" aria-labelledby="response-title" className="bg-surface border border-primary/30 p-6 w-full max-w-3xl max-h-[90vh] overflow-y-auto space-y-5">
      <div className="flex justify-between"><h2 id="response-title" className="text-xl">Explicit endpoint response</h2><button aria-label="Close response" disabled={busy} onClick={onClose}><X /></button></div>
      <p className="text-sm text-gray-400">Choose specific endpoints for a backend-host firewall response. A weak cryptographic posture is not proof that an endpoint is malicious. Historical capture addresses may not identify the current host. Backend-host rules do not establish protection of remote infrastructure.</p>
      <p className="text-xs text-primary break-all">Analysis scope: {analysisId ?? 'Select a single analysis with provenance before responding.'}</p>
      {!getApiToken() && <p className="text-amber-400 text-sm">Configure an API token in System Config to use response operations.</p>}
      <div className="grid grid-cols-2 gap-3">{endpoints.map(ip => <label key={ip} className="text-xs border border-primary/20 p-3 break-all"><input type="checkbox" disabled={busy} checked={selected.includes(ip)} onChange={e => setSelected(previous => e.target.checked ? [...previous, ip] : previous.filter(v => v !== ip))} className="mr-2" />{ip}</label>)}</div>
      <button disabled={!analysisId || !getApiToken() || !selected.length || busy} onClick={() => void deploy()} className="border border-red-500/40 text-red-400 p-3 disabled:opacity-40">{busy ? 'Awaiting response receipts…' : `Submit response for ${selected.length} selected endpoints`}</button>
      {error && <p role="alert" className="text-red-400 text-sm">{error}</p>}
      {result && <div className="space-y-3"><p className="text-sm">Backend outcome: {text(result.status)} · {text(result.message, '')}</p>
        {Object.entries(record(result.ips_results)).map(([ip, receipt]) => <div key={ip} className={`border p-3 text-xs ${isVerifiedResponse(receipt) ? 'border-blue-400 text-blue-300' : 'border-gray-600 text-gray-300'}`}><p>{ip}: {isVerifiedResponse(receipt) ? 'Verified enforcement receipt' : 'No verified mitigation'}</p><pre className="whitespace-pre-wrap break-words mt-2">{display(receipt)}</pre></div>)}
        {!Object.keys(record(result.ips_results)).length && <p className="text-amber-400 text-sm">No per-endpoint receipts returned. No sessions were marked mitigated.</p>}
      </div>}
      <p className="text-xs text-gray-400">Failed, logged-only, dry-run and unverified execution outcomes retain the original finding state. Response does not change the captured posture score.</p>
    </section>
  </div>;
}
