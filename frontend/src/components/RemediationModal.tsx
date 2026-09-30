import { useState } from 'react';
import { X, ShieldAlert, CheckSquare, Square } from 'lucide-react';
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
  const allSelected = endpoints.length > 0 && selected.length === endpoints.length;

  const toggleAll = () => setSelected(allSelected ? [] : [...endpoints]);

  const deploy = async () => {
    if (!analysisId || !selected.length || busy) return;
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await apiFetch('/api/soar/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips: selected, analysis_id: analysisId, confirm: true, scope: 'host_input' }) });
      const data = record(await response.json());
      setResult(data);
      window.dispatchEvent(new CustomEvent('response-result', { detail: { ...data, analysis_id: data.analysis_id ?? analysisId } }));
    } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="response-title"
        className="bg-slate-900 border border-cyan-500/30 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl"
      >
        {/* ── Sticky header - always visible ── */}
        <div className="flex items-center justify-between p-5 border-b border-white/10 shrink-0">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-amber-400 w-5 h-5" />
            <h2 id="response-title" className="text-lg font-bold text-white">Review Targets</h2>
          </div>
          <button
            aria-label="Close"
            disabled={busy}
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-40"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ── Scrollable body ── */}
        <div className="overflow-y-auto flex-1 p-5 space-y-5">

          {/* Purpose explanation */}
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 space-y-2">
            <p className="text-amber-300 text-sm font-semibold">What does this do?</p>
            <p className="text-slate-300 text-sm leading-relaxed">
              This sends a <strong>dry-run firewall block command</strong> to the backend for each selected IP address.
              On this prototype it logs the intent and validates the target — <strong>no actual firewall rule is applied</strong>.
              In a production deployment this would issue an OS-level firewall rule (e.g. <code>iptables</code>) to block the flagged endpoint.
            </p>
            <p className="text-xs text-amber-400">
              ⚠ A weak cryptographic posture is not proof of malicious intent. Response does not change the captured posture score.
            </p>
          </div>

          <p className="text-xs text-cyan-400 break-all">
            Analysis scope: {analysisId ?? 'Select a single analysis with provenance before responding.'}
          </p>

          {!getApiToken() && (
            <p className="text-amber-400 text-sm bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
              Configure an API token in System Config to use response operations.
            </p>
          )}

          {/* Select All toggle */}
          {endpoints.length > 0 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-300 font-medium">{endpoints.length} endpoint{endpoints.length !== 1 ? 's' : ''} detected</p>
              <button
                disabled={busy}
                onClick={toggleAll}
                className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 transition-colors disabled:opacity-40"
              >
                {allSelected ? <CheckSquare className="w-3.5 h-3.5" /> : <Square className="w-3.5 h-3.5" />}
                {allSelected ? 'Deselect All' : 'Select All'}
              </button>
            </div>
          )}

          {/* Endpoint checkboxes */}
          <div className="grid grid-cols-2 gap-2">
            {endpoints.map(ip => (
              <label
                key={ip}
                className={`flex items-center gap-2 text-xs border rounded-lg p-3 cursor-pointer transition-colors break-all
                  ${selected.includes(ip)
                    ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300'
                    : 'border-white/10 text-slate-400 hover:border-white/30 hover:text-slate-300'}`}
              >
                <input
                  type="checkbox"
                  disabled={busy}
                  checked={selected.includes(ip)}
                  onChange={e => setSelected(previous => e.target.checked ? [...previous, ip] : previous.filter(v => v !== ip))}
                  className="accent-cyan-500"
                />
                {ip}
              </label>
            ))}
          </div>

          {/* Submit button */}
          <button
            disabled={!analysisId || !getApiToken() || !selected.length || busy}
            onClick={() => void deploy()}
            className="w-full border border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20 px-4 py-3 rounded-lg font-medium text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? 'Awaiting response receipts…' : `Submit dry-run response for ${selected.length} selected endpoint${selected.length !== 1 ? 's' : ''}`}
          </button>

          {error && <p role="alert" className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

          {/* Results */}
          {result && (
            <div className="space-y-3">
              <p className="text-sm font-medium text-slate-300">Backend outcome: <span className="text-cyan-400">{text(result.status)}</span> · {text(result.message, '')}</p>
              {Object.entries(record(result.ips_results)).map(([ip, receipt]) => (
                <div key={ip} className={`border rounded-lg p-3 text-xs ${isVerifiedResponse(receipt) ? 'border-blue-400/50 bg-blue-500/10 text-blue-300' : 'border-white/10 text-slate-400'}`}>
                  <p className="font-medium mb-2">{ip}: {isVerifiedResponse(receipt) ? '✓ Verified enforcement receipt' : '⚠ No verified mitigation (dry-run)'}</p>
                  <pre className="whitespace-pre-wrap break-words text-[10px] opacity-80">{display(receipt)}</pre>
                </div>
              ))}
              {!Object.keys(record(result.ips_results)).length && (
                <p className="text-amber-400 text-sm">No per-endpoint receipts returned. No sessions were marked mitigated.</p>
              )}
            </div>
          )}

          <p className="text-xs text-slate-500 border-t border-white/10 pt-4">
            Failed, logged-only, dry-run and unverified execution outcomes retain the original finding state.
          </p>
        </div>
      </section>
    </div>
  );
}
