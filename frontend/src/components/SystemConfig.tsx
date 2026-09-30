import { useEffect, useState } from 'react';
import { BACKEND_URL } from '../config';
import { apiFetch, errorMessage, getApiToken, setApiToken } from '../lib/api';
import { record, text } from '../lib/sessions';
import type { JsonRecord } from '../lib/sessions';
import { CyberCard } from './CyberCard';
import { ComponentHealth, EvidenceValue } from './Evidence';
import { ReportDownloads } from './ReportDownloads';

export function SystemConfig({ analysisId }: { analysisId: string }) {
  const [token, setToken] = useState(getApiToken);
  const [health, setHealth] = useState<JsonRecord | null>(null);
  const [healthError, setHealthError] = useState('');
  const [message, setMessage] = useState('');
  const [flushing, setFlushing] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let disposed = false;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await apiFetch('/api/health', { signal: controller.signal });
        const data = record(await response.json());
        if (!disposed) { setHealth(data); setHealthError(''); }
      } catch (e) { if (!disposed) { setHealth(null); setHealthError(errorMessage(e)); } }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => { disposed = true; controller.abort(); clearInterval(timer); };
  }, [revision]);
  const flush = async () => {
    setFlushing(true); setMessage('');
    try {
      const response = await apiFetch('/api/sessions/flush', { method: 'DELETE' });
      const data = record(await response.json());
      if (!['success', 'flushed'].includes(text(data.status, ''))) throw new Error(`Flush not confirmed: ${text(data.message, text(data.status))}`);
      window.dispatchEvent(new Event('db-flushed'));
      setMessage('Backend confirmed database flush.');
    } catch (e) { setMessage(errorMessage(e)); }
    finally { setFlushing(false); }
  };
  return <div className="space-y-8 animate-tech-drop">
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 tracking-tight">System Configuration</h2>
    
    <CyberCard className="space-y-5" trailColor="bg-cyan-500/50">
      <h3 className="text-xl font-bold text-slate-200">API Authentication</h3>
      <p className="text-sm text-slate-400">Backend: <span className="font-mono text-cyan-400">{BACKEND_URL}</span></p>
      <form onSubmit={e => { e.preventDefault(); setApiToken(token); setMessage('Token saved for this browser tab; reconnecting.'); setRevision(n => n + 1); }} className="space-y-4 max-w-2xl">
        <label className="block text-sm font-medium text-slate-300">API token
          <input type="password" autoComplete="off" spellCheck={false} value={token} onChange={e => setToken(e.target.value)} 
          className="block mt-2 w-full bg-slate-900/60 border border-white/10 rounded-lg p-3 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all placeholder:text-slate-600 shadow-inner" placeholder="Enter API Token..." />
        </label>
        <button type="submit" className="cybr-btn">Save Token & Reconnect<span className="cybr-btn__glitch">Save Token & Reconnect</span><span className="cybr-btn__tag">AUTH</span></button>
      </form>
      <p className="text-xs text-slate-500 leading-relaxed border-l-2 border-cyan-500/30 pl-3">Stored only in sessionStorage for this tab, OR globally bypassed by setting <strong>VITE_API_TOKEN</strong> in Vercel environment variables. Configure SECUREMAILSCOPE_API_TOKEN on the backend. Without a configured backend token, only permitted loopback passive analysis is available. Capture, response and flush require a configured token.</p>
    </CyberCard>
    
    {message && <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg"><p role="status" className="text-emerald-400 text-sm font-medium">{message}</p></div>}
    
    <CyberCard className="space-y-5" trailColor="bg-purple-500/50">
      <h3 className="text-xl font-bold text-slate-200">Backend Health & Capabilities</h3>
      {healthError && <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg"><p role="alert" className="text-amber-400 text-sm font-medium">{healthError} Health is unavailable.</p></div>}
      
      <div className="bg-slate-900/40 rounded-xl p-5 border border-white/5">
        <ComponentHealth components={health?.components ?? health?.component_statuses ?? { ml: health?.ml, cti: health?.cti, yara: health?.yara }} />
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <EvidenceValue label="Service status" value={health?.status} />
        <EvidenceValue label="Response dry-run setting" value={health?.ips_dry_run} />
        <EvidenceValue label="Parser" value={health?.parser ?? record(health?.components).parser} />
        <EvidenceValue label="Capture lifecycle" value={health?.capture ?? health?.capture_status} />
        <EvidenceValue label="Bulk ingestion / configured paths" value={health?.ingestion ?? health?.watchdog ?? health?.paths ?? { status: health?.bulk_ingest ?? null, ingress_path: health?.ingress_path ?? null, file_contract: health?.bulk_file_contract ?? null }} />
        <EvidenceValue label="Database" value={health?.database ?? record(health?.components).database} />
      </div>
      <p className="text-xs text-slate-500 leading-relaxed">Health is the backend's reported state. Configured dry-run/enforcement mode does not establish that a firewall rule was applied. Passive analysis detects observed weaknesses; it does not block cipher negotiation.</p>
      
      <details className="bg-slate-900/40 rounded-xl border border-white/5 group overflow-hidden">
        <summary className="text-sm cursor-pointer p-4 font-medium text-cyan-400 hover:bg-white/[0.02] transition-colors list-none flex items-center justify-between">
          Full health response
          <span className="text-slate-600 group-open:rotate-180 transition-transform">▼</span>
        </summary>
        <div className="p-4 pt-0 border-t border-white/5 mt-2">
          <EvidenceValue label="API health receipt" value={health} />
        </div>
      </details>
    </CyberCard>
    
    <CyberCard className="space-y-4" trailColor="bg-cyan-500/50">
      <h3 className="text-xl font-bold text-slate-200">Scoped Report Downloads</h3>
      <div className="bg-slate-900/40 rounded-xl p-5 border border-white/5">
        <ReportDownloads analysisId={analysisId} />
      </div>
    </CyberCard>
    
    <CyberCard className="space-y-4 border-rose-500/20" trailColor="bg-rose-500/50">
      <h3 className="text-xl font-bold text-rose-400">Clear Storage</h3>
      <p className="text-sm text-slate-400 mb-4">This deletes backend session records across analyses, not just the selected dataset.</p>
      <button onClick={() => void flush()} disabled={flushing || !getApiToken()} className="px-6 py-3 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 font-bold rounded-lg uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed w-full sm:w-auto">
        {flushing ? 'Awaiting flush response…' : 'Flush Database'}
      </button>
    </CyberCard>
  </div>;
}
