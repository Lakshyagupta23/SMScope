import { useState } from 'react';
import { CyberCard } from './CyberCard';
import { EvidenceValue } from './Evidence';
import { ReportDownloads } from './ReportDownloads';
import { apiFetch, errorMessage } from '../lib/api';
import { aggregateSessions, mergeSessions, record, sessionArray, text } from '../lib/sessions';
import type { JsonRecord } from '../lib/sessions';

export function PCAPIngest({ onAnalysis }: { onAnalysis: (id: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [result, setResult] = useState<JsonRecord | null>(null);
  const [error, setError] = useState('');
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const run = async (file?: File) => {
    if (busy) return;
    if (file && !/\.pcap(ng)?$/i.test(file.name)) { setError('Select a .pcap or .pcapng capture.'); return; }
    setBusy(true); setError(''); setResult(null); setAnalysisId(null);
    setName(file?.name ?? 'Synthetic demo fixture (mixed scenarios)');
    const form = new FormData();
    if (file) form.append('file', file);
    try {
      const response = await apiFetch(file ? '/api/pcap/upload' : '/api/pcap/demo', { method: 'POST', ...(file ? { body: form } : {}) });
      const data = record(await response.json());
      setResult(data);
      if (data.status !== 'success' && data.status !== 'no_sessions') {
        setError(`${text(data.status, 'Analysis failed')}: ${text(data.message, 'See backend result below.')}`);
      }
      const id = text(data.analysis_id, '');
      if (id) { setAnalysisId(id); onAnalysis(id); }
      window.dispatchEvent(new Event('analysis-complete'));
    } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };
  const sessions = mergeSessions([], sessionArray(result));
  const stats = aggregateSessions(sessions);
  return <div className="space-y-8 animate-tech-drop">
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 tracking-tight">PCAP Ingestion Gateway</h2>
    
    <CyberCard className="space-y-6" trailColor="bg-cyan-500/50">
      <p className="text-sm text-slate-400 leading-relaxed">Upload a capture for passive analysis. Missing handshakes, encrypted certificates and incomplete flows remain explicitly unassessed.</p>
      
      <label className="block border-2 border-dashed border-cyan-500/30 bg-cyan-950/20 hover:bg-cyan-900/30 transition-colors rounded-xl p-10 text-center cursor-pointer group">
        <span className="block text-cyan-400 font-semibold mb-2 group-hover:text-cyan-300 transition-colors drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]">Select PCAP / PCAPNG</span>
        <span className="block text-xs text-slate-500 mb-6">Drop your packet capture file here or click to browse</span>
        <input className="hidden" aria-label="Upload packet capture" type="file" accept=".pcap,.pcapng" disabled={busy} onChange={e => { const f = e.target.files?.[0]; if (f) void run(f); e.target.value = ''; }} />
      </label>
      
      <div className="flex flex-col items-start gap-4 mt-6">
        <button disabled={busy} onClick={() => void run()} className="cybr-btn disabled:opacity-40 w-full sm:w-auto">
          Run Demo Payload<span className="cybr-btn__glitch">Run Demo Payload</span><span className="cybr-btn__tag">TEST</span>
        </button>
        <p className="text-xs text-slate-500">The demo contains synthetic test traffic. It is not a known-benign baseline, authentic enterprise capture or model accuracy evaluation.</p>
      </div>
      
      {busy && <div className="flex items-center gap-3 mt-6 p-4 bg-cyan-900/20 border border-cyan-500/30 rounded-lg">
        <div className="w-4 h-4 rounded-full bg-cyan-400 animate-ping"></div>
        <p role="status" className="text-cyan-400 text-sm font-medium">Processing capture {name}... Backend stage telemetry unavailable.</p>
      </div>}
      
      {error && <div className="mt-4 p-4 bg-rose-500/10 border border-rose-500/30 rounded-lg">
        <p role="alert" className="text-rose-400 text-sm font-medium">{error}</p>
      </div>}
      
      {result && <div className="space-y-6 mt-8 pt-6 border-t border-white/5">
        <h3 className="text-xl font-bold text-slate-200">Analysis Results</h3>
        <p className="text-sm text-slate-300"><span className="text-cyan-400 font-medium">Outcome:</span> {text(result.status)} <span className="text-slate-500 mx-2">|</span> {name}</p>
        
        {result.status === 'no_sessions' && <p className="text-amber-400 bg-amber-400/10 border border-amber-400/20 p-4 rounded-lg text-sm">No email sessions reported for this capture. This does not establish a secure posture.</p>}
        {sessions.length > 0 && <p className="text-sm text-slate-300 bg-slate-800/50 p-4 rounded-lg border border-white/5">{stats.total} unique sessions · mean score <span className="text-cyan-400 font-bold">{stats.score === null ? 'unknown' : stats.score.toFixed(1)}</span> · {stats.scored} scored / {stats.unscored} unscored · {stats.unknown} unknown assessments.</p>}
        
        <div className="bg-slate-900/60 rounded-lg p-4 border border-white/5">
          <EvidenceValue label="Backend analysis receipt" value={Object.fromEntries(Object.entries(result).filter(([key]) => key !== 'sessions' && key !== 'results'))} />
        </div>
        <ReportDownloads analysisId={analysisId} />
      </div>}
    </CyberCard>
    
    <CyberCard className="space-y-4" trailColor="bg-purple-500/50"><h3 className="text-xl font-bold text-slate-200">Live Capture & Integration</h3>
      <button disabled className="border border-slate-700 bg-slate-800/50 text-slate-500 px-6 py-3 rounded-lg text-sm font-medium cursor-not-allowed">Live capture control unavailable in this client</button>
      <div className="space-y-2 mt-4">
        <p className="text-sm text-slate-400 leading-relaxed">Use PCAP uploads here. This client does not manage capture interfaces or verify capture lifecycle. Backend capture, response and database-flush operations require a configured API token.</p>
        <p className="text-sm text-slate-400 leading-relaxed">Actual capture, parser and ingestion-path status is shown from the health API in System Config when supplied.</p>
      </div>
    </CyberCard>
  </div>;
}
