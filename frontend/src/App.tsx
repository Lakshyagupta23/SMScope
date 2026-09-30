import { useEffect, useMemo, useState } from 'react';
import { Activity, Database, Globe, HardDrive, Network, Settings, ShieldAlert, TerminalSquare } from 'lucide-react';
import { WS_STREAM } from './config';
import { apiFetch, errorMessage, getApiToken } from './lib/api';
import { aggregateSessions, applyResponse, mergeSessions, record, sessionArray, text } from './lib/sessions';
import type { Session } from './lib/sessions';
import { TargetMatrix } from './components/TargetMatrix';
import { ThreatTopology } from './components/ThreatTopology';
import { GlobalMap } from './components/GlobalMap';
import { PCAPIngest } from './components/PCAPIngest';
import { ThreatHub } from './components/ThreatHub';
import { SystemConfig } from './components/SystemConfig';
import { DatabaseBrowser } from './components/DatabaseBrowser';
import { ErrorBoundary } from './components/ErrorBoundary';

const tabs = [
  ['target_matrix', 'Session Matrix', Activity], ['topology', 'Illustrative Topology', Network],
  ['global_map', 'Location Coverage', Globe], ['database_browser', 'Forensic Records', Database],
  ['pcap_ingest', 'PCAP Ingest', HardDrive], ['threat_hub', 'Findings', ShieldAlert],
  ['system_config', 'System Config', Settings],
] as const;

export default function App() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeTab, setActiveTab] = useState('target_matrix');
  const [analysisId, setAnalysisId] = useState('');
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const refresh = () => { setError(''); setRevision(n => n + 1); };
    const flushed = () => { setSessions([]); setAnalysisId(''); refresh(); };
    const authError = (e: Event) => setError(String((e as CustomEvent).detail));
    const response = (e: Event) => setSessions(s => applyResponse(s, (e as CustomEvent).detail));
    window.addEventListener('api-token-changed', refresh);
    window.addEventListener('analysis-complete', refresh);
    window.addEventListener('db-flushed', flushed);
    window.addEventListener('api-auth-error', authError);
    window.addEventListener('response-result', response);
    return () => {
      window.removeEventListener('api-token-changed', refresh);
      window.removeEventListener('analysis-complete', refresh);
      window.removeEventListener('db-flushed', flushed);
      window.removeEventListener('api-auth-error', authError);
      window.removeEventListener('response-result', response);
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const loadHistory = async () => {
      try {
        const response = await apiFetch('/api/sessions/history?limit=1000', { signal: controller.signal });
        const data: unknown = await response.json();
        if (!disposed) setSessions(previous => mergeSessions(previous, sessionArray(data)));
      } catch (e) { if (!disposed) setError(errorMessage(e)); }
    };
    const connect = () => {
      if (disposed) return;
      ws = new WebSocket(WS_STREAM);
      ws.onopen = () => {
        ws?.send(JSON.stringify({ type: 'authenticate', token: getApiToken() }));
        // Socket transport is open; authentication is confirmed only by the server.
      };
      ws.onmessage = event => {
        try {
          const data = record(JSON.parse(event.data));
          if (data.type === 'error' || data.type === 'auth_error') {
            setError(text(data.message, text(data.detail, 'WebSocket authorization or stream error. Check System Config.')));
            return;
          }
          if (data.type === 'authenticated' || data.type === 'auth_ok') { setConnected(true); return; }
          if (data.type === 'bulk_mitigate' || data.type === 'response_result' || data.type === 'response_outcomes') {
            setSessions(previous => applyResponse(previous, data));
            return;
          }
          const incoming = data.type === 'session' ? record(data.session ?? data.data) : data;
          if (incoming.session_id || incoming.src_ip || incoming.src) {
            setConnected(true);
            setSessions(previous => mergeSessions(previous, [incoming]));
          } else if (Array.isArray(data.sessions)) {
            setConnected(true);
            setSessions(previous => mergeSessions(previous, data.sessions as unknown[]));
          }
        } catch { setError('Received an invalid stream message; existing records were retained.'); }
      };
      ws.onclose = event => {
        setConnected(false);
        if ([1008, 4401, 4403].includes(event.code)) {
          setError('WebSocket authorization denied. Update the API token in System Config.');
          return;
        }
        if (!disposed) timer = setTimeout(() => { void loadHistory(); connect(); }, 3000);
      };
      ws.onerror = () => setConnected(false);
    };
    void loadHistory();
    connect();
    return () => {
      disposed = true;
      controller.abort();
      clearTimeout(timer);
      if (ws) { ws.onclose = null; ws.close(); }
    };
  }, [revision]);

  const analysisIds = useMemo(() => [...new Set(sessions.map(s => s.analysis_id).filter((s): s is string => !!s))], [sessions]);
  const selected = useMemo(() => analysisId ? sessions.filter(s => s.analysis_id === analysisId) : sessions, [sessions, analysisId]);
  const stats = useMemo(() => aggregateSessions(selected), [selected]);
  const content = () => {
    switch (activeTab) {
      case 'topology': return <ThreatTopology sessions={selected} />;
      case 'global_map': return <GlobalMap sessions={selected} />;
      case 'database_browser': return <DatabaseBrowser sessions={selected} />;
      case 'pcap_ingest': return <PCAPIngest onAnalysis={id => setAnalysisId(id)} />;
      case 'threat_hub': return <ThreatHub sessions={selected} />;
      case 'system_config': return <SystemConfig analysisId={analysisId} />;
      default: return <TargetMatrix stats={stats} sessions={selected} />;
    }
  };

  return <div className="min-h-screen bg-background text-white flex font-sans selection:bg-cyan-500/30">
    <aside className="w-64 shrink-0 border-r border-white/5 bg-slate-900/40 backdrop-blur-xl p-6 flex flex-col gap-6 shadow-2xl z-10">
      <h1 className="flex items-center gap-3 text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 py-3 tracking-tight"><TerminalSquare className="text-cyan-400" />SMScope</h1>
      <p className="text-xs text-slate-400 font-medium tracking-wide uppercase">Cryptographic Posture</p>
      <nav className="space-y-1 mt-4">{tabs.map(([id, label, Icon]) => <button key={id} onClick={() => setActiveTab(id)}
        className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left text-sm font-medium transition-all duration-300 ${activeTab === id ? 'bg-gradient-to-r from-cyan-500/20 to-purple-500/10 text-cyan-300 shadow-[inset_0_1px_1px_rgba(255,255,255,0.1)] border border-white/5' : 'border border-transparent text-slate-400 hover:text-slate-200 hover:bg-white/5'}`}>
        <Icon className={`w-5 h-5 ${activeTab === id ? 'text-cyan-400' : 'text-slate-500'}`} />{label}
      </button>)}</nav>
    </aside>
    <main className="flex-1 min-w-0 flex flex-col relative z-0">
      <header className="border-b border-white/5 bg-slate-900/20 backdrop-blur-md p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <label className="text-sm font-medium text-slate-300 flex items-center gap-3">Dataset Scope <select aria-label="Analysis scope" value={analysisId} onChange={e => setAnalysisId(e.target.value)} className="bg-slate-800/50 border border-white/10 rounded-md p-2.5 text-white max-w-md focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-shadow">
            <option value="">All loaded records</option>{analysisId && !analysisIds.includes(analysisId) && <option value={analysisId}>{analysisId} (no loaded sessions)</option>}{analysisIds.map(id => <option key={id} value={id}>{id}</option>)}
          </select></label>
          <span className="px-3 py-1 rounded-full text-xs font-medium border bg-slate-900/50 flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-rose-500 shadow-[0_0_8px_rgba(225,29,72,0.8)]'}`}></span>
            {connected ? 'Stream Connected' : 'Disconnected'}
          </span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-4xl">{stats.total} unique loaded sessions · {stats.scored} scored · {stats.unscored} unscored · {stats.unknown} unknown assessments. History limited to API response (up to 1,000) plus received stream records.</p>
        {error && <div role="alert" className="text-sm text-rose-400 bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg flex items-center justify-between">{error} <button className="underline font-medium hover:text-rose-300 transition-colors" onClick={() => setActiveTab('system_config')}>Open Settings</button></div>}
      </header>
      <div className="p-8 overflow-y-auto flex-1"><ErrorBoundary>{content()}</ErrorBoundary></div>
    </main>
  </div>;
}
