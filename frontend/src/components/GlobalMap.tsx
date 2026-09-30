import { CyberCard } from './CyberCard';
import type { Session } from '../lib/sessions';

/** Offline by default: endpoint addresses are never sent to public GeoIP services. */
export function GlobalMap({ sessions }: { sessions: Session[] }) {
  const endpoints = [...new Set(sessions.flatMap(s => [s.src, s.dst]))];
  const findingCount = sessions.filter(s => ['elevated', 'high', 'critical'].includes(s.status)).length;
  return <CyberCard className="space-y-6 animate-tech-drop" trailColor="bg-rose-500/50">
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-rose-400 to-orange-500 tracking-tight">Location Coverage</h2>
    
    <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
      <p className="text-amber-400 text-sm font-medium">Enrichment Disabled</p>
      <p className="text-sm text-slate-400 mt-2">No approved offline geolocation source is configured in this client. No external IP lookup or map-asset requests are made. Endpoint locations, including destinations, are unknown.</p>
    </div>
    
    <div className="bg-slate-900/40 rounded-xl p-5 border border-white/5 space-y-2">
      <p className="text-sm text-slate-300"><span className="text-cyan-400 font-bold">{sessions.length}</span> selected sessions</p>
      <p className="text-sm text-slate-300"><span className="text-rose-400 font-bold">{findingCount}</span> sessions with posture findings</p>
      <p className="text-sm text-slate-300"><span className="text-purple-400 font-bold">{endpoints.length}</span> distinct endpoint labels</p>
    </div>
    
    <p className="text-sm text-slate-500 leading-relaxed border-l-2 border-rose-500/30 pl-3">Unavailable location data says nothing about whether findings exist. Review Session Matrix for forensic evidence.</p>
    
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 mt-6">
      {endpoints.map(ip => <div key={ip} className="border border-white/5 bg-slate-900/60 hover:bg-slate-800/60 transition-colors p-4 rounded-xl text-xs font-mono break-all shadow-[0_4px_20px_rgba(0,0,0,0.1)]">
        <span className="text-cyan-300 block mb-2">{ip}</span>
        <span className="inline-block px-2 py-1 rounded bg-slate-800 text-slate-500 text-[10px] uppercase tracking-wider font-bold">Location unavailable</span>
      </div>)}
    </div>
  </CyberCard>;
}
