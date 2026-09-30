import { CyberCard } from './CyberCard';
import { statusColor } from '../lib/sessions';
import type { Session } from '../lib/sessions';

export function ThreatTopology({ sessions }: { sessions: Session[] }) {
  return <CyberCard className="space-y-6 animate-tech-drop" trailColor="bg-cyan-500/50">
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 tracking-tight">Illustrative Session Topology</h2>
    <p className="text-sm text-slate-400 leading-relaxed">Observed endpoint pairs in record order. Layout does not encode geographic position, network routing, distance or timing.</p>
    
    {!sessions.length && <div className="p-10 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-white/5">No session endpoints loaded.</div>}
    
    <div className="grid grid-cols-1 gap-4 mt-6">
      {sessions.map(s => <div key={s.session_id} className="flex flex-col sm:flex-row flex-wrap items-center justify-between gap-4 border border-white/10 bg-slate-900/40 hover:bg-slate-800/60 transition-colors p-5 rounded-xl text-sm shadow-[0_4px_20px_rgba(0,0,0,0.2)]">
        <div className="flex items-center gap-4 w-full sm:w-auto flex-1 justify-between sm:justify-start">
          <span className="font-mono text-cyan-300 break-all">{s.src}</span>
          <div className="flex flex-col items-center px-4">
            <span className={`text-[10px] uppercase font-bold tracking-widest ${statusColor(s.status).replace('text-', 'text-glow-')}`}>{s.status}</span>
            <span className="text-slate-500 text-xs mt-1">→ {s.protocol} →</span>
          </div>
          <span className="font-mono text-purple-400 break-all">{s.dst}</span>
        </div>
        <div className="w-full sm:w-auto text-xs text-slate-500 break-all text-right mt-2 sm:mt-0">
          ID: {s.session_id}
        </div>
      </div>)}
    </div>
  </CyberCard>;
}
