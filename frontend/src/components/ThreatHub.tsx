import { CyberCard } from './CyberCard';
import { ComponentHealth } from './Evidence';
import { tlsLabel, statusColor } from '../lib/sessions';
import type { Session } from '../lib/sessions';

export function ThreatHub({ sessions }: { sessions: Session[] }) {
  const distribution = new Map<string, number>();
  for (const s of sessions) { const label = tlsLabel(s); distribution.set(label, (distribution.get(label) ?? 0) + 1); }
  const findings = sessions.filter(s => s.risk_factors.length > 0);
  return <div className="space-y-8 animate-tech-drop">
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 tracking-tight">Posture Findings & Evidence Coverage</h2>
    
    <CyberCard trailColor="bg-cyan-500/50">
      <h3 className="text-xl font-bold text-slate-200 mb-6">Observed Encryption Distribution</h3>
      {!distribution.size && <div className="p-10 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-white/5">No records in this scope.</div>}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {[...distribution].map(([label, count]) => <div key={label} className="flex justify-between items-center bg-slate-900/40 hover:bg-slate-800/60 transition-colors border border-white/5 rounded-xl p-4">
          <span className="text-slate-300 font-medium">{label}</span>
          <span className="text-2xl font-black text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]">{count}</span>
        </div>)}
      </div>
    </CyberCard>
    
    <p className="text-sm text-slate-400 leading-relaxed border-l-2 border-cyan-500/30 pl-3">Cryptographic weaknesses and statistical anomalies are observations, not observed attacks. ATT&CK technique attribution requires additional evidence and is not inferred here.</p>
    
    <div className="space-y-6">
      {findings.map(s => <CyberCard key={s.session_id} trailColor="bg-purple-500/50">
        <h3 className="text-xl font-bold text-cyan-400 break-all">{s.session_id}</h3>
        <p className="text-xs text-slate-500 mb-5 mt-1">{s.src} → {s.dst} <span className="mx-2">•</span> <span className={`${statusColor(s.status).replace('text-', 'text-glow-')} font-bold uppercase tracking-widest`}>{s.status}</span> <span className="mx-2">•</span> Analysis: {s.analysis_id ?? 'unknown'}</p>
        
        <div className="bg-slate-900/40 rounded-xl p-5 border border-white/5 mb-6">
          <ul className="list-disc pl-5 text-sm text-slate-300 space-y-3 marker:text-cyan-500">{s.risk_factors.map((f, i) => <li key={i}>{f}</li>)}</ul>
        </div>
        
        <ComponentHealth components={s.component_statuses} />
      </CyberCard>)}
    </div>
    
    {!findings.length && <div className="p-10 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-white/5">No findings supplied for this scope. Check unknown assessments and component coverage before drawing conclusions.</div>}
  </div>;
}
