import { useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { CyberCard } from './CyberCard';
import { ForensicModal } from './ForensicModal';
import { RemediationModal } from './RemediationModal';
import { statusColor, tlsLabel } from '../lib/sessions';
import type { Session, SessionStats } from '../lib/sessions';

export function TargetMatrix({ stats, sessions }: { stats: SessionStats; sessions: Session[] }) {
  const [selected, setSelected] = useState<Session | null>(null);
  const [responseOpen, setResponseOpen] = useState(false);
  return <div className="space-y-8 animate-tech-drop">
    <ForensicModal session={selected} onClose={() => setSelected(null)} />
    {responseOpen && <RemediationModal sessions={sessions} onClose={() => setResponseOpen(false)} />}
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <CyberCard trailColor="bg-cyan-500/50"><h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Mean heuristic posture score</h2>
        <p className="text-5xl font-black my-4 text-transparent bg-clip-text bg-gradient-to-br from-cyan-300 to-cyan-600 drop-shadow-[0_0_10px_rgba(6,182,212,0.3)]">{stats.score === null ? 'Unknown' : `${stats.score.toFixed(1)} / 100`}</p>
        <p className="text-xs text-slate-500 leading-relaxed">Arithmetic mean of {stats.scored} scored sessions in the selected dataset. {stats.unscored} unscored. This is not attack probability or compliance certification.</p></CyberCard>
      
      <CyberCard trailColor="bg-purple-500/50"><h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Unresolved posture findings</h2>
        <p className="text-5xl font-black my-4 text-transparent bg-clip-text bg-gradient-to-br from-rose-400 to-purple-600 drop-shadow-[0_0_10px_rgba(244,63,94,0.3)]">{stats.breaches}</p>
        <p className="text-xs text-slate-500 leading-relaxed">Elevated, high and critical sessions; {stats.resolvedBreaches} with verified response receipts. A response does not change historical scores. {stats.unknown} assessments unknown.</p></CyberCard>
      
      <CyberCard trailColor="bg-emerald-500/50"><h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Observed legacy TLS / SSL</h2>
        <p className="text-5xl font-black my-4 text-transparent bg-clip-text bg-gradient-to-br from-emerald-300 to-teal-600 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">{stats.legacyPercent === null ? 'Unknown' : `${stats.legacyPercent.toFixed(1)}%`}</p>
        <p className="text-xs text-slate-500 leading-relaxed">{stats.legacy} of {stats.knownTls} sessions with observed TLS versions. {stats.total - stats.knownTls} lack a selected TLS version; absence is not plaintext evidence.</p></CyberCard>
    </div>
    
    <CyberCard><h2 className="mb-6 text-lg font-bold text-slate-200">Session Posture Trend</h2>
      <div className="h-64"><ResponsiveContainer width="100%" height="100%">
      <AreaChart data={sessions.map(s => ({ name: s.session_id, score: s.score }))}>
        <defs>
          <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
        <XAxis dataKey="name" hide />
        <YAxis domain={[0, 100]} stroke="rgba(255,255,255,0.2)" tick={{fill: '#94a3b8', fontSize: 12}} />
        <Tooltip contentStyle={{backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(6,182,212,0.3)', borderRadius: '8px', backdropFilter: 'blur(8px)'}} />
        <Area type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} fill="url(#scoreGradient)" connectNulls={false} />
      </AreaChart>
    </ResponsiveContainer></div><p className="text-xs text-slate-500 mt-4">Missing scores are gaps; record order is not a measured rate or timeline.</p></CyberCard>
    
    <div className="flex justify-between items-center gap-4 mt-8"><h2 className="text-2xl font-bold tracking-tight text-white">Session Evidence Log</h2>
      <button className="cybr-btn" onClick={() => setResponseOpen(true)}>
        Review Targets<span className="cybr-btn__glitch">Review Targets</span><span className="cybr-btn__tag">SOAR</span>
      </button>
    </div>
    <SessionTable sessions={sessions} onSelect={setSelected} />
  </div>;
}

export function SessionTable({ sessions, onSelect }: { sessions: Session[]; onSelect: (s: Session) => void }) {
  return <CyberCard className="!p-0 overflow-x-auto"><table className="w-full text-left text-sm whitespace-nowrap">
    <thead className="bg-slate-900/60 text-slate-400 font-semibold border-b border-white/10 uppercase tracking-wider text-xs">
      <tr>{['Session / analysis', 'Endpoints', 'Protocol / TLS', 'Posture', 'Evidence'].map(label => <th key={label} className="p-5">{label}</th>)}</tr>
    </thead>
    <tbody>{sessions.length === 0 && <tr><td colSpan={5} className="p-10 text-center text-slate-500">No records loaded in this scope. Security posture is unknown.</td></tr>}
      {sessions.map(s => <tr key={s.session_id} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
        <td className="p-5 max-w-[240px] truncate"><button className="text-cyan-400 font-medium hover:text-cyan-300 transition-colors" onClick={() => onSelect(s)}>{s.session_id}</button><p className="text-xs text-slate-500 mt-1">{s.analysis_id ?? 'Legacy / unscoped'}</p></td>
        <td className="p-5"><span className="text-slate-300">{s.src}</span><br /><span className="text-slate-500 text-xs">→ {s.dst}</span></td>
        <td className="p-5"><span className="font-medium text-slate-300">{s.protocol}</span><br /><span className="text-slate-500 text-xs">{tlsLabel(s)}</span></td>
        <td className={`p-5 font-medium ${statusColor(s.status).replace('text-', 'text-glow-')}`}>{s.status}<br /><span className="text-xs text-slate-400 font-normal">{s.score === null ? 'Unscored' : `${s.score}/100`}</span>{s.is_mitigated && <span className="inline-flex items-center gap-1 mt-1 text-[10px] font-bold text-emerald-400 uppercase tracking-wider bg-emerald-400/10 px-2 py-0.5 rounded border border-emerald-400/20">Mitigated</span>}</td>
        <td className="p-5 max-w-sm truncate text-slate-400 text-xs" title={s.reason}>{s.reason}</td>
      </tr>)}
    </tbody></table></CyberCard>;
}
