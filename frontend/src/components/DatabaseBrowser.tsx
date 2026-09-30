import { useState } from 'react';
import type { Session } from '../lib/sessions';
import { ForensicModal } from './ForensicModal';
import { SessionTable } from './TargetMatrix';
import { CyberCard } from './CyberCard';

/** Uses exactly the same normalized, scoped dataset as the dashboard. */
export function DatabaseBrowser({ sessions }: { sessions: Session[] }) {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Session | null>(null);
  const filtered = sessions.filter(s => [s.src, s.dst, s.session_id, s.analysis_id, s.status, s.protocol].join(' ').toLowerCase().includes(search.toLowerCase()));
  return <div className="space-y-6 animate-tech-drop">
    <ForensicModal session={selected} onClose={() => setSelected(null)} />
    <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 tracking-tight">Historical Forensic Records</h2>
    
    <CyberCard className="space-y-4" trailColor="bg-cyan-500/50">
      <div className="relative">
        <span className="absolute inset-y-0 left-0 flex items-center pl-4 text-cyan-500/50">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        </span>
        <input aria-label="Search records" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP, session, analysis or status..." 
        className="w-full bg-slate-900/60 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all shadow-inner" />
      </div>
      <p className="text-sm text-slate-400 font-medium ml-1"><span className="text-cyan-400 font-bold">{filtered.length}</span> matching records from the selected loaded dataset.</p>
    </CyberCard>
    
    <div className="bg-slate-900/40 rounded-xl border border-white/5 p-1 overflow-hidden">
      <SessionTable sessions={filtered} onSelect={setSelected} />
    </div>
  </div>;
}
