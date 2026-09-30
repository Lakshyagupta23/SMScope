import { useState } from 'react';
import { downloadReport, errorMessage } from '../lib/api';

export function ReportDownloads({ analysisId }: { analysisId: string | null }) {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const download = async (format: 'json' | 'html' | 'pdf') => {
    if (!analysisId) return;
    setPending(true); setMessage('');
    try { await downloadReport(format, analysisId); setMessage(`${format.toUpperCase()} received; download requested for analysis ${analysisId}.`); }
    catch (e) { setMessage(errorMessage(e)); }
    finally { setPending(false); }
  };
  return <div className="space-y-3">
    <p className="text-xs text-gray-400 break-all">Report scope: {analysisId || 'Select a single analysis ID in Dataset scope first.'}</p>
    <p className="text-xs text-gray-400">JSON contains structured records. HTML and PDF provide the backend-generated posture report. Reports describe captured evidence, not confirmed incidents or compliance certification.</p>
    <div className="flex gap-3">{(['json', 'html', 'pdf'] as const).map(format => <button key={format} disabled={!analysisId || pending} onClick={() => void download(format)} className="border border-primary/40 px-4 py-2 text-sm text-primary disabled:opacity-40">{pending ? 'Please wait' : `Download ${format.toUpperCase()}`}</button>)}</div>
    {message && <p role="status" className="text-sm text-amber-300">{message}</p>}
  </div>;
}
