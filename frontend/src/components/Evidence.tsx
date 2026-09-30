import { display, record, text } from '../lib/sessions';
export function EvidenceValue({ label, value }: { label: string; value: unknown }) {
  return <div className="border border-primary/20 bg-black/30 p-3 min-w-0">
    <div className="text-xs text-gray-400 mb-1">{label}</div>
    <pre className="font-mono text-xs whitespace-pre-wrap break-words text-gray-200">{display(value)}</pre>
  </div>;
}
export function ComponentHealth({ components }: { components: unknown }) {
  const data = record(components);
  return <div className="grid grid-cols-1 md:grid-cols-3 gap-3">{['cti', 'ml', 'yara'].map(name => {
    const value = data[name] ?? data[name.toUpperCase()];
    const status = typeof value === 'string' ? value : text(record(value).status, 'unknown / not reported');
    return <div key={name} className="border border-primary/20 p-3 text-xs">
      <h4 className="uppercase text-primary mb-2">{name}</h4><p className="text-gray-300">{status}</p>
      {typeof value === 'object' && <pre className="mt-2 whitespace-pre-wrap break-words text-gray-400">{display(value)}</pre>}
    </div>;
  })}</div>;
}
