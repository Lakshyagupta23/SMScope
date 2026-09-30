import { BACKEND_URL } from '../config';
import { record, text } from './sessions';

const TOKEN_KEY = 'securemailscope.apiToken';
export function getApiToken(): string { return import.meta.env.VITE_API_TOKEN || sessionStorage.getItem(TOKEN_KEY) || ''; }
export function setApiToken(token: string): void {
  if (token.trim()) sessionStorage.setItem(TOKEN_KEY, token.trim());
  else sessionStorage.removeItem(TOKEN_KEY);
  window.dispatchEvent(new Event('api-token-changed'));
}
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed';
}
/** Token is runtime session state, never a Vite environment variable or URL parameter. */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getApiToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${BACKEND_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    let detail = '';
    try {
      const body = record(await response.json());
      detail = text(body.detail, text(record(body.detail).message, text(body.message, '')));
    } catch { /* Non-JSON error response. */ }
    const auth = response.status === 401 || response.status === 403;
    const message = auth ? `Authorization denied (${response.status}). Check the API token in System Config.`
      : `API ${response.status}${detail ? `: ${detail}` : ''}`;
    if (auth) window.dispatchEvent(new CustomEvent('api-auth-error', { detail: message }));
    throw new Error(message);
  }
  return response;
}
export async function downloadReport(format: 'json' | 'html' | 'pdf', analysisId: string): Promise<void> {
  if (!analysisId) throw new Error('Select an analysis ID before exporting.');
  const response = await apiFetch(`/api/report/${format}?analysis_id=${encodeURIComponent(analysisId)}`);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = `securemailscope-${analysisId.replace(/[^a-zA-Z0-9_-]/g, '_')}.${format}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
