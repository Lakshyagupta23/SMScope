/**
 * config.ts
 * ---------
 * Single source of truth for all backend URLs.
 * Uses Vite environment variables so this works across dev, Docker, and production.
 * Set VITE_BACKEND_URL and VITE_WS_URL in your .env file.
 */

export const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
export let WS_URL = import.meta.env.VITE_WS_URL || BACKEND_URL.replace(/^http/, 'ws');

if (typeof window !== 'undefined' && window.location.protocol === 'https:' && WS_URL.startsWith('ws://')) {
    WS_URL = WS_URL.replace('ws://', 'wss://');
}

/** Convenience: full WebSocket stream endpoint */
export const WS_STREAM = `${WS_URL}/ws/stream`;
