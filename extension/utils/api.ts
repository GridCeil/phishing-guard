import type { CheckUrlResponse, CheckUrlError } from './types';

// Swap this for your deployed backend URL at build time via .env + import.meta.env
// (WXT supports Vite-style env vars prefixed with WXT_).
export const API_BASE_URL = import.meta.env.WXT_API_BASE_URL || 'http://localhost:5000';
const API_TOKEN = import.meta.env.WXT_API_TOKEN || '';

const URL_SCHEMES_TO_SKIP = ['chrome:', 'chrome-extension:', 'about:', 'edge:', 'moz-extension:', 'file:'];

/** Don't bother scanning internal browser pages, new-tab pages, etc. */
export function isScannableUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return !URL_SCHEMES_TO_SKIP.some((scheme) => parsed.protocol === scheme);
  } catch {
    return false;
  }
}

export async function checkUrl(url: string, deepScan = false): Promise<CheckUrlResponse> {
  if (!API_TOKEN) throw new Error('WXT_API_TOKEN is not configured');

  const resp = await fetch(`${API_BASE_URL}/api/check-url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_TOKEN}`,
    },
    body: JSON.stringify({ url, deep_scan: deepScan }),
  });

  if (!resp.ok) {
    const body = (await resp.json().catch(() => null)) as CheckUrlError | null;
    throw new Error(body?.error || `Request failed with status ${resp.status}`);
  }

  return resp.json() as Promise<CheckUrlResponse>;
}
