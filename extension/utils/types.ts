export type Verdict = 'safe' | 'low_risk' | 'suspicious' | 'malicious';

export interface Finding {
  type: string;
  message: string;
  weight: number;
  [key: string]: unknown;
}

export interface CheckUrlResponse {
  url: string;
  domain: string;
  risk_score: number;
  verdict: Verdict;
  deep_scan: boolean;
  reasons: string[];
  findings: Finding[];
}

export interface CheckUrlError {
  error: string;
}

// What the background script caches per-tab and the popup reads back.
export interface TabScanState {
  status: 'idle' | 'scanning' | 'done' | 'error';
  result?: CheckUrlResponse;
  errorMessage?: string;
  checkedAt?: number;
}

// Messages passed between content script / popup -> background script.
export type ExtensionMessage =
  | { type: 'GET_TAB_STATE'; tabId: number }
  | { type: 'RESCAN'; tabId: number; url: string; deepScan?: boolean }
  | { type: 'DOM_SIGNAL'; signal: 'cross_origin_password_form'; count: number; url: string };
