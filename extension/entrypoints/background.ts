import { checkUrl, isScannableUrl } from '@/utils/api';
import type { ExtensionMessage, TabScanState, Verdict } from '@/utils/types';

const tabStates = new Map<number, TabScanState>();

const BADGE_CONFIG: Record<Verdict, { text: string; color: string }> = {
  safe: { text: '', color: '#2e7d32' },
  low_risk: { text: '!', color: '#9e9d24' },
  suspicious: { text: '!!', color: '#ef6c00' },
  malicious: { text: '!!!', color: '#c62828' },
};

const NOTIFICATION_ICON =
  'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22128%22 height=%22128%22 viewBox=%220 0 128 128%22%3E%3Crect width=%22128%22 height=%22128%22 rx=%2224%22 fill=%22%23c62828%22/%3E%3Cpath d=%22M64 24 112 104H16z%22 fill=%22white%22/%3E%3Cpath d=%22M60 50h8v28h-8zm0 36h8v8h-8z%22 fill=%22%23c62828%22/%3E%3C/svg%3E';

function setBadge(tabId: number, verdict?: Verdict) {
  if (!verdict) {
    browser.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const config = BADGE_CONFIG[verdict];
  browser.action.setBadgeText({ tabId, text: config.text });
  browser.action.setBadgeBackgroundColor({ tabId, color: config.color });
}

async function scanTab(tabId: number, url: string, deepScan = false) {
  if (!isScannableUrl(url)) {
    tabStates.delete(tabId);
    setBadge(tabId, undefined);
    return;
  }

  tabStates.set(tabId, { status: 'scanning' });
  setBadge(tabId, undefined);

  try {
    const result = await checkUrl(url, deepScan);
    tabStates.set(tabId, { status: 'done', result, checkedAt: Date.now() });
    setBadge(tabId, result.verdict);

    // Warn loudly on high-confidence phishing hits.
    if (result.verdict === 'malicious') {
      browser.notifications?.create(`phishing-${tabId}-${Date.now()}`, {
        type: 'basic',
        iconUrl: NOTIFICATION_ICON,
        title: 'Phishing Guard: dangerous site',
        message: `${result.domain} looks like a phishing site. Reasons: ${result.reasons
          .slice(0, 2)
          .join('; ')}`,
        priority: 2,
      });
    }
  } catch (err) {
    tabStates.set(tabId, {
      status: 'error',
      errorMessage: err instanceof Error ? err.message : 'Unknown error',
    });
    setBadge(tabId, undefined);
  }
}

// Fires when the URL in the address bar actually changes (not every resource load).
browser.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only care about the top-level frame, not iframes/ads/etc.
  if (details.frameId !== 0) return;
  scanTab(details.tabId, details.url);
});

// Catch client-side navigations (SPA route changes) that onBeforeNavigate misses.
browser.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  scanTab(details.tabId, details.url);
});

browser.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

/** Folds a client-only DOM signal into the cached result for that tab,
 * bumping the verdict up a level if it isn't already at the top. */
function applyDomSignal(tabId: number, message: string) {
  const current = tabStates.get(tabId);
  if (!current?.result) return;

  const bumped = { ...current.result };
  bumped.reasons = [...bumped.reasons, message];
  bumped.risk_score = Math.min(bumped.risk_score + 0.25, 1);
  if (bumped.verdict === 'safe') bumped.verdict = 'low_risk';
  else if (bumped.verdict === 'low_risk') bumped.verdict = 'suspicious';

  tabStates.set(tabId, { ...current, result: bumped });
  setBadge(tabId, bumped.verdict);
}

function isExtensionMessage(message: unknown): message is ExtensionMessage {
  if (typeof message !== 'object' || message === null || !('type' in message)) return false;
  const data = message as Record<string, unknown>;

  if (data.type === 'GET_TAB_STATE') return typeof data.tabId === 'number';
  if (data.type === 'RESCAN') {
    return (
      typeof data.tabId === 'number' &&
      typeof data.url === 'string' &&
      (data.deepScan === undefined || typeof data.deepScan === 'boolean')
    );
  }
  if (data.type === 'DOM_SIGNAL') {
    return (
      data.signal === 'cross_origin_password_form' &&
      typeof data.count === 'number' &&
      typeof data.url === 'string'
    );
  }
  return false;
}

browser.runtime.onMessage.addListener((rawMessage, sender, sendResponse) => {
  if (!isExtensionMessage(rawMessage)) {
    sendResponse(undefined);
    return true;
  }
  const message = rawMessage;

  if (message.type === 'GET_TAB_STATE') {
    sendResponse(tabStates.get(message.tabId) ?? { status: 'idle' });
    return true;
  }
  if (message.type === 'RESCAN') {
    scanTab(message.tabId, message.url, message.deepScan ?? true).then(() => {
      sendResponse(tabStates.get(message.tabId));
    });
    return true; // keep the message channel open for the async sendResponse
  }
  if (message.type === 'DOM_SIGNAL' && sender.tab?.id != null) {
    applyDomSignal(
      sender.tab.id,
      `Page has a password form submitting to a different domain (${message.count}x)`,
    );
    sendResponse(undefined);
    return true;
  }
  sendResponse(undefined);
  return true;
});

export default defineBackground(() => {
  console.log('Phishing Guard background script running', { id: browser.runtime.id });
});
