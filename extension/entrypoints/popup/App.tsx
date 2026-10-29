import React, { useEffect, useState, useCallback } from 'react';
import type { ExtensionMessage, TabScanState, Verdict } from '@/utils/types';

const VERDICT_LABEL: Record<Verdict, string> = {
  safe: 'No issues found',
  low_risk: 'Minor concerns',
  suspicious: 'Suspicious site',
  malicious: 'Likely phishing',
};

const VERDICT_DESCRIPTION: Record<Verdict, string> = {
  safe: 'This page did not match any known phishing patterns.',
  low_risk: 'A couple of minor red flags, but nothing conclusive.',
  suspicious: 'Several indicators suggest this could be a phishing page.',
  malicious: 'Strong indicators this page is impersonating a trusted site.',
};

export default function App() {
  const [tabId, setTabId] = useState<number | null>(null);
  const [state, setState] = useState<TabScanState>({ status: 'idle' });
  const [rescanning, setRescanning] = useState(false);

  const loadTabState = useCallback(async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    setTabId(tab.id);
    const response = (await browser.runtime.sendMessage({
      type: 'GET_TAB_STATE',
      tabId: tab.id,
    } satisfies ExtensionMessage)) as TabScanState;
    setState(response);
  }, []);

  useEffect(() => {
    loadTabState();
  }, [loadTabState]);

  async function handleRescan() {
    if (!tabId) return;
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;

    setRescanning(true);
    try {
      const response = (await browser.runtime.sendMessage({
        type: 'RESCAN',
        tabId,
        url: tab.url,
        deepScan: true,
      } satisfies ExtensionMessage)) as TabScanState;
      setState(response);
    } finally {
      setRescanning(false);
    }
  }

  const verdict = state.result?.verdict;

  return (
    <div className="popup">
      <div className={`status-strip status-strip--${verdict ?? 'idle'}`}>
        <span className="status-strip__label">
          {state.status === 'scanning' && 'Scanning…'}
          {state.status === 'idle' && 'Not scanned'}
          {state.status === 'error' && 'Scan failed'}
          {state.status === 'done' && verdict && VERDICT_LABEL[verdict]}
        </span>
      </div>

      <div className="popup__body">
        {state.status === 'done' && state.result && (
          <>
            <div className="domain-row">
              <span className="domain-row__domain">{state.result.domain}</span>
              <span className="domain-row__score">
                {Math.round(state.result.risk_score * 100)}
                <span className="domain-row__score-unit">/100</span>
              </span>
            </div>

            <p className="verdict-description">
              {VERDICT_DESCRIPTION[state.result.verdict]}
            </p>

            {state.result.reasons.length > 0 && (
              <div className="reasons">
                <div className="reasons__heading">Signals detected</div>
                <ul className="reasons__list">
                  {state.result.reasons.map((reason, i) => (
                    <li key={i} className="reasons__item">
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {state.status === 'error' && (
          <p className="error-text">
            Couldn't reach the detection service. {state.errorMessage}
          </p>
        )}

        {state.status === 'idle' && (
          <p className="empty-text">Navigate to a page or run a scan below.</p>
        )}

        {state.status === 'scanning' && <p className="empty-text">Checking this page…</p>}

        <button className="rescan-btn" onClick={handleRescan} disabled={rescanning}>
          {rescanning ? 'Scanning…' : 'Run deep scan'}
        </button>
      </div>
    </div>
  );
}
