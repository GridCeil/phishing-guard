# Phishing Guard — WXT Extension

Browser extension frontend for the Flask phishing-detection backend. Watches
navigation, calls the API, and shows a badge + popup with the verdict.

## Setup

```bash
npm install
cp .env.example .env.local   # point WXT_API_BASE_URL at your backend
npm run dev                  # opens a dev browser with the extension loaded
```

For Firefox: `npm run dev:firefox`.

Make sure the Flask backend from `phishing-backend/` is running at the URL
you set in `.env.local` (defaults to `http://localhost:5000`).
Set `WXT_API_TOKEN` in `.env.local` to the same value as `API_TOKEN` in the
backend's `.env` file.

## How it's wired together

```
entrypoints/background.ts   – listens for navigation (webNavigation API),
                               calls POST /api/check-url, caches the result
                               per tabId, sets the toolbar badge color.

entrypoints/content.ts      – runs on every page, checks for password forms
                               that submit cross-origin (phishing tell the
                               backend can't see from the URL alone), sends
                               it to the background script via messaging.

entrypoints/popup/          – React UI. On open, asks the background script
                               for the current tab's cached state and renders
                               it. "Run deep scan" triggers a fresh check with
                               deep_scan: true (WHOIS + Safe Browsing).

utils/api.ts                – the one place that calls the Flask API.
utils/types.ts               – shared types matching the backend's JSON shape.
```

### Message flow

```
content script --DOM_SIGNAL--> background --(folds into cached result)
popup --GET_TAB_STATE--> background --(returns cached result)--> popup
popup --RESCAN--> background --checkUrl()--> Flask API --> popup
```

## Badge colors

| Verdict | Badge |
|---|---|
| safe | green, no text |
| low_risk | yellow `!` |
| suspicious | orange `!!` |
| malicious | red `!!!` + desktop notification |

## Building for production

```bash
npm run build          # outputs to .output/chrome-mv3/
npm run zip            # packages a .zip for the Chrome Web Store
```

Before publishing: narrow `host_permissions` in `wxt.config.ts` to your real
API domain (drop `localhost`), and set `WXT_API_BASE_URL` to that domain in
your production `.env`.

## Icons

Add icon files to `assets/` or `public/icon/` (16/32/48/128px PNGs) — WXT
picks these up automatically if placed under `public/icon/`. None are
included here; the manifest will build without them but the toolbar icon
will be blank until you add some.
