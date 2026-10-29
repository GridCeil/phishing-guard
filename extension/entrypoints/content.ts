/**
 * Lightweight DOM checks that need page access (the Flask backend only ever
 * sees the URL, not the rendered page). Currently: flags password forms that
 * submit to a different origin than the page itself -- a strong phishing
 * signal (credential harvesting pages often post to a collector domain).
 *
 * This posts a message to the background script rather than calling the API
 * directly, keeping all network calls centralized in one place.
 */
export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  main() {
    const pageOrigin = location.origin;

    const crossOriginPasswordForms = Array.from(document.querySelectorAll('form')).filter(
      (form) => {
        const hasPasswordField = !!form.querySelector('input[type="password"]');
        if (!hasPasswordField || !form.action) return false;
        try {
          return new URL(form.action, location.href).origin !== pageOrigin;
        } catch {
          return false;
        }
      },
    );

    if (crossOriginPasswordForms.length > 0) {
      browser.runtime
        .sendMessage({
          type: 'DOM_SIGNAL',
          signal: 'cross_origin_password_form',
          count: crossOriginPasswordForms.length,
          url: location.href,
        })
        .catch(() => {
          // Background script may not be listening for this yet -- non-fatal.
        });
    }
  },
});
