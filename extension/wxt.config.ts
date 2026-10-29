import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'Phishing Guard',
    description: 'Scans the sites you visit for phishing indicators in real time.',
    version: '0.1.0',
    permissions: ['storage', 'tabs', 'webNavigation', 'notifications'],
    // Needed so the background script can call your local/hosted Flask API.
    // Tighten this to your real API origin before publishing.
    host_permissions: ['http://localhost:5000/*', 'https://your-api-domain.com/*'],
    action: {
      default_title: 'Phishing Guard',
    },
  },
});
