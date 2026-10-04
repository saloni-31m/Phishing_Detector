// Background service worker (Manifest V3).
// Watches tab navigation, calls the local inference API, caches results,
// and relays the verdict to the content script + popup.
 
const API_URL = "http://localhost:8000/predict";
const cache = new Map(); // url -> { isPhishing, probability, riskLevel, ts }
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
 
async function checkUrl(url) {
  const cached = cache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached;
  }
 
  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    const data = await res.json();
 
    const result = {
      isPhishing: data.is_phishing,
      probability: data.phishing_probability,
      riskLevel: data.risk_level,
      ts: Date.now(),
    };
    cache.set(url, result);
    return result;
  } catch (err) {
    console.warn("Phishing Detector: API call failed", err);
    return null; // fail open — don't block browsing if the API is down
  }
}
 
async function evaluateAndNotify(tabId, url) {
  const result = await checkUrl(url);
  if (!result) return;
 
  chrome.storage.local.set({ [`result_${tabId}`]: { url, ...result } });
 
  if (result.riskLevel === "high" || result.riskLevel === "medium") {
    chrome.tabs.sendMessage(tabId, {
      type: "PHISHING_WARNING",
      ...result,
    }).catch(() => {});
  } else {
    // Important: explicitly clear any stale banner from a previous URL.
    // Without this, a banner shown on one page can persist forever on
    // single-page apps (React/SPA sites like chatgpt.com) that change
    // the URL via the History API rather than a full page load, since
    // the content script never gets told the new page is actually safe.
    chrome.tabs.sendMessage(tabId, { type: "PHISHING_CLEAR" }).catch(() => {});
  }
 
  const badgeText = { high: "!!", medium: "!", low: "", safe: "" }[result.riskLevel] || "";
  const badgeColor = { high: "#d32f2f", medium: "#f57c00", low: "#fbc02d", safe: "#388e3c" }[result.riskLevel] || "#888";
  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
}
 
// Fires on a normal full page load
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;
  evaluateAndNotify(details.tabId, details.url);
});
 
// Fires on client-side route changes (History API pushState/replaceState),
// which is how single-page apps like ChatGPT change the URL WITHOUT a
// full page reload. onCompleted alone never sees these, which is why a
// banner from an earlier page can stay stuck on screen indefinitely.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;
  evaluateAndNotify(details.tabId, details.url);
});
 
// Allow popup.js to request a fresh check for the active tab
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_ACTIVE_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url) {
        sendResponse(null);
        return;
      }
      const result = await checkUrl(tab.url);
      sendResponse({ url: tab.url, ...result });
    });
    return true; // keep sendResponse async channel open
  }
});