// Injected into every page. Listens for a PHISHING_WARNING message from
// the background script and shows a dismissible banner at the top of
// the page if the site looks risky.
 
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "PHISHING_WARNING") {
    showWarningBanner(msg);
  } else if (msg.type === "PHISHING_CLEAR") {
    clearWarningBanner();
  }
});
 
function clearWarningBanner() {
  const existing = document.getElementById("__phishing_detector_banner");
  if (existing) existing.remove();
}
 
function showWarningBanner({ riskLevel, probability }) {
  const pct = Math.round(probability * 100);
  let banner = document.getElementById("__phishing_detector_banner");
 
  if (banner) {
    // Update the existing banner in place (e.g. risk level changed after
    // a re-check) rather than silently ignoring the new result.
    banner.style.background = riskLevel === "high" ? "#d32f2f" : "#f57c00";
    banner.querySelector("span").textContent =
      `⚠️ This page has a ${pct}% probability of being a phishing site. Be careful entering any information.`;
    return;
  }
 
  banner = document.createElement("div");
  banner.id = "__phishing_detector_banner";
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${riskLevel === "high" ? "#d32f2f" : "#f57c00"};
    color: white; font-family: sans-serif; font-size: 14px;
    padding: 10px 16px; display: flex; align-items: center;
    justify-content: space-between; box-shadow: 0 2px 6px rgba(0,0,0,0.3);
  `;
 
  banner.innerHTML = `
    <span>⚠️ This page has a ${pct}% probability of being a phishing site. Be careful entering any information.</span>
    <button id="__phishing_detector_dismiss" style="
      background: rgba(255,255,255,0.2); border: none; color: white;
      padding: 4px 10px; border-radius: 4px; cursor: pointer; margin-left: 12px;
    ">Dismiss</button>
  `;
 
  document.documentElement.prepend(banner);
  document.getElementById("__phishing_detector_dismiss")
    .addEventListener("click", () => banner.remove());
}