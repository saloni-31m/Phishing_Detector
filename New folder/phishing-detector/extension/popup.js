const statusEl = document.getElementById("status");
const urlBoxEl = document.getElementById("url-box");
const urlDomainEl = document.getElementById("url-domain");
const urlPathEl = document.getElementById("url-path");
const recheckBtn = document.getElementById("recheck");

const LABELS = {
  safe: "✅ Looks safe",
  low: "🟡 Low risk",
  medium: "🟠 Medium risk — be careful",
  high: "🔴 High risk — likely phishing",
};

const BAR_COLORS = {
  safe: "#2e7d32",
  low: "#c9a100",
  medium: "#e07b00",
  high: "#d32f2f",
};

function splitUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const domain = u.hostname;
    const rest = u.pathname + u.search;
    return { domain, rest: rest === "/" ? "" : rest };
  } catch {
    return { domain: rawUrl, rest: "" };
  }
}

function renderStatusOnly(className, verdictHtml) {
  statusEl.className = className;
  statusEl.innerHTML = `<div class="verdict">${verdictHtml}</div>`;
}

function render(result) {
  if (!result) {
    renderStatusOnly("loading", "Could not reach detection API");
    urlBoxEl.style.display = "none";
    return;
  }

  const risk = result.riskLevel || "safe";
  const pct = Math.round((result.probability ?? 0) * 100);
  const color = BAR_COLORS[risk] || "#888";

  statusEl.className = risk;
  statusEl.innerHTML = `
    <div class="verdict">${LABELS[risk] || "Unknown"}</div>
    <div id="bar-track"><div id="bar-fill" style="width:${pct}%; background:${color};"></div></div>
    <div id="bar-label" style="color:${color};">${pct}% phishing probability</div>
  `;

  const { domain, rest } = splitUrl(result.url || "");
  urlDomainEl.textContent = domain;
  urlDomainEl.title = result.url || "";
  urlPathEl.textContent = rest;
  urlPathEl.title = result.url || "";
  urlPathEl.style.display = rest ? "block" : "none";
  urlBoxEl.style.display = "block";
}

function checkActiveTab() {
  renderStatusOnly("loading", "Checking current page...");
  urlBoxEl.style.display = "none";
  chrome.runtime.sendMessage({ type: "CHECK_ACTIVE_TAB" }, (result) => {
    render(result);
  });
}

recheckBtn.addEventListener("click", checkActiveTab);
checkActiveTab();