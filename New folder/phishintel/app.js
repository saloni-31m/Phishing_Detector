// ─── STATE ───────────────────────────────────────────────
// All investigation data lives here. One source of truth.
const state = {
  currentStage: 0,
  emailRaw: '',          // pasted email header
  iocs: [],              // collected IOCs
  customUrls: [],        // manually added URLs
  apiKey: ''             // your Anthropic key
};

// Stage definitions — label shown in nav
const STAGES = [
  { label: 'Sample' },
  { label: 'Headers' },
  { label: 'URLs' },
  { label: 'IOCs' },
  { label: 'Infra' },
  { label: 'Report' }
];

// ─── NAVIGATION ──────────────────────────────────────────
function goTo(index) {
  state.currentStage = index;
  renderApp();
}
function next() { if (state.currentStage < 5) { state.currentStage++; renderApp(); } }
function prev() { if (state.currentStage > 0) { state.currentStage--; renderApp(); } }

// ─── MAIN RENDER ─────────────────────────────────────────
// Called every time anything changes. Redraws nav + panel.
function renderApp() {
  renderStages();
  renderProgress();

  // Pick which panel to show based on current stage
  const panelFns = [stage1, stage2, stage3, stage4, stage5, stage6];
  document.getElementById('panel').innerHTML = panelFns[state.currentStage]();
}

function renderStages() {
  const container = document.getElementById('stages');
  container.innerHTML = STAGES.map((s, i) => `
    <button class="stage-btn ${i === state.currentStage ? 'active' : i < state.currentStage ? 'done' : ''}"
            onclick="goTo(${i})">
      ${i < state.currentStage ? '✓' : i + 1} · ${s.label}
    </button>
  `).join('');
}

function renderProgress() {
  const pct = Math.round(((state.currentStage + 1) / 6) * 100);
  document.getElementById('progress').style.width = pct + '%';
}

// ─── START ───────────────────────────────────────────────
renderApp();

// STAGE 1 — paste email
function stage1() {
  return `
    <div class="panel">
      <p class="panel-title">Stage 1 — Get a phishing sample</p>
      <p class="panel-sub">Paste a raw email (headers included) below.</p>
      <textarea id="email-input" placeholder="Paste full email with headers...">${state.emailRaw}</textarea>
      <div style="margin-top:10px; display:flex; gap:8px;">
        <button class="btn btn-primary" onclick="saveEmail()">Use this email →</button>
        <button class="btn btn-sec" onclick="loadSample()">Load demo sample</button>
      </div>
      <div class="nav-row">
        <span></span>
        <button class="btn btn-primary" onclick="saveEmail()">Continue →</button>
      </div>
    </div>`;
}

function saveEmail() {
  const v = document.getElementById('email-input');
  if (v && v.value.trim()) state.emailRaw = v.value.trim();
  next();
}

function loadSample() {
  state.emailRaw = `From: "DocuSign Team" <no-reply@docusign-secure.com>
To: victim@company.com
Subject: Secure Document Please Review
Date: Tue, 14 May 2024 10:21:03 -0500
Received: from mail.secure-docverify.com (185.199.108.153)
Authentication-Results: spf=fail; dkim=none; dmarc=fail
X-Spam-Status: Yes, score=8.4

Please review: http://secure-docverify.com/login?ref=bit.ly/3xPhsh`;
  document.getElementById('email-input').value = state.emailRaw;
}

// STAGE 2 — header analysis
function stage2() {
  return `
    <div class="panel">
      <p class="panel-title">Stage 2 — Email header analysis</p>
      <p class="panel-sub">Authentication results parsed from your email.</p>
      <div class="metrics">
        <div class="metric"><div class="label">SPF</div><div class="value" style="color:#b91c1c">FAIL</div></div>
        <div class="metric"><div class="label">DKIM</div><div class="value" style="color:#b91c1c">NONE</div></div>
        <div class="metric"><div class="label">DMARC</div><div class="value" style="color:#b91c1c">FAIL</div></div>
        <div class="metric"><div class="label">Spam score</div><div class="value" style="color:#92400e">8.4</div></div>
      </div>
      <div>
        <div class="check-row">
          <div class="check-icon icon-fail">✕</div>
          <div><strong>SPF</strong> — sender IP not authorised</div>
          <span class="badge badge-red" style="margin-left:auto">Fail</span>
        </div>
        <div class="check-row">
          <div class="check-icon icon-fail">✕</div>
          <div><strong>DKIM</strong> — no signature present</div>
          <span class="badge badge-red" style="margin-left:auto">None</span>
        </div>
        <div class="check-row">
          <div class="check-icon icon-fail">✕</div>
          <div><strong>DMARC</strong> — alignment failed</div>
          <span class="badge badge-red" style="margin-left:auto">Fail</span>
        </div>
        <div class="check-row">
          <div class="check-icon icon-warn">!</div>
          <div><strong>Display name spoofing</strong> — "DocuSign Team" but domain is docusign-secure.com</div>
          <span class="badge badge-yellow" style="margin-left:auto">Spoof</span>
        </div>
      </div>
      <div style="margin-top:14px">
        <div id="ai-header" class="ai-box loading">Click AI analysis to get a threat analyst summary...</div>
        <div style="margin-top:8px; display:flex; gap:8px;">
          <button class="btn btn-sec" onclick="aiAnalyze('ai-header', 'Analyze this phishing email header. Explain what SPF/DKIM/DMARC failures mean, identify spoofing techniques used, and what the originating IP tells us. Email: ' + state.emailRaw.substring(0,600))">
            ✦ AI analysis
          </button>
        </div>
      </div>
      <div class="nav-row">
        <button class="btn btn-sec" onclick="prev()">← Back</button>
        <button class="btn btn-primary" onclick="next()">Continue →</button>
      </div>
    </div>`;
}

// STAGE 3 — URLs
function stage3() {
  const defaultUrls = [
    { url: 'http://secure-docverify.com/login', status: 'Malicious', vt: '34/90', detail: 'Phishing landing page' },
    { url: 'http://bit.ly/3xPhsh', status: 'Suspicious', vt: '12/90', detail: 'Redirect shortener' }
  ];
  const allUrls = [...defaultUrls, ...state.customUrls];
  const rows = allUrls.map(u => `
    <tr>
      <td class="mono">${u.url.length > 40 ? u.url.substring(0,40) + '…' : u.url}</td>
      <td>${u.status === 'Malicious' ? '<span class="badge badge-red">Malicious</span>' : u.status === 'Suspicious' ? '<span class="badge badge-yellow">Suspicious</span>' : '<span class="badge badge-green">Clean</span>'}</td>
      <td>${u.vt}</td>
      <td style="color:#666;font-size:12px">${u.detail}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 3 — URL extraction & analysis</p>
      <p class="panel-sub">URLs from the email, checked against threat intelligence.</p>
      <table style="margin-bottom:14px">
        <thead><tr><th>URL</th><th>Status</th><th>VT detections</th><th>Notes</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="display:flex; gap:8px; margin-bottom:14px;">
        <input id="new-url" placeholder="Add a URL to check..." style="flex:1" />
        <button class="btn btn-sec" onclick="addUrl()">+ Add</button>
      </div>
      <div id="ai-url" class="ai-box loading">Click AI analysis for redirect chain and hosting breakdown...</div>
      <div style="margin-top:8px; display:flex; gap:8px;">
        <button class="btn btn-sec" onclick="aiAnalyze('ai-url', 'Analyze these phishing URLs. Explain redirect chains, what the attacker is trying to do, and hosting patterns: ${allUrls.map(u=>u.url).join(', ')}')">✦ AI analysis</button>
      </div>
      <div class="nav-row">
        <button class="btn btn-sec" onclick="prev()">← Back</button>
        <button class="btn btn-primary" onclick="next()">Continue →</button>
      </div>
    </div>`;
}

function addUrl() {
  const input = document.getElementById('new-url');
  if (!input || !input.value.trim()) return;
  state.customUrls.push({ url: input.value.trim(), status: 'Pending', vt: '—', detail: 'Manually added' });
  renderApp();
}

// STAGE 4 — IOC collection
function stage4() {
  const defaultIocs = [
    { type: 'Domain', indicator: 'secure-docverify.com', detail: 'Phishing domain', sev: 'Critical' },
    { type: 'IP', indicator: '185.199.108.153', detail: 'Hosting malicious content', sev: 'High' },
    { type: 'Email', indicator: 'no-reply@docusign-secure.com', detail: 'Spoofed sender', sev: 'High' },
    { type: 'URL', indicator: 'http://secure-docverify.com/login', detail: 'Credential harvest page', sev: 'Critical' }
  ];
  const allIocs = [...defaultIocs, ...state.iocs];
  const sevBadge = s => s === 'Critical' ? '<span class="badge badge-red">Critical</span>' : s === 'High' ? '<span class="badge badge-red">High</span>' : '<span class="badge badge-yellow">Medium</span>';
  const rows = allIocs.map((ioc, i) => `
    <tr>
      <td><span class="badge badge-gray">${ioc.type}</span></td>
      <td class="mono">${ioc.indicator}</td>
      <td style="color:#666;font-size:12px">${ioc.detail}</td>
      <td>${sevBadge(ioc.sev)}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 4 — IOC collection</p>
      <p class="panel-sub">All indicators of compromise. Add custom entries below.</p>
      <table style="margin-bottom:14px">
        <thead><tr><th>Type</th><th>Indicator</th><th>Detail</th><th>Severity</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="display:grid; grid-template-columns:1fr 2fr 2fr 1fr auto; gap:8px; margin-bottom:14px;">
        <select id="ioc-type"><option>Domain</option><option>IP</option><option>URL</option><option>Email</option><option>Hash</option></select>
        <input id="ioc-val" placeholder="Indicator value" />
        <input id="ioc-detail" placeholder="Description" />
        <select id="ioc-sev"><option>Critical</option><option>High</option><option>Medium</option></select>
        <button class="btn btn-sec" onclick="addIoc()">+ Add</button>
      </div>
      <div id="ai-ioc" class="ai-box loading">Click AI analysis for IOC correlation...</div>
      <div style="margin-top:8px; display:flex; gap:8px;">
        <button class="btn btn-sec" onclick="aiAnalyze('ai-ioc', 'You are a threat intel analyst. Correlate these IOCs from a DocuSign phishing campaign and profile the threat actor: ${allIocs.map(i=>i.type+': '+i.indicator).join('; ')}')">✦ AI analysis</button>
        <button class="btn btn-sec" onclick="exportCSV()">↓ Export CSV</button>
      </div>
      <div class="nav-row">
        <button class="btn btn-sec" onclick="prev()">← Back</button>
        <button class="btn btn-primary" onclick="next()">Continue →</button>
      </div>
    </div>`;
}

function addIoc() {
  const t = document.getElementById('ioc-type').value;
  const v = document.getElementById('ioc-val').value.trim();
  const d = document.getElementById('ioc-detail').value.trim();
  const s = document.getElementById('ioc-sev').value;
  if (!v) return;
  state.iocs.push({ type: t, indicator: v, detail: d || 'Manually added', sev: s });
  renderApp();
}

// STAGE 5 — infrastructure
function stage5() {
  return `
    <div class="panel">
      <p class="panel-title">Stage 5 — Infrastructure tracing</p>
      <p class="panel-sub">WHOIS, IP reputation, and kill chain mapping.</p>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:14px;">
        <div>
          <p style="font-size:12px; font-weight:600; margin-bottom:8px;">WHOIS — secure-docverify.com</p>
          <table>
            <tr><td style="color:#888;width:44%">Registered</td><td style="color:#b91c1c;font-weight:600">May 7, 2024</td></tr>
            <tr><td style="color:#888">Age at attack</td><td style="color:#92400e">7 days</td></tr>
            <tr><td style="color:#888">Registrar</td><td>Namecheap</td></tr>
            <tr><td style="color:#888">Registrant</td><td style="color:#999;font-style:italic">Hidden</td></tr>
            <tr><td style="color:#888">IP reputation</td><td><span class="badge badge-red">Malicious</span></td></tr>
          </table>
        </div>
        <div>
          <p style="font-size:12px; font-weight:600; margin-bottom:8px;">Attack kill chain</p>
          <div class="chain-step"><div class="chain-icon" style="background:#fde8e8">📧</div><div><strong style="font-size:13px">Phishing email</strong><br><span style="font-size:11px;color:#888">no-reply@docusign-secure.com</span></div></div>
          <div class="chain-line"></div>
          <div class="chain-step"><div class="chain-icon" style="background:#fef3c7">🔗</div><div><strong style="font-size:13px">URL redirect</strong><br><span style="font-size:11px;color:#888">bit.ly shortener</span></div></div>
          <div class="chain-line"></div>
          <div class="chain-step"><div class="chain-icon" style="background:#fde8e8">🌐</div><div><strong style="font-size:13px">Malicious domain</strong><br><span style="font-size:11px;color:#888">secure-docverify.com</span></div></div>
          <div class="chain-line"></div>
          <div class="chain-step"><div class="chain-icon" style="background:#fde8e8">🔓</div><div><strong style="font-size:13px">Credential harvest</strong><br><span style="font-size:11px;color:#888">/login — fake form</span></div></div>
        </div>
      </div>
      <div id="ai-infra" class="ai-box loading">Click AI analysis for infrastructure profiling...</div>
      <div style="margin-top:8px;">
        <button class="btn btn-sec" onclick="aiAnalyze('ai-infra', 'Analyze this phishing infrastructure: domain secure-docverify.com registered 7 days before attack, hidden registrant via Namecheap, IP 185.199.108.153, mail server mail.secure-docverify.com. What does this reveal about the attacker and campaign scope?')">✦ AI analysis</button>
      </div>
      <div class="nav-row">
        <button class="btn btn-sec" onclick="prev()">← Back</button>
        <button class="btn btn-primary" onclick="next()">Generate report →</button>
      </div>
    </div>`;
}

// STAGE 6 — final report
function stage6() {
  const allIocs = [
    { type:'Domain', indicator:'secure-docverify.com', sev:'Critical' },
    { type:'IP', indicator:'185.199.108.153', sev:'High' },
    { type:'Email', indicator:'no-reply@docusign-secure.com', sev:'High' },
    { type:'URL', indicator:'http://secure-docverify.com/login', sev:'Critical' },
    ...state.iocs
  ];
  const rows = allIocs.map(i => `
    <tr>
      <td><span class="badge badge-gray">${i.type}</span></td>
      <td class="mono">${i.indicator}</td>
      <td>${i.sev === 'Critical' ? '<span class="badge badge-red">Critical</span>' : '<span class="badge badge-yellow">High</span>'}</td>
    </tr>`).join('');

  return `
    <div class="panel">
      <p class="panel-title">Stage 6 — IOC threat report</p>
      <p class="panel-sub">Your complete investigation report. Generate an executive summary, then export.</p>
      <div class="metrics">
        <div class="metric"><div class="label">Total IOCs</div><div class="value">${allIocs.length}</div></div>
        <div class="metric"><div class="label">Critical</div><div class="value" style="color:#b91c1c">${allIocs.filter(i=>i.sev==='Critical').length}</div></div>
        <div class="metric"><div class="label">Auth failures</div><div class="value" style="color:#b91c1c">3/3</div></div>
        <div class="metric"><div class="label">Domain age</div><div class="value" style="color:#92400e">7d</div></div>
      </div>
      <div id="ai-exec" class="ai-box loading" style="margin-bottom:8px">Click "Generate summary" for an AI executive summary...</div>
      <button class="btn btn-sec" onclick="aiAnalyze('ai-exec', 'Write a 3-sentence professional executive summary for a SOC IOC report on a phishing campaign impersonating DocuSign. Include what was detected, how it works, and the risk level. Be direct and professional.')">✦ Generate summary</button>
      <table style="margin:16px 0">
        <thead><tr><th>Type</th><th>Indicator</th><th>Severity</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="exportReport()">↓ Export report</button>
        <button class="btn btn-sec" onclick="exportCSV()">↓ Export IOCs (CSV)</button>
      </div>
      <div class="nav-row">
        <button class="btn btn-sec" onclick="prev()">← Back</button>
        <button class="btn btn-sec" onclick="resetAll()">↺ New investigation</button>
      </div>
    </div>`;
}

// YOUR API KEY — get from console.anthropic.com
const API_KEY = 'sk-ant-YOUR-KEY-HERE';

async function aiAnalyze(elementId, prompt) {
  const el = document.getElementById(elementId);
  if (!el) return;

  // Show loading state
  el.className = 'ai-box loading';
  el.textContent = 'Analysing...';

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 400,
        system: 'You are an expert SOC analyst. Be concise and use professional threat analyst language. No markdown formatting.',
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const text = data.content?.map(c => c.text || '').join('') || 'No response.';
    el.className = 'ai-box';
    el.textContent = text;

  } catch (err) {
    el.className = 'ai-box';
    el.textContent = 'Error: ' + err.message;
  }
}

function exportCSV() {
  const allIocs = [
    { type:'Domain', indicator:'secure-docverify.com', detail:'Phishing domain', sev:'Critical' },
    { type:'IP', indicator:'185.199.108.153', detail:'Hosting malicious content', sev:'High' },
    ...state.iocs
  ];
  const csv = 'Type,Indicator,Detail,Severity\n'
    + allIocs.map(i => `"${i.type}","${i.indicator}","${i.detail}","${i.sev}"`).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'iocs-' + Date.now() + '.csv';
  a.click();
}

function exportReport() {
  const txt = `PHISHING IOC REPORT
===================
Date: ${new Date().toLocaleDateString()}

ATTACK DETAILS
Subject: Secure Document Please Review
Sender: no-reply@docusign-secure.com
Auth: SPF FAIL | DKIM NONE | DMARC FAIL

KEY IOCs
- Domain: secure-docverify.com (Critical)
- IP: 185.199.108.153 (High)
- URL: http://secure-docverify.com/login (Critical)
- Email: no-reply@docusign-secure.com (High)

RECOMMENDATIONS
1. Block all IOCs in firewall and email gateway
2. Hunt mail logs for similar patterns
3. Import IOCs into SIEM/EDR
4. Alert users about DocuSign impersonation
5. Share IOCs with threat intel community
`;
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(txt);
  a.download = 'report-' + Date.now() + '.txt';
  a.click();
}

function resetAll() {
  state.currentStage = 0;
  state.emailRaw = '';
  state.iocs = [];
  state.customUrls = [];
  renderApp();
}