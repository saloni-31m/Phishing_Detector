# Dataset Sources

You need two classes of URLs: **phishing** (label=1) and **legitimate** (label=0).
Aim for a roughly balanced set — 5,000–10,000 of each is plenty for a final
year project and keeps feature extraction time reasonable.

## Phishing URLs

1. **PhishTank** — https://phishtank.org/developer_info.php
   Free, community-verified phishing URLs. Offers a downloadable CSV of
   currently active/verified phishing pages. Requires free registration
   for the full data feed, but a sample CSV is available without one.

2. **OpenPhish** — https://openphish.com/
   Free tier gives a rolling feed of recently identified phishing URLs
   (no login required for the community feed, updated every few hours).

3. **UCI Machine Learning Repository — Phishing datasets** —
   https://archive.ics.uci.edu/ — search "phishing websites" — several
   pre-labeled, pre-featurized datasets exist here if you want a fallback
   / comparison dataset in addition to your own scraped one.

## Legitimate URLs

1. **Tranco List** — https://tranco-list.eu/
   A research-grade "top sites" ranking (successor to the deprecated Alexa
   Top 1M), designed specifically to be citable in academic work — use
   this over an old Alexa CSV.

2. **Common Crawl** — https://commoncrawl.org/
   If you want more diverse/organic legitimate URLs beyond homepages
   (useful for content-based features), Common Crawl's URL index is a
   good source, though heavier to work with.

## Important notes for your report

- **Timestamp your dataset.** Phishing URLs go dead/get taken down within
  hours to days. Note the exact collection date — this becomes a natural
  "limitations / future work" discussion point (concept drift).
- **Never visit live phishing URLs in a normal browser.** Extract features
  via HTTP requests in a script (or a sandboxed VM) — don't click through
  in your day-to-day browser.
- **Cite your sources properly** in the report (PhishTank, OpenPhish, and
  Tranco all have citable formats on their sites).
- Keep a `data/urls.csv` with two columns: `url,label` — this is the format
  `train_model.py` expects.
