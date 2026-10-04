"""
URL feature extraction for phishing detection.
 
Extracts lexical/structural features directly from a URL string, without
needing to fetch the page — fast, safe, and works even if the site is down.
 
TODOs mark where you can add content-based features (require an HTTP
request to fetch the page HTML) and WHOIS-based features (domain age).
Both are good "extend the baseline" additions for your report.
"""
 
import re
import math
import os
from urllib.parse import urlparse
 
_TRUSTED_DOMAINS_PATH = os.path.join(
    os.path.dirname(__file__), "trusted_domains.txt"
)
_trusted_domains_cache = None
 
 
def _load_trusted_domains() -> set:
    """
    Lazily loads the trusted-domain whitelist (Tranco top 300k) once per
    process. Returns an empty set (feature degrades to 0 for everything)
    if the file isn't present, so the extractor never crashes without it.
    """
    global _trusted_domains_cache
    if _trusted_domains_cache is None:
        try:
            with open(_TRUSTED_DOMAINS_PATH, encoding="utf-8") as f:
                _trusted_domains_cache = {
                    line.strip().lower() for line in f if line.strip()
                }
        except FileNotFoundError:
            _trusted_domains_cache = set()
    return _trusted_domains_cache
 
# Common multi-part public suffixes we want to treat as one "suffix" unit
# so e.g. "example.co.uk" doesn't get its domain misread as "co".
# Not exhaustive (a full list is the public suffix list, psl) but covers
# the common cases well enough for a lexical-feature baseline.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "com.br", "co.za",
    # Indian sector-specific second-levels: shared categories many
    # different, unrelated organizations register under (e.g.
    # icici.bank.in and hdfc.bank.in are different banks, not
    # subdomains of one "bank.in" site) — must be treated as suffixes,
    # not apex domains, or a reputation check on the apex would wrongly
    # extend trust across every organization sharing the category.
    "bank.in", "gov.in", "nic.in", "res.in", "ac.in",
}
 
# Subset of the above that require verified eligibility to register at
# all (confirmed via NIXI/INRegistry policy), as opposed to "co.in",
# "net.in", "org.in" etc. which have been open to anyone since 2005.
# A domain under one of these is structurally hard to spoof regardless
# of whether it's globally popular enough to appear on a traffic-based
# whitelist like Tranco — bank.in requires an RBI banking license
# (registrar: IDRBT), gov.in/nic.in are government-only (registrar:
# NIC), and ac.in/res.in are restricted to accredited academic/research
# institutions (registrar: ERNET).
RESTRICTED_ELIGIBILITY_SUFFIXES = {"bank.in", "gov.in", "nic.in", "ac.in", "res.in"}
 
 
def _split_domain(hostname: str):
    """
    Lightweight stand-in for tldextract: splits a hostname into
    (subdomain, domain, suffix) without needing the external package
    or network access to fetch the public suffix list.
    """
    if not hostname:
        return "", "", ""
 
    parts = hostname.lower().split(".")
    if len(parts) < 2:
        return "", parts[0] if parts else "", ""
 
    # Check for a known multi-part suffix (e.g. co.uk) first
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_SUFFIXES and len(parts) >= 3:
        suffix = last_two
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
    else:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
 
    return subdomain, domain, suffix
 
SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "banking",
    "confirm", "signin", "webscr", "ebayisapi", "paypal", "password",
]
 
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
}
 
 
def _count_meaningful_subdomains(subdomain: str) -> int:
    """
    Count subdomain parts, excluding a leading 'www'.
    'www' is present on a huge fraction of legitimate sites and carries
    essentially no phishing signal on its own, but naive datasets (e.g.
    top-domain lists that store only apex domains like 'wikipedia.org')
    never include it — so a model trained on num_subdomains without this
    adjustment learns 'has any subdomain' as a false phishing signal and
    flags ordinary www.example.com pages. Genuinely unusual subdomains
    (e.g. 'login.verify.example.com') still count normally.
    """
    if not subdomain:
        return 0
    parts = [p for p in subdomain.split(".") if p]
    if parts and parts[0] == "www":
        parts = parts[1:]
    return len(parts)
 
 
def _shannon_entropy(s: str) -> float:
    """Higher entropy can indicate randomly-generated/obfuscated domains."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)
 
 
def get_full_domain(url: str) -> str:
    """
    Public helper: returns just the apex domain (e.g. 'github.io') for a
    URL. Used by api.py for the UGC-platform check — kept separate from
    extract_features() because that function's output feeds directly into
    the model as numeric columns, and a domain string can't go there.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    _, domain, suffix = _split_domain(parsed.hostname or "")
    return f"{domain}.{suffix}".lower() if suffix else domain.lower()
 
 
def extract_features(url: str) -> dict:
    """
    Extract a feature dict from a single URL.
    Returns a dict of feature_name -> numeric value so it's easy to inspect,
    log, and convert to a DataFrame row.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    subdomain, domain, suffix = _split_domain(parsed.hostname or "")
    full_domain = f"{domain}.{suffix}" if suffix else domain
    path = parsed.path or ""
    if path == "/":
        path = ""  # root slash is meaningless noise, not a real path
    query = parsed.query or ""
 
    features = {
        # --- Length-based ---
        "url_length": len(url),
        "domain_length": len(full_domain),
        "path_length": len(path),
 
        # --- Character/structure based ---
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_at_symbols": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": _count_meaningful_subdomains(subdomain),
        "has_ip_address": 1 if re.match(
            r"^(\d{1,3}\.){3}\d{1,3}$", parsed.hostname or ""
        ) else 0,
 
        # --- Protocol / security signals ---
        "uses_https": 1 if parsed.scheme == "https" else 0,
 
        # --- Suspicious content signals ---
        "has_suspicious_word": 1 if any(
            w in url.lower() for w in SUSPICIOUS_WORDS
        ) else 0,
        "is_shortened": 1 if full_domain.lower() in SHORTENER_DOMAINS else 0,
        "num_query_params": query.count("=") if query else 0,
 
        # --- Entropy (randomness) of the domain name ---
        "domain_entropy": round(_shannon_entropy(domain), 3),
 
        # --- Domain reputation (whitelist against known popular domains) ---
        "is_trusted_domain": 1 if full_domain.lower() in _load_trusted_domains() else 0,
 
        # --- Restricted-eligibility TLD (hard to spoof regardless of
        # global popularity, since registration itself requires proof
        # of banking license / government / academic accreditation) ---
        "is_restricted_tld": 1 if suffix.lower() in RESTRICTED_ELIGIBILITY_SUFFIXES else 0,
 
        # --- Ratio features ---
        "digit_ratio": round(
            sum(c.isdigit() for c in url) / len(url), 3
        ) if url else 0,
    }
 
    # TODO (content-based, requires fetching the page — do this in a
    # separate, rate-limited, sandboxed step, not inline here):
    #   - has_password_field: form with type="password" present
    #   - has_iframe: hidden/zero-size iframe present
    #   - external_link_ratio: fraction of <a> hrefs pointing off-domain
    #   - favicon_domain_mismatch: favicon loaded from a different domain
 
    # TODO (WHOIS-based, requires `python-whois` + a network call):
    #   - domain_age_days: newly registered domains are a strong phishing
    #     signal — most legitimate sites are months/years old
 
    return features
 
 
if __name__ == "__main__":
    # Quick manual sanity check
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.tk/verify/account?id=283991",
        "http://192.168.1.1/banking/confirm",
    ]
    for u in test_urls:
        print(u)
        for k, v in extract_features(u).items():
            print(f"  {k}: {v}")
        print()