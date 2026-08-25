"""
common.py
=========
Shared constants and small algorithms used by more than one module.

Keeping these here (instead of copy-pasting into log_parser.py and
detectors.py separately) guarantees that, e.g., "how we split a domain into
subdomain + registrable domain" is defined exactly once. If parsing and
detection ever disagreed on that logic, alerts would silently point at the
wrong domain.
"""

import math

# ---------------------------------------------------------------------------
# Brand watchlist (used by detectors.detect_typosquatting)
# ---------------------------------------------------------------------------
# A small, illustrative set of frequently-impersonated brands. In a real
# deployment this would be the organisation's own domains plus high-value
# third parties (identity providers, payment processors, etc.), likely
# loaded from a config file rather than hardcoded.
BRAND_WATCHLIST = [
    "google.com",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "github.com",
    "netflix.com",
    "chase.com",
    "dropbox.com",
]

# ---------------------------------------------------------------------------
# MITRE ATT&CK reference (id -> technique name), so every module/alert/report
# uses identical labels instead of re-typing technique names.
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES = {
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    "T1568.001": "Dynamic Resolution: Fast Flux DNS",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1590.002": "Gather Victim Network Information: DNS Information",
    "T1583.001": "Acquire Infrastructure: Domains",
}

# Real ATT&CK tactic each technique above belongs to (verified against
# attack.mitre.org - not invented for this project). Multiple detectors can
# legitimately share a technique ID: DGA and Fast Flux are both
# sub-techniques of T1568 "Dynamic Resolution"; tunneling, beaconing and
# encrypted-DNS evasion are all T1071.004 "DNS" because they're the same
# underlying technique used for different purposes; typosquatting and
# newly-registered-domain scoring are both T1583.001 "Acquire
# Infrastructure: Domains" because both are about attacker-owned domains,
# just detected via a different signal (string similarity vs. registration
# recency).
MITRE_TACTIC = {
    "T1568.002": "Command and Control",
    "T1568.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1590.002": "Reconnaissance",
    "T1583.001": "Resource Development",
}
TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Command and Control"]

# A few real, well-known public DoH (DNS-over-HTTPS) resolvers. Traffic to
# these is not inherently malicious (plenty of legitimate software uses
# them) - but on a network that expects to see and inspect plain DNS, a
# client resolving one of these is a signal it may be about to move its DNS
# resolution outside that visibility. Shared here (not duplicated) so the
# generator's demo scenario and the detector's watchlist can't drift apart.
KNOWN_DOH_PROVIDERS = [
    "cloudflare-dns.com",
    "dns.google",
    "doh.opendns.com",
    "mozilla.cloudflare-dns.com",
    "dns.quad9.net",
    "doh.cleanbrowsing.org",
]

# Icon + short display label, purely for the dashboard's UI - kept here so
# dashboard.py doesn't hardcode detector-specific strings.
DETECTOR_META = {
    "dga":              {"icon": "\U0001F3B2", "label": "DGA Domain"},
    "tunneling":        {"icon": "\U0001F573\uFE0F", "label": "DNS Tunneling"},
    "beaconing":        {"icon": "\U0001F4E1", "label": "C2 Beaconing"},
    "nxdomain_spike":   {"icon": "\U0001F50D", "label": "Recon / NXDOMAIN Spike"},
    "typosquat":        {"icon": "\U0001F3AD", "label": "Typosquat"},
    "fast_flux":        {"icon": "\U0001F300", "label": "Fast-Flux DNS"},
    "doh_evasion":      {"icon": "\U0001F512", "label": "Encrypted-DNS Evasion"},
    "newly_registered": {"icon": "\U0001F195", "label": "Newly Registered Domain"},
}

# ---------------------------------------------------------------------------
# Simplified public-suffix handling
# ---------------------------------------------------------------------------
# A handful of common multi-label TLDs. This is a deliberately small stand-in
# for a full Public Suffix List (https://publicsuffix.org/) - good enough for
# this project's traffic, but a production tool should use the `tldextract`
# package instead of hand-rolling this.
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "co.jp", "com.au",
    "com.br", "com.cn", "com.mx", "net.au", "org.au", "co.nz", "co.za",
}


def split_domain(fqdn: str):
    """
    Split a fully-qualified domain name into (subdomain_labels, registrable_domain).

    Example:
        "4a6f.tunnel.evil-corp.net" -> (["4a6f", "tunnel"], "evil-corp.net")
        "www.google.com"            -> (["www"], "google.com")
        "google.com"                -> ([], "google.com")
        "vpn.example.co.uk"         -> (["vpn"], "example.co.uk")
    """
    fqdn = (fqdn or "").rstrip(".").lower().strip()
    if not fqdn:
        return [], ""
    labels = fqdn.split(".")
    if len(labels) <= 2:
        return [], fqdn

    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_TLDS and len(labels) >= 3:
        registrable = ".".join(labels[-3:])
        sub = labels[:-3]
    else:
        registrable = last_two
        sub = labels[:-2]
    return sub, registrable


def registrable_domain(fqdn: str) -> str:
    """Convenience wrapper: just the eTLD+1 (registrable domain)."""
    _, reg = split_domain(fqdn)
    return reg


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """
    Shannon entropy in bits/character of a string - a measure of how
    'random-looking' its character distribution is.

    Human-chosen words (google, microsoft, github) draw from a small set of
    recurring English letter patterns, so they sit in a low-to-moderate
    entropy band (roughly 2.5-3.5 bits/char). Algorithmically generated
    strings tend to spread evenly across the alphabet, pushing entropy
    towards log2(26) ~= 4.7 for lowercase letters (higher still if digits
    are mixed in). It's a cheap, fast first signal - not proof on its own,
    which is why the DGA detector also looks at n-gram rarity.
    """
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Levenshtein (edit) distance
# ---------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    """
    Minimum number of single-character insertions, deletions or
    substitutions needed to turn `a` into `b`.

    Used by the typosquat detector to find domains that are one or two
    edits away from a watched brand (paypa1.com vs paypal.com).
    Implemented from scratch (pure Python, O(len(a) * len(b)) time,
    O(min(len(a), len(b))) space) so the project has no dependency on a
    compiled Levenshtein package.
    """
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,        # deletion
                curr_row[j - 1] + 1,    # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------
def severity_label(score: float) -> str:
    """Map a 0-100 numeric severity score to a category used throughout the UI."""
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

SEVERITY_COLORS = {
    "Critical": "#C2453D",
    "High": "#D97A3F",
    "Medium": "#D4A94A",
    "Low": "#4A9B7F",
}
