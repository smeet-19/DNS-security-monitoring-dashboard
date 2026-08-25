"""
detectors.py
============
Five DNS-based threat detectors. Each one takes the normalized DataFrame
produced by log_parser.load_log() and returns an "alerts" DataFrame with a
consistent schema:

    alert_id          str    e.g. "ALT-0001" (assigned after all detectors
                                run and results are merged + sorted)
    timestamp          Timestamp  representative time for the alert (usually
                                    the last event that contributed to it)
    detector             str    "dga" | "tunneling" | "beaconing" |
                                  "nxdomain_spike" | "typosquat"
    severity_score          float  0-100
    severity_label            str    "Low" | "Medium" | "High" | "Critical"
    src_ip                      str    one IP, or several joined with ";"
    domain                        str    the flagged domain (or, for
                                            nxdomain_spike, a few sample
                                            domains joined with ";")
    reason                          str    short human-readable explanation
    mitre_id                          str    e.g. "T1568.002"
    mitre_name                          str    looked up from common.py
    evidence                              str    JSON blob of the raw metrics
                                                    behind the score, for the
                                                    Domain Detail page

No detector ever imports from log_generator.py - they only ever see the
columns a real DNS log would have. Detection has to work purely from
statistical/behavioural signal, the same as it would on a real network.

Design note: thresholds below were tuned empirically against
log_generator.py's synthetic traffic (see evaluate.py) to get every injected
scenario caught with a low false-positive rate on benign hosts. Real traffic
will behave differently - treat these constants as a starting point to
re-tune against your own environment, not as universal truths.
"""

import json

import pandas as pd

from common import (
    BRAND_WATCHLIST,
    KNOWN_DOH_PROVIDERS,
    MITRE_TECHNIQUES,
    levenshtein,
    severity_label,
    shannon_entropy,
)

ALERT_COLUMNS = [
    "alert_id", "timestamp", "detector", "severity_score", "severity_label",
    "src_ip", "domain", "reason", "mitre_id", "mitre_name", "evidence",
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _empty_alerts() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def _alert(detector, domain, src_ip, timestamp, score, reason, mitre_id, evidence):
    score = round(float(max(0.0, min(100.0, score))), 1)
    return {
        "timestamp": timestamp,
        "detector": detector,
        "severity_score": score,
        "severity_label": severity_label(score),
        "src_ip": src_ip,
        "domain": domain,
        "reason": reason,
        "mitre_id": mitre_id,
        "mitre_name": MITRE_TECHNIQUES.get(mitre_id, ""),
        "evidence": json.dumps(evidence, default=str),
    }


def _to_df(alerts: list) -> pd.DataFrame:
    if not alerts:
        return pd.DataFrame(columns=[c for c in ALERT_COLUMNS if c != "alert_id"])
    return pd.DataFrame(alerts)


# ---------------------------------------------------------------------------
# 1. DGA detection - Shannon entropy + n-gram (bigram) rarity
# ---------------------------------------------------------------------------
# Reference vocabulary used to decide which letter-pairs "look English".
# Mixes everyday function words with common tech/brand vocabulary, since
# that's what legitimate domains are usually built from.
_REFERENCE_WORDS = [
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "her",
    "was", "one", "our", "out", "day", "get", "has", "him", "his", "how",
    "new", "now", "old", "see", "two", "way", "who", "did", "its", "let",
    "put", "say", "she", "too", "use", "google", "microsoft", "amazon",
    "facebook", "apple", "github", "office", "cloud", "service", "account",
    "secure", "login", "mail", "support", "update", "system", "network",
    "server", "client", "admin", "portal", "internal", "backup", "storage",
    "stream", "video", "photo", "share", "drive", "docs", "sheet", "slide",
    "search", "browser", "mobile", "download", "upload", "content", "media",
    "player", "shop", "store", "payment", "bank", "finance", "invoice",
    "order", "delivery", "news", "weather", "sports", "travel", "hotel",
    "flight", "booking", "ticket", "social", "friend", "message", "chat",
    "group", "event", "calendar", "meeting", "project", "team", "task",
    "report", "dashboard", "monitor", "alert", "status",
]


def _build_common_bigrams(words):
    bigrams = set()
    for w in words:
        for i in range(len(w) - 1):
            bigrams.add(w[i:i + 2])
    return bigrams


_COMMON_BIGRAMS = _build_common_bigrams(_REFERENCE_WORDS)


def _rare_bigram_ratio(label: str) -> float:
    """Fraction of the label's letter-pairs that never appear in the
    reference vocabulary. High for algorithmically-generated strings.
    Computed per hyphen-separated segment (not across hyphen boundaries) -
    otherwise any hyphenated compound name gets penalized just because no
    reference word contains a literal hyphen, which isn't a meaningful
    signal (see the hyphen discount in detect_dga below for why)."""
    segments = [seg for seg in label.split("-") if len(seg) >= 2]
    if not segments:
        return 0.0
    total, rare = 0, 0
    for seg in segments:
        bigrams = [seg[i:i + 2] for i in range(len(seg) - 1)]
        total += len(bigrams)
        rare += sum(1 for bg in bigrams if bg not in _COMMON_BIGRAMS)
    return rare / total if total else 0.0


def detect_dga(df: pd.DataFrame, min_label_len: int = 6, score_threshold: float = 45.0) -> pd.DataFrame:
    """Flags registrable domains whose second-level label looks
    algorithmically generated: high character-entropy, mostly-unseen letter
    pairs, and (secondarily) a high digit ratio."""
    if df.empty:
        return _empty_alerts()

    grouped = df.groupby("registrable_domain").agg(
        n_queries=("timestamp", "count"),
        last_seen=("timestamp", "max"),
        hosts=("src_ip", lambda s: sorted(set(s))),
        nxdomain_ratio=("response_code", lambda s: (s == "NXDOMAIN").mean()),
    ).reset_index()

    alerts = []
    for _, row in grouped.iterrows():
        domain = row["registrable_domain"]
        if not domain:
            continue
        label = domain.split(".")[0]
        if len(label) < min_label_len:
            continue

        ent = shannon_entropy(label)
        rare_ratio = _rare_bigram_ratio(label)
        digit_ratio = sum(ch.isdigit() for ch in label) / len(label)
        norm_entropy = min(ent / 5.17, 1.0)  # log2(36) ~= 5.17 bits/char ceiling for [a-z0-9]

        score = 100 * (0.45 * norm_entropy + 0.40 * rare_ratio + 0.15 * digit_ratio)
        if "-" in label:
            # Real DGA output is almost always one contiguous alphanumeric
            # string - genuine DGA malware doesn't hyphenate its generated
            # labels. A hyphen is mild evidence AGAINST classic DGA, even if
            # the individual word segments still look somewhat unusual.
            score *= 0.7
        if score < score_threshold:
            continue

        reason = (
            f"Label '{label}' looks algorithmically generated: entropy "
            f"{ent:.2f} bits/char, {rare_ratio * 100:.0f}% of letter-pairs "
            f"are uncommon in English, {digit_ratio * 100:.0f}% digits."
        )
        alerts.append(_alert(
            detector="dga", domain=domain, src_ip=";".join(row["hosts"][:5]),
            timestamp=row["last_seen"], score=score, reason=reason,
            mitre_id="T1568.002",
            evidence={
                "entropy_bits_per_char": round(ent, 2),
                "rare_bigram_ratio": round(rare_ratio, 2),
                "digit_ratio": round(digit_ratio, 2),
                "n_queries": int(row["n_queries"]),
                "nxdomain_ratio": round(float(row["nxdomain_ratio"]), 2),
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 2. DNS tunneling detection
# ---------------------------------------------------------------------------

def detect_tunneling(df: pd.DataFrame, min_queries: int = 20, score_threshold: float = 45.0) -> pd.DataFrame:
    """Flags (host, domain) pairs where the query pattern looks like data is
    being smuggled through subdomain labels: long, high-entropy, almost
    always-unique labels, a heavy TXT/NULL skew, and a high query rate."""
    if df.empty:
        return _empty_alerts()

    candidates = df[df["subdomain_label_count"] > 0]
    if candidates.empty:
        return _empty_alerts()

    alerts = []
    for (src_ip, domain), grp in candidates.groupby(["src_ip", "registrable_domain"]):
        n = len(grp)
        if n < min_queries:
            continue

        avg_len = grp["subdomain_len"].mean()
        txt_null_ratio = grp["query_type"].isin(["TXT", "NULL"]).mean()
        duration_min = max((grp["timestamp"].max() - grp["timestamp"].min()).total_seconds() / 60.0, 1 / 60)
        rate = n / duration_min
        unique_ratio = grp["subdomain"].nunique() / n
        avg_entropy = grp["subdomain"].apply(lambda s: shannon_entropy(s.replace(".", ""))).mean()

        length_score = min(avg_len / 50.0, 1.0)
        rate_score = min(rate / 10.0, 1.0)
        entropy_score = min(avg_entropy / 4.5, 1.0)

        score = 100 * (
            0.25 * length_score + 0.20 * txt_null_ratio + 0.20 * rate_score
            + 0.20 * unique_ratio + 0.15 * entropy_score
        )
        if score < score_threshold:
            continue

        reason = (
            f"{n} queries to {domain} from {src_ip} in {duration_min:.1f} min "
            f"({rate:.1f}/min). Avg subdomain length {avg_len:.0f} chars, "
            f"{unique_ratio * 100:.0f}% unique labels, {txt_null_ratio * 100:.0f}% "
            f"TXT/NULL queries - consistent with data encoded into query names."
        )
        alerts.append(_alert(
            detector="tunneling", domain=domain, src_ip=src_ip,
            timestamp=grp["timestamp"].max(), score=score, reason=reason,
            mitre_id="T1071.004",
            evidence={
                "n_queries": int(n),
                "avg_subdomain_len_chars": round(float(avg_len), 1),
                "queries_per_min": round(float(rate), 2),
                "unique_label_ratio": round(float(unique_ratio), 2),
                "txt_null_ratio": round(float(txt_null_ratio), 2),
                "avg_subdomain_entropy": round(float(avg_entropy), 2),
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 3. Beaconing detection - inter-query interval regularity
# ---------------------------------------------------------------------------

def detect_beaconing(df: pd.DataFrame, min_queries: int = 6, cv_threshold: float = 0.20,
                      score_threshold: float = 50.0) -> pd.DataFrame:
    """Flags (host, domain) pairs queried at a suspiciously regular cadence -
    a low coefficient of variation (std/mean) on inter-query intervals is the
    signature of an automated check-in loop rather than human browsing."""
    if df.empty:
        return _empty_alerts()

    alerts = []
    for (src_ip, domain), grp in df.groupby(["src_ip", "query_name"]):
        n = len(grp)
        if n < min_queries:
            continue

        ts = grp["timestamp"].sort_values()
        intervals = ts.diff().dropna().dt.total_seconds()
        if intervals.empty or intervals.mean() <= 0:
            continue

        mean_iv, std_iv = float(intervals.mean()), float(intervals.std(ddof=0))
        cv = std_iv / mean_iv if mean_iv else 1.0
        if cv > cv_threshold:
            continue

        regularity_score = max(0.0, 1 - (cv / cv_threshold))
        count_score = min(n / 50.0, 1.0)
        score = 100 * (0.7 * regularity_score + 0.3 * count_score)
        if score < score_threshold:
            continue

        reason = (
            f"{src_ip} queried {domain} {n} times at highly regular "
            f"~{mean_iv:.0f}s intervals (\u00b1{std_iv:.1f}s, CV={cv:.2f}) - "
            f"a classic automated check-in rhythm. Note: some legitimate "
            f"background services (mail sync, update checkers) also poll on "
            f"a fixed schedule, so corroborate with destination reputation "
            f"before treating this as confirmed C2."
        )
        alerts.append(_alert(
            detector="beaconing", domain=domain, src_ip=src_ip,
            timestamp=grp["timestamp"].max(), score=score, reason=reason,
            mitre_id="T1071.004",
            evidence={
                "n_queries": int(n),
                "mean_interval_sec": round(mean_iv, 1),
                "std_interval_sec": round(std_iv, 2),
                "coefficient_of_variation": round(cv, 3),
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 4. NXDOMAIN spike detection - sliding window per host
# ---------------------------------------------------------------------------

def detect_nxdomain_spike(df: pd.DataFrame, window_minutes: float = 5.0, count_threshold: int = 20,
                           min_total: int = 10) -> pd.DataFrame:
    """Flags hosts producing a burst of NXDOMAIN responses within a short
    sliding window - the signature of either DGA malware churning through
    unregistered candidate domains, or a host brute-forcing subdomains for
    reconnaissance. (Which of the two it is shows up in the *shape* of the
    failed names - dictionary-like prefixes against one target domain
    suggests recon; scattered high-entropy names across many TLDs suggests
    DGA - worth eyeballing in the Domain Detail page.)"""
    if df.empty:
        return _empty_alerts()

    nx = df[df["response_code"] == "NXDOMAIN"]
    if nx.empty:
        return _empty_alerts()

    window = pd.Timedelta(minutes=window_minutes)
    alerts = []
    for src_ip, grp in nx.groupby("src_ip"):
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        n = len(grp)
        if n < min_total:
            continue

        # two-pointer sliding window: largest number of NXDOMAIN events from
        # this host inside any `window_minutes`-wide slice of the capture
        left, max_count, max_left, max_right = 0, 0, 0, 0
        for right in range(n):
            while grp["timestamp"].iloc[right] - grp["timestamp"].iloc[left] > window:
                left += 1
            count = right - left + 1
            if count > max_count:
                max_count, max_left, max_right = count, left, right
        if max_count < count_threshold:
            continue

        host_total = int((df["src_ip"] == src_ip).sum())
        ratio = n / host_total if host_total else 0.0
        window_end = grp["timestamp"].iloc[max_right]
        # sample names from *inside the flagged burst window only* - pulling
        # from the host's whole-day NXDOMAIN history here would risk
        # surfacing an unrelated benign domain that coincidentally tied on
        # count, which would make the alert's evidence misleading.
        window_slice = grp.iloc[max_left:max_right + 1]
        top_domains = window_slice["query_name"].value_counts().head(3).index.tolist()

        score = 100 * min(1.0, 0.6 * (max_count / (count_threshold * 2)) + 0.4 * ratio)

        reason = (
            f"{max_count} NXDOMAIN responses from {src_ip} within a "
            f"{window_minutes:.0f}-minute window ({ratio * 100:.0f}% of all its "
            f"queries never resolved). Sample failed lookups: {', '.join(top_domains)}."
        )
        alerts.append(_alert(
            detector="nxdomain_spike", domain=";".join(top_domains), src_ip=src_ip,
            timestamp=window_end, score=score, reason=reason,
            mitre_id="T1590.002",
            evidence={
                "max_nxdomain_in_window": int(max_count),
                "window_minutes": window_minutes,
                "host_nxdomain_ratio": round(float(ratio), 2),
                "total_nxdomain_events": n,
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 5. Typosquat detection - Levenshtein distance to a brand watchlist
# ---------------------------------------------------------------------------

def detect_typosquatting(df: pd.DataFrame, max_distance: int = 2) -> pd.DataFrame:
    """Flags queried domains that are 1-2 character edits away from a
    watched brand domain but aren't an exact match - the classic
    typosquat/phishing-infrastructure pattern."""
    if df.empty:
        return _empty_alerts()

    watchlist = set(BRAND_WATCHLIST)
    domains = [d for d in df["registrable_domain"].dropna().unique() if d and len(d) >= 4]

    alerts = []
    for domain in domains:
        if domain in watchlist:
            continue
        best_brand, best_dist = None, None
        for brand in BRAND_WATCHLIST:
            if abs(len(domain) - len(brand)) > max_distance + 1:
                continue  # cheap pre-filter before the O(n*m) edit-distance call
            d = levenshtein(domain, brand)
            if best_dist is None or d < best_dist:
                best_dist, best_brand = d, brand

        if best_dist is None or not (0 < best_dist <= max_distance):
            continue

        grp = df[df["registrable_domain"] == domain]
        hosts = sorted(grp["src_ip"].unique())
        score = 92 - (best_dist - 1) * 24  # distance 1 -> 92 (Critical), distance 2 -> 68 (High)

        reason = (
            f"'{domain}' is {best_dist} character edit(s) away from watched "
            f"brand domain '{best_brand}' - classic typosquat pattern."
        )
        alerts.append(_alert(
            detector="typosquat", domain=domain, src_ip=";".join(hosts[:5]),
            timestamp=grp["timestamp"].max(), score=score, reason=reason,
            mitre_id="T1583.001",
            evidence={
                "edit_distance": int(best_dist),
                "matched_brand": best_brand,
                "n_queries": int(len(grp)),
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 6. Fast-flux DNS detection (MITRE ATT&CK T1568.001)
# ---------------------------------------------------------------------------

def detect_fast_flux(df: pd.DataFrame, min_resolved: int = 8, min_distinct_ips: int = 4,
                      score_threshold: float = 45.0) -> pd.DataFrame:
    """Flags domains resolving to an unusually high number of DISTINCT IPs
    combined with a short TTL - the signature of a fast-flux front-end layer
    rotating IPs to resist takedown/blocklisting (real-world examples:
    Storm Worm, various ransomware C2). A domain simply having 2-3 answer
    IPs is normal (round-robin load balancing, CDNs) - fast flux is
    distinguished by a HIGH ratio of unique IPs to lookups, sustained over
    many queries, usually paired with TTLs under a few minutes so resolvers
    are forced to keep re-querying."""
    if df.empty:
        return _empty_alerts()

    resolved = df[(df["response_code"] == "NOERROR") & (df["response_ip"] != "")]
    if resolved.empty:
        return _empty_alerts()

    alerts = []
    for domain, grp in resolved.groupby("registrable_domain"):
        n = len(grp)
        if n < min_resolved:
            continue
        distinct_ips = grp["response_ip"].nunique()
        if distinct_ips < min_distinct_ips:
            continue

        ip_ratio = distinct_ips / n
        avg_ttl = float(pd.to_numeric(grp["ttl"], errors="coerce").fillna(0).mean())

        ip_score = min(ip_ratio * 1.5, 1.0)
        ttl_score = 1.0 if avg_ttl <= 300 else max(0.0, 1 - (avg_ttl - 300) / 3600)
        volume_score = min(distinct_ips / 10.0, 1.0)

        score = 100 * (0.40 * ip_score + 0.30 * ttl_score + 0.30 * volume_score)
        if score < score_threshold:
            continue

        hosts = sorted(grp["src_ip"].unique())
        reason = (
            f"{domain} resolved to {distinct_ips} different IPs across {n} lookups "
            f"(avg TTL {avg_ttl:.0f}s) - consistent with a fast-flux proxy layer "
            f"rotating front-end IPs to resist takedown/blocklisting."
        )
        alerts.append(_alert(
            detector="fast_flux", domain=domain, src_ip=";".join(hosts[:5]),
            timestamp=grp["timestamp"].max(), score=score, reason=reason,
            mitre_id="T1568.001",
            evidence={
                "distinct_ips": int(distinct_ips),
                "n_resolved_queries": int(n),
                "unique_ip_ratio": round(float(ip_ratio), 2),
                "avg_ttl_sec": round(avg_ttl, 1),
            },
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 7. Newly-registered-domain (NRD) risk detection (MITRE ATT&CK T1583.001)
# ---------------------------------------------------------------------------

def detect_newly_registered_domain(df: pd.DataFrame, max_age_days: float = 7.0,
                                    score_threshold: float = 40.0) -> pd.DataFrame:
    """Flags domains that (per registration-date data) were created very
    recently and are already being queried from inside the network.
    Legitimate services are almost never adopted within days of the domain
    itself being registered, so this is a strong, well-established signal
    in real threat intel feeds (often called 'Newly Observed/Registered
    Domains' or NRD scoring).

    IMPORTANT: 'first_registered_days_ago' is SIMULATED in this project's
    synthetic data (see log_generator.py's cached_age()) because real
    WHOIS/RDAP lookups need internet access this environment doesn't have.
    In production, replace the column with a real lookup - e.g. the `whois`
    PyPI package, an RDAP client, or a commercial newly-observed-domains
    feed - everything downstream of that column is unchanged."""
    if df.empty or "first_registered_days_ago" not in df.columns:
        return _empty_alerts()

    candidates = df.dropna(subset=["first_registered_days_ago"])
    if candidates.empty:
        return _empty_alerts()

    grouped = candidates.groupby("registrable_domain").agg(
        age_days=("first_registered_days_ago", "first"),
        n_queries=("timestamp", "count"),
        last_seen=("timestamp", "max"),
        hosts=("src_ip", lambda s: sorted(set(s))),
    ).reset_index()

    alerts = []
    for _, row in grouped.iterrows():
        age = float(row["age_days"])
        if age > max_age_days:
            continue

        freshness_score = 1 - (age / max_age_days)
        volume_score = min(int(row["n_queries"]) / 15.0, 1.0)
        score = 100 * (0.75 * freshness_score + 0.25 * volume_score)
        if score < score_threshold:
            continue

        domain = row["registrable_domain"]
        reason = (
            f"{domain} was (per registration data) created only {age:.0f} day(s) ago "
            f"and is already being queried {int(row['n_queries'])} time(s) from inside "
            f"the network - legitimate services are rarely adopted this quickly."
        )
        alerts.append(_alert(
            detector="newly_registered", domain=domain, src_ip=";".join(row["hosts"][:5]),
            timestamp=row["last_seen"], score=score, reason=reason,
            mitre_id="T1583.001",
            evidence={"age_days": round(age, 1), "n_queries": int(row["n_queries"])},
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# 8. Encrypted-DNS (DoH/DoT) evasion detection (MITRE ATT&CK T1071.004)
# ---------------------------------------------------------------------------

def detect_doh_evasion(df: pd.DataFrame, score: float = 55.0) -> pd.DataFrame:
    """Flags hosts resolving a known public DoH (DNS-over-HTTPS) provider.
    This is a WATCHLIST check, not traffic inspection - DoH is encrypted by
    definition, so nothing downstream of the handshake is visible to a DNS
    log anyway. The signal here is narrower but still useful: a host that
    starts resolving a public DoH endpoint is a host that may be about to
    move its DNS resolution outside this network's visibility entirely.
    Not inherently malicious on its own (privacy-conscious browsers do this
    by default in some configurations) - treat this as 'worth knowing
    about', lower baseline severity than the other detectors, and easy to
    correlate with whatever else that host is doing."""
    if df.empty:
        return _empty_alerts()

    # Exact hostname match, not registrable_domain: known DoH endpoints are
    # specific hostnames (e.g. "doh.opendns.com"), and for several of them
    # that identifying label sits in the subdomain position, which
    # registrable_domain would otherwise strip off (leaving "opendns.com" -
    # too broad, since not every opendns.com subdomain is a DoH endpoint).
    hits = df[df["query_name"].isin(KNOWN_DOH_PROVIDERS)]
    if hits.empty:
        return _empty_alerts()

    alerts = []
    for src_ip, grp in hits.groupby("src_ip"):
        providers = sorted(grp["registrable_domain"].unique())
        reason = (
            f"{src_ip} resolved {len(providers)} known public DoH provider(s) "
            f"({', '.join(providers)}) - {int(len(grp))} quer{'y' if len(grp)==1 else 'ies'} total. "
            f"Traffic sent over DoH afterwards would be invisible to standard DNS logging."
        )
        alerts.append(_alert(
            detector="doh_evasion", domain=";".join(providers), src_ip=src_ip,
            timestamp=grp["timestamp"].max(), score=score, reason=reason,
            mitre_id="T1071.004",
            evidence={"providers": providers, "n_queries": int(len(grp))},
        ))
    return _to_df(alerts)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

DETECTOR_FUNCS = {
    "dga": detect_dga,
    "tunneling": detect_tunneling,
    "beaconing": detect_beaconing,
    "nxdomain_spike": detect_nxdomain_spike,
    "typosquat": detect_typosquatting,
    "fast_flux": detect_fast_flux,
    "newly_registered": detect_newly_registered_domain,
    "doh_evasion": detect_doh_evasion,
}


def run_all_detectors(df: pd.DataFrame) -> pd.DataFrame:
    """Runs every detector and returns one alerts table, highest severity
    first, with sequential SOC-ticket-style IDs (ALT-0001, ALT-0002, ...)."""
    if df is None or df.empty:
        return _empty_alerts()

    pieces = [func(df) for func in DETECTOR_FUNCS.values()]
    pieces = [p for p in pieces if p is not None and not p.empty]
    if not pieces:
        return _empty_alerts()

    alerts = pd.concat(pieces, ignore_index=True)
    alerts = alerts.sort_values("severity_score", ascending=False).reset_index(drop=True)
    alerts.insert(0, "alert_id", [f"ALT-{i + 1:04d}" for i in range(len(alerts))])
    return alerts[ALERT_COLUMNS]


if __name__ == "__main__":
    import sys
    from log_parser import load_log

    path = sys.argv[1] if len(sys.argv) > 1 else "data/dns_log_synthetic.csv"
    events = load_log(path)
    result = run_all_detectors(events)
    print(f"{len(events)} events -> {len(result)} alerts")
    if not result.empty:
        print(result["detector"].value_counts())
        print()
        print(result.drop(columns=["evidence"]).head(15).to_string())
