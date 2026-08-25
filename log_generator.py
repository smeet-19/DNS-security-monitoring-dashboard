"""
log_generator.py
=================
Synthetic DNS query log generator for the DNS Security Monitoring Dashboard.

Produces a CSV of DNS query events mixing realistic benign traffic with
eight injected attack/anomaly scenarios - one per detector in detectors.py:

    Scenario              Detector responsible       ground_truth_label
    -----------------------------------------------------------------------
    Benign browsing        (baseline)                   "benign"
    DGA malware             DGA detector                  "dga"
    DNS tunneling            Tunneling detector             "tunneling"
    C2 beaconing              Beaconing detector               "beaconing"
    Subdomain recon            NXDOMAIN spike detector            "nxdomain_flood"
    Typosquat phishing           Typosquat detector                   "typosquat"
    Fast-flux C2 proxy              Fast-flux detector                     "fast_flux"
    Encrypted-DNS (DoH) evasion       DoH-evasion detector                     "doh_evasion"
    Freshly-registered lookalike        Newly-registered-domain detector           "newly_registered"

IMPORTANT: the ground_truth_label column exists ONLY because this data is
synthetic. Detectors never read it - they only ever see the columns a real
DNS log would have. The label is used exclusively by evaluate.py, after the
fact, to score how well the detectors did.

Realism note: every domain gets a STABLE, cached pool of 1-3 answer IPs and
a stable simulated "registration age" the first time it's seen, instead of
re-rolling a brand new random IP on every single query. Real DNS behaves
this way (a domain doesn't get a fresh random IP on every lookup) - and
without this, *every* domain would look like fast-flux by accident, which
would make the fast-flux detector meaningless.

Run directly:
    python log_generator.py --output data/dns_log_synthetic.csv --hours 18
"""

import argparse
import csv
import ipaddress
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

from common import BRAND_WATCHLIST, KNOWN_DOH_PROVIDERS

# ---------------------------------------------------------------------------
# Reference / scenario data
# ---------------------------------------------------------------------------

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "microsoft.com", "office.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "amazon.com", "apple.com",
    "cloudflare.com", "linkedin.com", "slack.com", "zoom.us", "dropbox.com",
    "netflix.com", "spotify.com", "adobe.com", "salesforce.com", "notion.so",
    "atlassian.com", "gmail.com", "outlook.com", "reddit.com", "twitter.com",
    "npmjs.com", "python.org", "docker.com", "ubuntu.com", "mozilla.org",
    "wordpress.com",
]

# Realistic single-edit-distance lookalikes of common phishing targets.
# Order matches BRAND_WATCHLIST in common.py so the pairing is obvious.
TYPOSQUAT_DOMAINS = [
    "gooogle.com", "paypa1.com", "micr0soft.com", "appie.com", "amaz0n.com",
    "facebo0k.com", "githup.com", "nettflix.com", "chace.com", "dropb0x.com",
]
assert len(TYPOSQUAT_DOMAINS) == len(BRAND_WATCHLIST)

RECON_TARGET_DOMAIN = "corp-internal-target.com"
SUBDOMAIN_WORDLIST = [
    "admin", "dev", "test", "staging", "vpn", "vpn1", "vpn2", "mail",
    "mail2", "ftp", "ftp-old", "backup", "db", "db1", "internal", "api",
    "api-v1", "api-v2", "portal", "intranet", "git", "jenkins", "ci",
    "sso", "auth", "webmail", "remote", "citrix", "owa", "exchange",
]

TUNNEL_C2_DOMAIN = "assets.cdn-edge-sync.net"
BEACON_C2_DOMAIN = "telemetry.svc-update-check.com"
FASTFLUX_DOMAIN = "cdn-relay-pool.net"
# Deliberately unremarkable/business-sounding - nothing about the NAME is
# suspicious. The only thing wrong with this one is *when it was
# registered*, to prove domain-age is a genuinely independent signal rather
# than just repeating what the other detectors already catch.
NRD_LOOKALIKE_DOMAIN = "quarterly-review-portal.com"

DGA_TLDS = [".com", ".net", ".info", ".biz", ".xyz", ".top", ".click"]

QUERY_TYPES_BENIGN = (
    ["A"] * 65 + ["AAAA"] * 15 + ["CNAME"] * 10 + ["MX"] * 5
    + ["TXT"] * 3 + ["NS"] * 2
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def fake_public_ip(rng: random.Random) -> str:
    """A syntactically valid, globally-routable-looking IPv4 address."""
    while True:
        candidate = ipaddress.IPv4Address(rng.randint(1, 0xFFFFFFFF - 1))
        if candidate.is_global:
            return str(candidate)


def cached_ips(domain, rng: random.Random, cache: dict, pool_size=(1, 3)):
    """Stable, small pool of answer IPs for a domain, generated once and
    reused - real domains resolve to (roughly) the same small IP set every
    time, they don't get a brand new address on every lookup."""
    if domain not in cache:
        n = rng.randint(*pool_size)
        cache[domain] = [fake_public_ip(rng) for _ in range(n)]
    return cache[domain]


def cached_age(domain, rng: random.Random, cache: dict, age_range=(365, 4380)):
    """Stable simulated 'days since this domain was registered', generated
    once per domain and reused. SIMULATED - see the note in detectors.py's
    detect_newly_registered_domain() about swapping this for a real
    WHOIS/RDAP lookup in production."""
    if domain not in cache:
        cache[domain] = rng.randint(*age_range)
    return cache[domain]


def make_event(t, src_ip, query_name, qtype, rcode, rip, ttl, label, domain_age=None):
    """Build one CSV row as a dict. query_size_bytes is a rough estimate of
    wire size (12-byte header + encoded qname + 4 bytes qtype/qclass) - close
    enough for volumetric analysis, not a byte-exact DNS wire encoding."""
    size = 12 + len(query_name) + 5
    return {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        "src_ip": src_ip,
        "query_name": query_name,
        "query_type": qtype,
        "response_code": rcode,
        "response_ip": rip,
        "ttl": ttl,
        "query_size_bytes": size,
        "first_registered_days_ago": "" if domain_age is None else domain_age,
        "ground_truth_label": label,
    }


def _span_seconds(start_time, end_time) -> float:
    return max((end_time - start_time).total_seconds(), 1.0)


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def generate_benign_traffic(hosts, start_time, end_time, rng, ip_cache, age_cache):
    """Everyday browsing: each host queries a handful of common domains every
    few minutes, almost always resolving cleanly to a small stable IP pool,
    occasionally hitting a stale/mistyped domain (real networks are never
    100% clean)."""
    events = []
    for host in hosts:
        t = start_time + timedelta(seconds=rng.uniform(0, 300))
        while t < end_time:
            domain = rng.choice(BENIGN_DOMAINS)
            qtype = rng.choice(QUERY_TYPES_BENIGN)
            resolves = rng.random() > 0.02
            if resolves:
                rcode = "NOERROR"
                rip = rng.choice(cached_ips(domain, rng, ip_cache))
                ttl = rng.choice([300, 600, 1800, 3600, 14400, 86400])
                age = cached_age(domain, rng, age_cache)
            else:
                rcode, rip, ttl, age = rng.choice(["NXDOMAIN", "SERVFAIL"]), "", 0, None
            events.append(make_event(t, host, domain, qtype, rcode, rip, ttl, "benign", age))
            t += timedelta(minutes=rng.uniform(2, 12))
    return events


def random_dga_label(rng: random.Random) -> str:
    """Generate one algorithmically-generated-looking domain label. Mixes two
    common real-world DGA styles: pure random alphanumeric (hash-like), and
    consonant/vowel-alternating 'pronounceable' strings (used by DGA families
    that try to look slightly less suspicious)."""
    length = rng.randint(8, 20)
    if rng.random() < 0.3:
        consonants, vowels = "bcdfghjklmnpqrstvwxyz", "aeiou"
        return "".join(
            rng.choice(consonants) if i % 2 == 0 else rng.choice(vowels)
            for i in range(length)
        )
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_dga_traffic(host, start_time, end_time, rng, ip_cache, age_cache, n_bursts=3):
    """Simulates DGA malware: several bursts through the day, each one
    generating dozens of candidate C2 domains. Almost all are unregistered
    (NXDOMAIN, no meaningful registration age) - only the one the attacker
    actually stood up that day resolves, and gets a freshly-registered age
    plus a low TTL mimicking fast-flux-adjacent infrastructure."""
    events = []
    for _ in range(n_bursts):
        burst_start = start_time + timedelta(seconds=rng.uniform(0, _span_seconds(start_time, end_time)))
        n_domains = rng.randint(40, 90)
        t = burst_start
        for i in range(n_domains):
            domain = random_dga_label(rng) + rng.choice(DGA_TLDS)
            is_live_c2 = (i == n_domains - 1)
            if is_live_c2:
                rip = cached_ips(domain, rng, ip_cache, pool_size=(1, 1))[0]
                rcode, ttl = "NOERROR", rng.choice([60, 120, 300])
                age = cached_age(domain, rng, age_cache, age_range=(0, 5))
            else:
                rcode, rip, ttl, age = "NXDOMAIN", "", 0, None
            events.append(make_event(t, host, domain, "A", rcode, rip, ttl, "dga", age))
            t += timedelta(seconds=rng.uniform(0.5, 4))
    return events


def generate_tunneling_traffic(host, start_time, end_time, rng, ip_cache, age_cache, n_sessions=2):
    """Simulates DNS tunneling: long, high-entropy subdomain labels (encoded
    data chunks) queried rapidly against a single attacker-controlled domain,
    skewed towards TXT/NULL record types which carry more payload per
    response than a bare A record."""
    events = []
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"  # base32-ish charset
    c2_ip = cached_ips(TUNNEL_C2_DOMAIN, rng, ip_cache, pool_size=(1, 1))[0]
    age = cached_age(TUNNEL_C2_DOMAIN, rng, age_cache, age_range=(0, 5))
    for _ in range(n_sessions):
        session_start = start_time + timedelta(
            seconds=rng.uniform(0, _span_seconds(start_time, end_time) * 0.8)
        )
        n_queries = rng.randint(150, 400)
        t = session_start
        for _ in range(n_queries):
            chunk = "".join(rng.choice(alphabet) for _ in range(rng.randint(32, 63)))
            domain = f"{chunk}.{TUNNEL_C2_DOMAIN}"
            qtype = rng.choices(["TXT", "NULL", "A"], weights=[55, 30, 15])[0]
            rip = c2_ip if qtype == "A" else ""
            events.append(make_event(t, host, domain, qtype, "NOERROR", rip, rng.choice([60, 120]), "tunneling", age))
            t += timedelta(seconds=rng.uniform(0.3, 2.5))
    return events


def generate_beaconing_traffic(host, start_time, end_time, rng, ip_cache, age_cache,
                                interval_seconds=60, jitter_seconds=3):
    """Simulates C2 beaconing: one host querying one domain at a suspiciously
    regular interval - the classic 'phone home' pattern. Runs for a sub-window
    of the full capture (not all day), which is realistic and keeps it from
    dominating every chart in the dashboard."""
    events = []
    c2_ip = cached_ips(BEACON_C2_DOMAIN, rng, ip_cache, pool_size=(1, 1))[0]
    age = cached_age(BEACON_C2_DOMAIN, rng, age_cache, age_range=(0, 5))
    t = start_time
    while t < end_time:
        events.append(make_event(t, host, BEACON_C2_DOMAIN, "A", "NOERROR", c2_ip, 120, "beaconing", age))
        t += timedelta(seconds=interval_seconds + rng.uniform(-jitter_seconds, jitter_seconds))
    return events


def generate_recon_traffic(host, start_time, end_time, rng, n_bursts=1):
    """Simulates subdomain brute-force reconnaissance against one target
    domain: a wordlist of common infra names plus random filler, fired
    rapidly, almost all NXDOMAIN. Deliberately a DIFFERENT story from DGA
    (single target domain, dictionary-flavoured labels, one short burst) so
    the NXDOMAIN-spike detector earns its place instead of re-detecting DGA."""
    events = []
    for _ in range(n_bursts):
        t = start_time + timedelta(seconds=rng.uniform(0, _span_seconds(start_time, end_time)))
        prefixes = list(SUBDOMAIN_WORDLIST)
        n_random = rng.randint(60, 150)
        prefixes += [
            "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 8)))
            for _ in range(n_random)
        ]
        rng.shuffle(prefixes)
        for prefix in prefixes:
            domain = f"{prefix}.{RECON_TARGET_DOMAIN}"
            events.append(make_event(t, host, domain, "A", "NXDOMAIN", "", 0, "nxdomain_flood"))
            t += timedelta(seconds=rng.uniform(0.2, 1.2))
    return events


def generate_typosquat_traffic(host, start_time, end_time, rng, ip_cache, age_cache, n_hits=None):
    """Simulates a user (or malware) hitting a handful of lookalike brand
    domains - low volume by design, since real typosquat visits are sparse
    events, not floods. Each lookalike is registered recently, same as real
    phishing infrastructure."""
    events = []
    n_hits = n_hits or rng.randint(4, 10)
    for _ in range(n_hits):
        t = start_time + timedelta(seconds=rng.uniform(0, _span_seconds(start_time, end_time)))
        domain = rng.choice(TYPOSQUAT_DOMAINS)
        rip = rng.choice(cached_ips(domain, rng, ip_cache, pool_size=(1, 2)))
        age = cached_age(domain, rng, age_cache, age_range=(0, 5))
        events.append(make_event(t, host, domain, "A", "NOERROR", rip, rng.choice([60, 300]), "typosquat", age))
    return events


def generate_fastflux_traffic(host, start_time, end_time, rng, age_cache, n_queries=(120, 220)):
    """Simulates a fast-flux C2 front-end: the SAME domain resolves to a
    DIFFERENT IP on almost every single lookup (deliberately bypasses
    cached_ips - that's the entire point of fast flux), backed by a very
    short TTL so resolvers keep coming back for a fresh answer. See MITRE
    ATT&CK T1568.001."""
    events = []
    n = rng.randint(*n_queries)
    age = cached_age(FASTFLUX_DOMAIN, rng, age_cache, age_range=(0, 5))
    t = start_time + timedelta(seconds=rng.uniform(0, _span_seconds(start_time, end_time) * 0.7))
    for _ in range(n):
        rip = fake_public_ip(rng)  # intentionally NOT cached - a new IP almost every time
        ttl = rng.choice([60, 90, 120])
        events.append(make_event(t, host, FASTFLUX_DOMAIN, "A", "NOERROR", rip, ttl, "fast_flux", age))
        t += timedelta(seconds=rng.uniform(20, 90))
    return events


def generate_doh_traffic(host, start_time, end_time, rng, ip_cache, age_cache, n_queries=(4, 10)):
    """Simulates a host resolving one or two well-known public DoH
    (DNS-over-HTTPS) providers. This is a visibility-evasion signal, not
    inherently malicious - real DoH providers are real, long-established
    domains, so (unlike every other 'attacker' scenario here) this one
    correctly does NOT get a freshly-registered age."""
    events = []
    providers = rng.sample(KNOWN_DOH_PROVIDERS, k=rng.randint(1, 2))
    n = rng.randint(*n_queries)
    for _ in range(n):
        t = start_time + timedelta(seconds=rng.uniform(0, _span_seconds(start_time, end_time)))
        domain = rng.choice(providers)
        rip = rng.choice(cached_ips(domain, rng, ip_cache, pool_size=(1, 2)))
        age = cached_age(domain, rng, age_cache)  # default old range - these ARE legitimate, established domains
        events.append(make_event(t, host, domain, "A", "NOERROR", rip, rng.choice([300, 1800]), "doh_evasion", age))
    return events


def generate_nrd_traffic(host, start_time, end_time, rng, ip_cache, age_cache, n_queries=(10, 25)):
    """Simulates a host visiting a domain that looks completely unremarkable
    in every way EXCEPT that (per simulated registration data) it was
    registered a few days ago. Proves domain-age is a genuinely independent
    signal, not just a restatement of something the other detectors would
    already catch (no unusual entropy, no beaconing regularity, no typo
    pattern, no high volume)."""
    events = []
    n = rng.randint(*n_queries)
    age = cached_age(NRD_LOOKALIKE_DOMAIN, rng, age_cache, age_range=(0, 5))
    t = start_time + timedelta(seconds=rng.uniform(0, 600))
    for _ in range(n):
        rip = rng.choice(cached_ips(NRD_LOOKALIKE_DOMAIN, rng, ip_cache, pool_size=(1, 2)))
        qtype = rng.choice(["A", "A", "A", "AAAA", "CNAME"])
        events.append(make_event(t, host, NRD_LOOKALIKE_DOMAIN, qtype, "NOERROR", rip,
                                  rng.choice([300, 3600]), "newly_registered", age))
        t += timedelta(minutes=rng.uniform(5, 40))
        if t >= end_time:
            break
    return events


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

SPECIAL_ROLES = [
    "dga_host", "tunnel_host", "beacon_host", "recon_host", "typo_host",
    "fastflux_host", "doh_host", "nrd_host",
]


def generate_dataset(hours=18, num_benign_hosts=22, seed=42, out_path="data/dns_log_synthetic.csv"):
    rng = random.Random(seed)
    end_time = datetime.now().replace(microsecond=0)
    start_time = end_time - timedelta(hours=hours)

    all_hosts = [f"192.168.1.{i}" for i in range(10, 10 + num_benign_hosts + len(SPECIAL_ROLES))]
    rng.shuffle(all_hosts)
    benign_hosts = all_hosts[:num_benign_hosts]
    special = dict(zip(SPECIAL_ROLES, all_hosts[num_benign_hosts:num_benign_hosts + len(SPECIAL_ROLES)]))

    ip_cache, age_cache = {}, {}

    events = []
    # Background browsing for the clean hosts...
    events += generate_benign_traffic(benign_hosts, start_time, end_time, rng, ip_cache, age_cache)
    # ...and for every compromised/special host too - a real interesting
    # machine still does normal browsing alongside its notable traffic.
    events += generate_benign_traffic(list(special.values()), start_time, end_time, rng, ip_cache, age_cache)

    events += generate_dga_traffic(special["dga_host"], start_time, end_time, rng, ip_cache, age_cache)
    events += generate_tunneling_traffic(special["tunnel_host"], start_time, end_time, rng, ip_cache, age_cache)

    beacon_start = start_time + timedelta(hours=rng.uniform(0, max(1, hours - 6)))
    beacon_end = min(beacon_start + timedelta(hours=rng.uniform(4, 8)), end_time)
    events += generate_beaconing_traffic(special["beacon_host"], beacon_start, beacon_end, rng, ip_cache, age_cache)

    events += generate_recon_traffic(special["recon_host"], start_time, end_time, rng)
    events += generate_typosquat_traffic(special["typo_host"], start_time, end_time, rng, ip_cache, age_cache)
    events += generate_fastflux_traffic(special["fastflux_host"], start_time, end_time, rng, age_cache)
    events += generate_doh_traffic(special["doh_host"], start_time, end_time, rng, ip_cache, age_cache)
    events += generate_nrd_traffic(special["nrd_host"], start_time, end_time, rng, ip_cache, age_cache)

    events.sort(key=lambda e: e["timestamp"])

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp", "src_ip", "query_name", "query_type", "response_code",
        "response_ip", "ttl", "query_size_bytes", "first_registered_days_ago",
        "ground_truth_label",
    ]
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    return out_path, len(events), special


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic DNS query log for the DNS Security Monitoring Dashboard.")
    parser.add_argument("--output", default="data/dns_log_synthetic.csv", help="output CSV path")
    parser.add_argument("--hours", type=int, default=18, help="length of the simulated capture window")
    parser.add_argument("--hosts", type=int, default=22, help="number of purely-benign internal hosts")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed, for reproducible demo data")
    args = parser.parse_args()

    out_path, n, roles = generate_dataset(hours=args.hours, num_benign_hosts=args.hosts, seed=args.seed, out_path=args.output)
    print(f"Wrote {n} DNS query events to {out_path}")
    print("Injected attacker/compromised hosts (for your own reference while testing):")
    for role, ip in roles.items():
        print(f"  {role:14s} -> {ip}")


if __name__ == "__main__":
    main()
