# DNS Security Monitoring Dashboard

A DNS query-log analysis tool that flags suspicious domain-query patterns:
DGA malware, DNS tunneling, C2 beaconing, subdomain-enumeration recon,
typosquat/phishing infrastructure, fast-flux C2, encrypted-DNS (DoH)
evasion, and newly-registered-domain risk - eight detectors in total, each
scored, explained, and mapped to a real MITRE ATT&CK technique. Built for a
VAPT internship project.

Ships with a synthetic log generator so the whole pipeline is demoable
without access to real enterprise DNS logs, plus a parser that also reads
real BIND9 query logs and Zeek `dns.log`.

## Quickstart

```bash
pip install -r requirements.txt

# optional - a demo dataset is already included at data/dns_log_synthetic.csv,
# but you can regenerate it (or make a bigger/longer one) any time:
python log_generator.py --output data/dns_log_synthetic.csv --hours 18

streamlit run dashboard.py
```

Streamlit will print a local URL (usually `http://localhost:8501`) - open
it in a browser. On Windows, if the bare `streamlit` command isn't found,
use `python -m streamlit run dashboard.py` instead.

> **A note on how this was built:** this project was written and unit-tested
> in a sandboxed environment with no internet access, so `streamlit` itself
> couldn't be installed or run there. Every other piece - the log generator,
> the parser (against synthetic data **and** hand-built BIND/Zeek sample
> logs), all eight detectors, and the risk-scoring layer - was actually
> executed and checked against real output, including every number in this
> README. `dashboard.py` was validated by mocking the Streamlit API and
> running its actual page logic end-to-end against real data (so the data
> handling is exercised), but the real widgets have not been visually
> confirmed in a browser.

## Project structure

```
dns_dashboard/
├── common.py          # shared constants + small algorithms (entropy, Levenshtein,
│                       #   domain splitting, MITRE technique/tactic maps, DoH watchlist)
├── log_generator.py    # synthetic DNS log generator (benign + 8 attack scenarios)
├── log_parser.py         # loads CSV / BIND query logs / Zeek dns.log -> one schema
├── detectors.py            # the 8 detectors + run_all_detectors()
├── risk.py                   # host risk scoring, kill-chain tactic view, exec summary
├── evaluate.py                  # scores detectors against synthetic ground truth
├── dashboard.py                    # Streamlit UI (5 pages, see below)
├── requirements.txt
├── data/
│   └── dns_log_synthetic.csv          # ready-to-use demo dataset (~6,100 events)
└── sample_logs/
    ├── bind_sample.log                   # hand-built BIND query-log sample
    └── zeek_sample.log                      # hand-built Zeek dns.log sample
```

## Dashboard pages

| Page | What it's for |
|---|---|
| **Overview** | Auto-generated executive summary, top-risk hosts, traffic volume over time, top talkers/domains, response-code and detector breakdowns |
| **Alerts** | Severity-sorted, filterable alert table with icon-coded cards for the highest-priority items, CSV export |
| **Domain Detail** | Pick a domain, see its full query history and which detector(s) flagged it |
| **Host Investigation** | Pick a *host*, see its composite risk score, which real ATT&CK tactics it touched (Reconnaissance -> Resource Development -> Command and Control), and a chronological alert timeline that reads as a narrative |
| **Detector Performance** | (bundled synthetic data only) recall per injected scenario + false-positive rate, from `evaluate.py` |

## How the demo data is built

`log_generator.py` simulates an 18-hour capture window across ~30 internal
hosts. Most only ever produce ordinary browsing traffic. Eight hosts are
"compromised" or otherwise notable and, on top of their own normal
browsing, each produce one attack pattern:

| Scenario | What it looks like | Caught by | MITRE ATT&CK | Tactic |
|---|---|---|---|---|
| DGA malware | Bursts of dozens of random-looking domains, almost all NXDOMAIN | DGA detector | `T1568.002` | Command and Control |
| DNS tunneling | Long, high-entropy subdomains, TXT/NULL-heavy, one domain, high rate | Tunneling detector | `T1071.004` | Command and Control |
| C2 beaconing | One domain queried at a near-perfectly regular interval | Beaconing detector | `T1071.004` | Command and Control |
| Fast-flux C2 | One domain resolving to a new IP almost every lookup, short TTL | Fast-flux detector | `T1568.001` | Command and Control |
| Encrypted-DNS evasion | Host resolves a known public DoH provider | DoH-evasion detector | `T1071.004` | Command and Control |
| Subdomain recon | Dictionary + random prefixes brute-forced against one target domain | NXDOMAIN spike detector | `T1590.002` | Reconnaissance |
| Typosquat phishing | A handful of hits on lookalike brand domains (`paypa1.com`, etc.) | Typosquat detector | `T1583.001` | Resource Development |
| Newly-registered lookalike | Ordinary-looking domain, but (simulated) registered days ago | NRD detector | `T1583.001` | Resource Development |

Every row also carries a `ground_truth_label` column - **detectors never
read this column**, it exists purely so `evaluate.py` can score them
afterwards. Real/uploaded logs won't have this column (or the simulated
`first_registered_days_ago` column), which every module handles gracefully.

### A realism fix worth knowing about

Early on, every domain in the generator got a **freshly random answer IP on
every single query** - which is not how DNS actually behaves, and would
have made every benign domain look exactly like fast-flux by accident. Every
domain now gets a small, stable, cached pool of IPs (and a stable simulated
registration age) the first time it's seen, and reuses it - the fast-flux
scenario is the one deliberate exception, since bypassing that stability is
the entire point of fast flux.

## Detector methodology

**1. DGA detection.** Shannon entropy + a rare-bigram ratio (fraction of
letter-pairs absent from a small reference vocabulary) + digit ratio,
combined into a 0-100 score. Bigrams are computed *within* each
hyphen-separated segment of a label, not across hyphens, and a hyphenated
label gets a score discount - real DGA output is essentially always one
contiguous alphanumeric string, so a hyphen is itself mild evidence
*against* classic DGA (this was a real false-positive source caught during
testing - see Evaluation Results below).

**2. DNS tunneling detection.** Groups by `(host, registrable_domain)`,
scores on subdomain length, TXT/NULL ratio, query rate, label uniqueness,
and subdomain entropy.

**3. Beaconing detection.** Coefficient of variation (std/mean) of
inter-query intervals per `(host, domain)` - a low CV means a near-fixed
schedule, the "phone home" signature.

**4. NXDOMAIN spike detection.** Sliding-window (two-pointer) scan per host
for the densest burst of NXDOMAIN responses - framed as reconnaissance
(subdomain brute-forcing) rather than DGA, though a DGA-infected host will
often trip this too, which is a useful correlation signal.

**5. Typosquat detection.** Levenshtein distance from every queried domain
to a small brand watchlist (`common.BRAND_WATCHLIST`); 1-2 edits away, not
an exact match, gets flagged.

**6. Fast-flux detection** *(new)*. Groups by domain, flags a high ratio of
distinct answer IPs to lookups combined with a short TTL (`<=300s`) -
exactly the two signals cited in MITRE's own T1568.001 write-up and in
CISA's fast-flux advisory. A domain having 2-3 IPs is normal
(load-balancing/CDN); fast flux is the *ratio* staying high as volume grows.

**7. Newly-registered-domain (NRD) detection** *(new)*. Flags domains
(simulated) registered within the last 7 days that are already seeing
traffic. This is a genuinely independent signal from the others - proven in
this project by a dedicated scenario (`quarterly-review-portal.com`) that
is boring in *every other* respect (ordinary English words, no unusual
entropy, no beaconing regularity, low volume) and is caught *only* by its
registration age. In production, swap the simulated age for a real
WHOIS/RDAP lookup or a newly-observed-domains threat-intel feed.

**8. Encrypted-DNS (DoH) evasion detection** *(new)*. Watchlist match
against known public DoH resolver hostnames (`common.KNOWN_DOH_PROVIDERS`).
Not inherently malicious - it's a visibility gap, not proof of compromise -
so it carries a lower baseline severity and is meant to be correlated with
whatever else that host is doing (which is exactly what the Host
Investigation page is for).

### Host risk scoring & kill-chain view (`risk.py`)

Individual alerts are useful, but a SOC analyst's real question is "which
*hosts* need attention today." `risk.py` aggregates the raw alerts into:

- **Host risk score** = highest single alert's severity, +8 points for
  every *additional independent detector* that also fired on that host
  (capped at 100). One detector firing is trusted at its own severity;
  several independent detectors agreeing is stronger evidence, so it's
  boosted.
- **Kill-chain tactic view** - which real ATT&CK tactics
  (Reconnaissance -> Resource Development -> Command and Control, in
  that official order) a host's alerts touch, plus a chronological
  (not severity-sorted) timeline that reads as a narrative of what
  happened, oldest alert first.
- **Auto-generated executive summary** - a few data-driven sentences
  (not a fill-in-the-blank template) for the top of the Overview page.

## Log format support

| Format | Notes |
|---|---|
| CSV (this project's schema) | `timestamp,src_ip,query_name,query_type,response_code,response_ip,ttl,query_size_bytes,first_registered_days_ago,ground_truth_label` |
| BIND9 query logs | Parses the `queries` and `query-errors` logging categories. Plain `queries` lines don't carry a response code - only `query-errors` lines do. |
| Zeek `dns.log` | Parsed via the `#fields` header line (dynamic column mapping), already pairs query + answer + rcode in one record. |

Two hand-built sample files are included in `sample_logs/` to try the
parser without a real BIND/Zeek deployment.

## Evaluation results

From `python evaluate.py data/dns_log_synthetic.csv` against the bundled
demo dataset (seed 42, ~6,069 events, 181 alerts):

| Scenario | Detector | Ground truth | Caught | Recall |
|---|---|---|---|---|
| dga | dga | 186 domains | 159 | **85%** |
| tunneling | tunneling | 1 (host, domain) pair | 1 | **100%** |
| beaconing | beaconing | 1 (host, domain) pair | 1 | **100%** |
| nxdomain_flood | nxdomain_spike | 1 host | 1 | **100%** |
| typosquat | typosquat | 5 domains | 5 | **100%** |
| fast_flux | fast_flux | 1 (host, domain) pair | 1 | **100%** |
| newly_registered | newly_registered | 1 (host, domain) pair | 1 | **100%** |
| doh_evasion | doh_evasion | 2 (host, domain) pairs | 2 | **100%** |

**False positives: 0 of 22 purely-benign hosts** received any alert.

Notes for your report:

- **DGA recall isn't 100%, on purpose-adjacent grounds.** The generator
  mixes pure-random and "pronounceable" (consonant/vowel-alternating) DGA
  styles; the latter naturally scores lower on entropy. A purely
  statistical detector will always miss some of those - a real, documented
  limitation, and part of why production systems add ML classifiers
  trained on large labeled corpora.
- **A real bug was caught and fixed during testing, not hidden.** The DGA
  detector originally also fired on every hyphenated internal domain name
  (`cdn-relay-pool.net`, `svc-update-check.com`, etc.), because bigrams
  spanning a hyphen are automatically "rare" (no reference word contains a
  hyphen) - which would flag *any* hyphenated business domain, real or not.
  Fixed by scoring bigrams within hyphen-segments only and adding a
  hyphen discount, since genuine DGA output is never hyphenated. Worth
  mentioning in a report: catching and explaining a methodology flaw is
  more convincing than a suspiciously perfect detector.
- **The newly-registered-domain detector earns its place independently.**
  It correctly stays quiet on the dedicated NRD scenario domain until
  registration-age data is the *only* thing wrong with it, and it correctly
  cross-fires on the fast-flux and beaconing C2 domains too (they're also
  freshly "registered" in the simulated data) - multiple independent
  detectors converging on the same infrastructure for different reasons,
  which is exactly the kind of corroborating signal a real analyst wants,
  and exactly what the host risk score is designed to reward.

## Known limitations / future work

- **Public-suffix handling is simplified** (`common.split_domain` hardcodes
  a short multi-label-TLD list instead of a full Public Suffix List; swap
  in `tldextract` for production).
- **The DGA bigram reference vocabulary is small (~90 words) and
  English-centric** - legitimate but unusual brand names may still score
  higher than they should. A production version would derive this from a
  large corpus (e.g. the Tranco top 1M).
- **Domain age is simulated, not looked up.** Swap `cached_age()` in
  `log_generator.py` / the `first_registered_days_ago` column for a real
  WHOIS/RDAP client or threat-intel feed - `detect_newly_registered_domain`
  doesn't care where the number comes from.
- **DoH evasion is a watchlist, not traffic inspection** (can't inspect
  encrypted traffic anyway) - treat it as "worth correlating," not proof.
- **Beaconing false positives from legitimate polling** remain possible
  (mail sync, update checkers); the detector's `reason` text says so.
- **No persistence/SIEM integration** - alerts live in-memory per Streamlit
  session, exportable to CSV on demand.
- **Natural next step:** layer an Isolation Forest (or similar unsupervised
  model) over the per-(host, domain) feature vectors already computed here,
  and compare its flagged set against these eight rule-based detectors -
  rules are explainable and auditable; ML catches things you didn't think
  to write a rule for, at the cost of needing labeled data and being harder
  to explain in an incident writeup.

## Requirements

See `requirements.txt`. Only `pandas`/`numpy` for data handling and
`matplotlib` for charts - no compiled/exotic dependencies (Levenshtein
distance and Shannon entropy are implemented from scratch in `common.py`).
