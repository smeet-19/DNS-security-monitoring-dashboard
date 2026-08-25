"""
log_parser.py
=============
Loads DNS query logs from any of three sources and normalizes them into one
common pandas DataFrame schema that log_generator.py's output already
matches and that detectors.py is written against:

    timestamp                datetime64[ns]
    src_ip                   str
    query_name                str   (lowercased, no trailing root dot)
    query_type                 str   (upper-case, e.g. "A", "TXT", "NULL")
    response_code               str   (upper-case, "" if unknown)
    response_ip                  str   ("" if none)
    ttl                            Int64 (0 = unknown/no answer)
    query_size_bytes                int
    ground_truth_label                object (None unless synthetic data)
    registrable_domain                  str   (eTLD+1, derived)
    subdomain                            str   (labels before the
                                                  registrable domain, dot-
                                                  joined, "" if none)
    subdomain_label_count                 int
    subdomain_len                           int (len of the joined subdomain
                                                  string - useful for
                                                  tunneling detection)

Supported sources
------------------
1. csv    - our own synthetic format (also fine for hand-built CSVs using
             the same column names).
2. bind   - BIND9 `named` query logs (the "queries" and "query-errors"
             logging categories). Plain query lines don't carry a response
             code, only query-errors lines do - see the comment in
             load_bind() for why.
3. zeek   - Zeek/Bro dns.log (self-describing, tab-separated). The #fields
             header line is parsed to find columns dynamically rather than
             assuming a fixed column order, since Zeek's own field set is
             configurable.

Usage:
    from log_parser import load_log
    df = load_log("data/dns_log_synthetic.csv")            # auto-detected
    df = load_log("sample_logs/bind_sample.log", fmt="bind")
    df = load_log("sample_logs/zeek_sample.log", fmt="zeek")
"""

import ipaddress
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from common import split_domain

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def load_log(path, fmt: str = "auto") -> pd.DataFrame:
    """Load a DNS log file and return the normalized DataFrame described
    above. fmt: "auto" | "csv" | "bind" | "zeek"."""
    path = Path(path)
    if fmt == "auto":
        fmt = _detect_format(path)

    if fmt == "csv":
        df = _load_csv(path)
    elif fmt == "bind":
        df = _load_bind(path)
    elif fmt == "zeek":
        df = _load_zeek(path)
    else:
        raise ValueError(f"Unknown log format: {fmt!r} (expected csv/bind/zeek/auto)")

    return _finalize(df)


def _detect_format(path: Path) -> str:
    if path.suffix.lower() == ".csv":
        return "csv"
    try:
        with path.open("r", errors="replace") as f:
            head = f.readline()
    except OSError:
        return "csv"
    if head.startswith("#separator") or head.startswith("#fields"):
        return "zeek"
    if re.match(r"^\d{2}-[A-Za-z]{3}-\d{4}\s", head):
        return "bind"
    return "csv"


# ---------------------------------------------------------------------------
# Loader: our synthetic / hand-built CSV
# ---------------------------------------------------------------------------

def _load_csv(path: Path) -> pd.DataFrame:
    # keep_default_na=False is NOT optional here: pandas' default NA sniffer
    # treats the literal strings "NULL" and "NA" as missing values, and
    # "NULL" is a real, meaningful DNS record type used by tunneling tools.
    # Without this, every NULL-type row silently loses its query_type.
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
    if "ground_truth_label" not in df.columns:
        df["ground_truth_label"] = None
    else:
        df["ground_truth_label"] = df["ground_truth_label"].replace("", None)
    return df


# ---------------------------------------------------------------------------
# Loader: BIND9 named query logs
# ---------------------------------------------------------------------------
# Example "queries" category line (records the incoming query only):
#   18-Aug-2026 10:15:23.456 queries: info: client @0x7f8a2c0 \
#       192.168.1.10#54321 (google.com): query: google.com IN A + (10.0.0.1)
#
# Example "query-errors" category line (records a failed *response*):
#   18-Aug-2026 10:16:01.001 query-errors: info: client @0x7f8a2c0 \
#       192.168.1.10#54321 (bad.example): view internal: query failed \
#       (NXDOMAIN) for bad.example/IN/A at query.c:1234
#
# A stock BIND deployment logging only the "queries" category therefore has
# NO response-code visibility at all - you only find out a query failed if
# "query-errors" is also enabled. This parser handles both line types, but
# if your log only has plain "queries" lines, response_code will come back
# empty for every row and the NXDOMAIN-spike detector will have nothing to
# work with. (This is one real reason Zeek/dnstap logs are nicer to build
# detection on than raw BIND text logs: they pair query and answer in one
# record - see load_zeek below.)

_BIND_TS = r"(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})"

BIND_QUERY_RE = re.compile(
    _BIND_TS + r" queries: info: client(?: @0x[0-9a-fA-F]+)? "
    r"(?P<src_ip>[0-9a-fA-F:.]+)#\d+ \([^)]*\): query: "
    r"(?P<qname>\S+) \S+ (?P<qtype>\S+)"
)

BIND_ERROR_RE = re.compile(
    _BIND_TS + r" query-errors: info: client(?: @0x[0-9a-fA-F]+)? "
    r"(?P<src_ip>[0-9a-fA-F:.]+)#\d+ \([^)]*\): view \S+: query failed "
    r"\((?P<rcode>[A-Z]+)\) for (?P<qname>\S+)/IN/(?P<qtype>\S+)"
)


def _load_bind(path: Path) -> pd.DataFrame:
    rows = []
    with path.open("r", errors="replace") as f:
        for line in f:
            m = BIND_ERROR_RE.match(line)
            if m:
                rows.append({
                    "timestamp": datetime.strptime(m.group("ts"), "%d-%b-%Y %H:%M:%S.%f"),
                    "src_ip": m.group("src_ip"),
                    "query_name": m.group("qname"),
                    "query_type": m.group("qtype"),
                    "response_code": m.group("rcode"),
                    "response_ip": "",
                    "ttl": 0,
                })
                continue
            m = BIND_QUERY_RE.match(line)
            if m:
                rows.append({
                    "timestamp": datetime.strptime(m.group("ts"), "%d-%b-%Y %H:%M:%S.%f"),
                    "src_ip": m.group("src_ip"),
                    "query_name": m.group("qname"),
                    "query_type": m.group("qtype"),
                    "response_code": "",  # not present in plain query lines - see note above
                    "response_ip": "",
                    "ttl": 0,
                })
            # any other line (rndc/zone-transfer/notify/startup messages etc.)
            # is silently skipped - this parser only cares about query traffic.
    df = pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "query_name", "query_type",
        "response_code", "response_ip", "ttl",
    ])
    df["ground_truth_label"] = None
    return df


# ---------------------------------------------------------------------------
# Loader: Zeek/Bro dns.log
# ---------------------------------------------------------------------------

def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _load_zeek(path: Path) -> pd.DataFrame:
    fields = None
    unset_field, set_separator = "-", ","
    rows = []

    with path.open("r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#unset_field"):
                unset_field = line.split("\t", 1)[1]
                continue
            if line.startswith("#set_separator"):
                # Zeek escapes this as literal "\x2c" by default for a comma
                raw = line.split("\t", 1)[1]
                set_separator = raw.encode().decode("unicode_escape") if "\\x" in raw else raw
                continue
            if line.startswith("#"):
                continue  # #separator, #path, #open, #types, #close, ...
            if fields is None:
                continue  # data line seen before a #fields header - skip
            rows.append(dict(zip(fields, line.split("\t"))))

    events = []
    for row in rows:
        ts_raw = row.get("ts", unset_field)
        try:
            ts = datetime.fromtimestamp(float(ts_raw))
        except (ValueError, TypeError):
            continue  # can't use a record with no usable timestamp

        response_ip, ttl = "", 0
        answers_raw = row.get("answers", unset_field)
        if answers_raw and answers_raw != unset_field:
            for ans in answers_raw.split(set_separator):
                if _looks_like_ip(ans):
                    response_ip = ans
                    break
        ttls_raw = row.get("TTLs", unset_field)
        if ttls_raw and ttls_raw != unset_field:
            try:
                ttl = int(float(ttls_raw.split(set_separator)[0]))
            except (ValueError, IndexError):
                ttl = 0

        rcode = row.get("rcode_name", "")
        events.append({
            "timestamp": ts,
            "src_ip": row.get("id.orig_h", ""),
            "query_name": row.get("query", ""),
            "query_type": row.get("qtype_name", ""),
            "response_code": rcode.upper() if rcode and rcode != unset_field else "",
            "response_ip": response_ip,
            "ttl": ttl,
        })

    df = pd.DataFrame(events, columns=[
        "timestamp", "src_ip", "query_name", "query_type",
        "response_code", "response_ip", "ttl",
    ])
    df["ground_truth_label"] = None
    return df


# ---------------------------------------------------------------------------
# Shared post-processing
# ---------------------------------------------------------------------------

def _finalize(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce dtypes and add the derived domain-structure columns every
    detector relies on, regardless of which loader produced the raw rows."""
    if df.empty:
        cols = [
            "timestamp", "src_ip", "query_name", "query_type", "response_code",
            "response_ip", "ttl", "query_size_bytes", "first_registered_days_ago",
            "ground_truth_label", "registrable_domain", "subdomain",
            "subdomain_label_count", "subdomain_len",
        ]
        return pd.DataFrame(columns=cols)

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    df["src_ip"] = df["src_ip"].fillna("").astype(str)
    df["query_name"] = df["query_name"].fillna("").astype(str).str.lower().str.rstrip(".")
    df["query_type"] = df["query_type"].fillna("").astype(str).str.upper()
    df["response_code"] = df["response_code"].fillna("").astype(str).str.upper()
    df["response_ip"] = df["response_ip"].fillna("").astype(str)

    df["ttl"] = pd.to_numeric(df["ttl"], errors="coerce").fillna(0).astype("Int64")

    if "query_size_bytes" in df.columns:
        df["query_size_bytes"] = pd.to_numeric(df["query_size_bytes"], errors="coerce")
    else:
        df["query_size_bytes"] = pd.NA
    # if a source doesn't tell us the wire size, approximate it the same way
    # log_generator.py does, so detectors see a consistent feature either way
    fallback_size = 12 + df["query_name"].str.len() + 5
    df["query_size_bytes"] = df["query_size_bytes"].fillna(fallback_size).astype(int)

    if "ground_truth_label" not in df.columns:
        df["ground_truth_label"] = None

    # Only present on our own synthetic CSV (SIMULATED registration age -
    # see log_generator.py). Real BIND/Zeek sources don't have this, so it
    # comes back as an all-NaN column rather than a missing one, which is
    # what detect_newly_registered_domain() expects.
    if "first_registered_days_ago" in df.columns:
        df["first_registered_days_ago"] = pd.to_numeric(df["first_registered_days_ago"], errors="coerce")
    else:
        df["first_registered_days_ago"] = pd.NA

    split = df["query_name"].apply(split_domain)
    df["subdomain"] = split.apply(lambda t: ".".join(t[0]))
    df["registrable_domain"] = split.apply(lambda t: t[1])
    df["subdomain_label_count"] = split.apply(lambda t: len(t[0]))
    df["subdomain_len"] = df["subdomain"].str.len()

    return df


# ---------------------------------------------------------------------------
# Quick manual test: `python log_parser.py <path> [fmt]`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else "data/dns_log_synthetic.csv"
    test_fmt = sys.argv[2] if len(sys.argv) > 2 else "auto"
    out = load_log(test_path, fmt=test_fmt)
    print(f"Loaded {len(out)} rows from {test_path} (format={test_fmt})")
    print(out.head(5).to_string())
    print()
    print(out.dtypes)
