"""
risk.py
=======
Turns the raw, per-event alert list from detectors.py into the things a
human actually wants to look at first: which HOSTS need attention today,
and what STORY does each host's alerts tell (recon, then C2, then
exfiltration - or just one isolated flag).

This is deliberately a separate module from detectors.py: detectors.py's
job is "is this one signal suspicious", scored independently. risk.py's job
is "given everything that fired, what should a human do with it" -
correlation and narrative, not new detection logic.
"""

import pandas as pd

from common import MITRE_TACTIC, TACTIC_ORDER, severity_label


# ---------------------------------------------------------------------------
# Host risk score
# ---------------------------------------------------------------------------
# Formula (deliberately simple and easy to say out loud in a meeting):
#   risk = highest single alert's severity
#          + 8 points for every ADDITIONAL detector that also fired on this
#            host (capped at 100)
# Rationale: trust one detector's own severity score if it's the only one
# that fired; if several INDEPENDENT detectors agree on the same host,
# that's stronger evidence than any one of them alone, so boost it.
CORRELATION_BONUS_PER_DETECTOR = 8


def compute_host_risk(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """One row per host that appears in any alert, sorted highest-risk
    first. Columns: src_ip, risk_score, risk_label, n_alerts, n_detectors,
    detectors (comma-joined), top_reason, top_detector."""
    cols = ["src_ip", "risk_score", "risk_label", "n_alerts", "n_detectors",
            "detectors", "top_detector", "top_reason"]
    if alerts_df is None or alerts_df.empty:
        return pd.DataFrame(columns=cols)

    exploded = alerts_df.assign(src_ip=alerts_df["src_ip"].str.split(";")).explode("src_ip")
    exploded["src_ip"] = exploded["src_ip"].str.strip()

    rows = []
    for host, grp in exploded.groupby("src_ip"):
        if not host:
            continue
        top = grp.sort_values("severity_score", ascending=False).iloc[0]
        n_detectors = grp["detector"].nunique()
        score = min(100.0, float(top["severity_score"]) + CORRELATION_BONUS_PER_DETECTOR * (n_detectors - 1))
        rows.append({
            "src_ip": host,
            "risk_score": round(score, 1),
            "risk_label": severity_label(score),
            "n_alerts": int(len(grp)),
            "n_detectors": int(n_detectors),
            "detectors": ", ".join(sorted(grp["detector"].unique())),
            "top_detector": top["detector"],
            "top_reason": top["reason"],
        })

    out = pd.DataFrame(rows, columns=cols)
    return out.sort_values("risk_score", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Kill-chain / tactic timeline for one host
# ---------------------------------------------------------------------------

def host_tactic_summary(alerts_df: pd.DataFrame, src_ip: str) -> pd.DataFrame:
    """Which real MITRE ATT&CK tactics (Reconnaissance / Resource
    Development / Command and Control) this host's alerts touch, in ATT&CK
    tactic order, with the alert count and top severity per tactic. This is
    genuine ATT&CK tactic categorization (see common.MITRE_TACTIC), not an
    invented storyline - most DNS-abuse techniques land in Command and
    Control, which is itself worth pointing out: DNS's most common
    malicious use case IS as a C2/exfil channel."""
    host_alerts = alerts_df[alerts_df["src_ip"].apply(lambda s: src_ip in str(s).split(";"))]
    if host_alerts.empty:
        return pd.DataFrame(columns=["tactic", "n_alerts", "max_severity", "detectors"])

    host_alerts = host_alerts.copy()
    host_alerts["tactic"] = host_alerts["mitre_id"].map(MITRE_TACTIC).fillna("Other")

    rows = []
    for tactic, grp in host_alerts.groupby("tactic"):
        rows.append({
            "tactic": tactic,
            "n_alerts": int(len(grp)),
            "max_severity": float(grp["severity_score"].max()),
            "detectors": ", ".join(sorted(grp["detector"].unique())),
        })
    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    return pd.DataFrame(rows).sort_values(
        by="tactic", key=lambda s: s.map(lambda t: order.get(t, 99))
    ).reset_index(drop=True)


def host_alert_timeline(alerts_df: pd.DataFrame, src_ip: str) -> pd.DataFrame:
    """This host's own alerts in chronological order (oldest first) - reads
    like the narrative of what happened, as opposed to the main Alerts page
    which is severity-sorted for triage."""
    host_alerts = alerts_df[alerts_df["src_ip"].apply(lambda s: src_ip in str(s).split(";"))]
    return host_alerts.sort_values("timestamp").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Auto-generated executive summary
# ---------------------------------------------------------------------------

def generate_executive_summary(raw_df: pd.DataFrame, alerts_df: pd.DataFrame,
                                host_risk_df: pd.DataFrame) -> str:
    """A few sentences suitable for the top of a report or the first slide
    of a meeting - written from the data, not a template with blanks."""
    n_events = len(raw_df) if raw_df is not None else 0
    n_hosts = raw_df["src_ip"].nunique() if raw_df is not None and not raw_df.empty else 0

    if alerts_df is None or alerts_df.empty:
        return (
            f"Reviewed {n_events:,} DNS queries across {n_hosts} hosts. "
            f"No detector crossed its alert threshold - no follow-up required."
        )

    n_alerts = len(alerts_df)
    n_flagged_hosts = len(host_risk_df) if host_risk_df is not None else 0
    n_critical_hosts = int((host_risk_df["risk_label"] == "Critical").sum()) if host_risk_df is not None and not host_risk_df.empty else 0
    n_detectors_fired = alerts_df["detector"].nunique()

    lines = [
        f"Reviewed {n_events:,} DNS queries across {n_hosts} hosts. "
        f"{n_alerts} alert(s) raised by {n_detectors_fired} of 8 detectors, "
        f"touching {n_flagged_hosts} host(s)."
    ]

    if n_critical_hosts:
        top_hosts = host_risk_df[host_risk_df["risk_label"] == "Critical"].head(3)
        detail = "; ".join(
            f"{r.src_ip} ({r.n_detectors} detector(s): {r.detectors})" for r in top_hosts.itertuples()
        )
        lines.append(
            f"Immediate attention: {n_critical_hosts} host(s) at Critical risk - {detail}."
        )
    else:
        lines.append("No host reached Critical risk; review High-severity items when convenient.")

    multi = host_risk_df[host_risk_df["n_detectors"] > 1] if host_risk_df is not None and not host_risk_df.empty else pd.DataFrame()
    if not multi.empty:
        lines.append(
            f"{len(multi)} host(s) were flagged by more than one independent detector, "
            f"which is a stronger signal than any single alert on its own."
        )

    return " ".join(lines)
