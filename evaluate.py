"""
evaluate.py
===========
Scores the detectors in detectors.py against the ground_truth_label column
that log_generator.py stamps on synthetic data ONLY. Real captured traffic
has no ground truth, so this returns None on anything else - the dashboard
checks for that before showing its "Detector Performance" page.

Two things are measured, at the granularity that actually matches how each
detector alerts:

  * Recall per scenario - for dga/tunneling/beaconing/typosquat, "did we
    catch this (host, domain) pair"; for nxdomain_flood, "did we catch this
    HOST" (that detector deliberately reports a few sample domains per
    alert rather than every single one, so pair-level matching would
    under-count it - see the comment in detect_nxdomain_spike).

  * False-positive rate - the fraction of hosts that are 100% benign in the
    ground truth but still received at least one alert from any detector.

Run directly:
    python evaluate.py [path/to/synthetic_log.csv]
"""

import sys

import pandas as pd

from common import split_domain
from detectors import run_all_detectors
from log_parser import load_log

SCENARIO_TO_DETECTOR = {
    "dga": "dga",
    "tunneling": "tunneling",
    "beaconing": "beaconing",
    "nxdomain_flood": "nxdomain_spike",
    "typosquat": "typosquat",
    "fast_flux": "fast_flux",
    "newly_registered": "newly_registered",
    "doh_evasion": "doh_evasion",
}

# nxdomain_spike alerts carry a *sample* of domains, not an exhaustive list,
# so we evaluate that scenario at the host level instead of (host, domain).
HOST_GRANULAR_SCENARIOS = {"nxdomain_flood"}


def _flagged_pairs_for(alerts_df: pd.DataFrame, detector: str) -> set:
    pairs = set()
    rows = alerts_df[alerts_df["detector"] == detector] if not alerts_df.empty else alerts_df
    for _, row in rows.iterrows():
        ips = str(row["src_ip"]).split(";")
        doms = [split_domain(d)[1] or d for d in str(row["domain"]).split(";")]
        for ip in ips:
            for dom in doms:
                pairs.add((ip, dom))
    return pairs


def _flagged_hosts_for(alerts_df: pd.DataFrame, detector: str) -> set:
    hosts = set()
    rows = alerts_df[alerts_df["detector"] == detector] if not alerts_df.empty else alerts_df
    for _, row in rows.iterrows():
        hosts.update(str(row["src_ip"]).split(";"))
    return hosts


def evaluate_against_ground_truth(raw_df: pd.DataFrame, alerts_df: pd.DataFrame):
    """Returns None if raw_df has no usable ground truth (i.e. it's not our
    synthetic data), otherwise a dict with 'per_scenario' (DataFrame) and
    overall false-positive stats."""
    if raw_df is None or raw_df.empty or "ground_truth_label" not in raw_df.columns:
        return None
    truth = raw_df.dropna(subset=["ground_truth_label"])
    if truth.empty:
        return None
    if alerts_df is None:
        alerts_df = pd.DataFrame(columns=["detector", "src_ip", "domain"])

    rows = []
    for scenario, detector in SCENARIO_TO_DETECTOR.items():
        gt = truth[truth["ground_truth_label"] == scenario]
        if gt.empty:
            continue

        if scenario in HOST_GRANULAR_SCENARIOS:
            gt_units = set(gt["src_ip"].unique())
            flagged = _flagged_hosts_for(alerts_df, detector)
            unit = "hosts"
        else:
            gt_units = set(zip(gt["src_ip"], gt["registrable_domain"]))
            flagged = _flagged_pairs_for(alerts_df, detector)
            unit = "(host, domain) pairs"

        caught = gt_units & flagged
        recall = len(caught) / len(gt_units) if gt_units else 0.0
        rows.append({
            "scenario": scenario,
            "detector": detector,
            "unit": unit,
            "ground_truth_total": len(gt_units),
            "caught": len(caught),
            "recall": round(recall, 2),
        })

    # False positives: hosts that are ENTIRELY benign in ground truth but
    # still triggered at least one alert from any detector.
    labels_per_host = truth.groupby("src_ip")["ground_truth_label"].apply(set)
    pure_benign_hosts = set(labels_per_host[labels_per_host == {"benign"}].index)
    flagged_any = set()
    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            flagged_any.update(str(row["src_ip"]).split(";"))
    fp_hosts = pure_benign_hosts & flagged_any
    fp_rate = len(fp_hosts) / len(pure_benign_hosts) if pure_benign_hosts else 0.0

    return {
        "per_scenario": pd.DataFrame(rows),
        "false_positive_hosts": sorted(fp_hosts),
        "benign_hosts_total": len(pure_benign_hosts),
        "false_positive_rate": round(fp_rate, 3),
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/dns_log_synthetic.csv"
    df = load_log(path)
    alerts = run_all_detectors(df)
    result = evaluate_against_ground_truth(df, alerts)

    if result is None:
        print("No ground_truth_label column found - this only works on log_generator.py's synthetic output.")
        return

    print(f"{len(df)} events -> {len(alerts)} alerts\n")
    print("Recall per injected scenario:")
    print(result["per_scenario"].to_string(index=False))
    print()
    print(f"False positives: {len(result['false_positive_hosts'])} / {result['benign_hosts_total']} "
          f"purely-benign hosts got at least one alert (rate={result['false_positive_rate']})")
    if result["false_positive_hosts"]:
        print("  hosts:", ", ".join(result["false_positive_hosts"]))


if __name__ == "__main__":
    main()
