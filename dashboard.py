"""
dashboard.py
============
Streamlit UI for the DNS Security Monitoring Dashboard.

Run it with:
    streamlit run dashboard.py

Pages:
  Overview             - query volume over time, top talkers, top domains,
                           response-code / query-type breakdowns
  Alerts                - severity-sorted, filterable alert table + CSV export
  Domain Detail          - pick a domain, see its full query history and
                             which detector(s) flagged it
  Detector Performance     - (only meaningful on the bundled synthetic data)
                              recall per injected scenario + false-positive
                              rate, computed by evaluate.py

Design note: this app targets a SOC analyst staring at it for a long shift,
so the palette is a dark, low-glare slate rather than a bright dashboard
theme, and severity colour-coding is functional (it's how you triage), not
decorative. Domain names are shown in monospace throughout, the same way a
packet dump or terminal log would render them - the aim is to look and feel
like an actual piece of blue-team tooling, not a generic data app template.
"""

import html
import random
import tempfile
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from common import DETECTOR_META, MITRE_TACTIC, MITRE_TECHNIQUES, SEVERITY_COLORS, TACTIC_ORDER, split_domain
from detectors import run_all_detectors
from evaluate import evaluate_against_ground_truth
from log_generator import generate_dataset
from log_parser import load_log
from risk import compute_host_risk, generate_executive_summary, host_alert_timeline, host_tactic_summary

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_PATH = BASE_DIR / "data" / "dns_log_synthetic.csv"

# ---------------------------------------------------------------------------
# Theme tokens
# ---------------------------------------------------------------------------
BG = "#10141C"
PANEL = "#171C27"
GRID = "#2A3142"
TEXT = "#E3E7EE"
MUTED = "#7C8798"
ACCENT = "#4FC1E0"

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"]  { font-family: 'IBM Plex Sans', sans-serif; }
.stApp { background-color: #10141C; color: #E3E7EE; }
section[data-testid="stSidebar"] { background-color: #12161F; border-right: 1px solid #2A3142; }
section[data-testid="stSidebar"] * { color: #E3E7EE; }
h1, h2, h3, h4 { font-family: 'IBM Plex Sans', sans-serif; letter-spacing: -0.01em; }
[data-testid="stMetricValue"] { font-family: 'IBM Plex Mono', monospace; color: #E3E7EE; }
[data-testid="stMetricLabel"] { color: #7C8798; }
[data-testid="stDataFrame"] { font-family: 'IBM Plex Mono', monospace; }
.stButton>button { background-color: #171C27; color: #E3E7EE; border: 1px solid #2A3142; border-radius: 4px; }
.stButton>button:hover { border-color: #4FC1E0; color: #4FC1E0; }
.stDownloadButton>button { background-color: #171C27; color: #4FC1E0; border: 1px solid #4FC1E0; border-radius: 4px; }
hr { border-color: #2A3142; }
code { font-family: 'IBM Plex Mono', monospace; background-color: #171C27; color: #4FC1E0; }
</style>
"""


# ---------------------------------------------------------------------------
# Cached data operations
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Parsing DNS log...")
def cached_load_log(path: str, fmt: str) -> pd.DataFrame:
    return load_log(path, fmt=fmt)


@st.cache_data(show_spinner="Running detectors...")
def cached_run_detectors(df: pd.DataFrame) -> pd.DataFrame:
    return run_all_detectors(df)


def _save_upload_to_temp(uploaded_file) -> str:
    suffix = Path(uploaded_file.name).suffix or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getvalue())
        return tmp.name


# ---------------------------------------------------------------------------
# Small chart helpers (matplotlib, themed to match the app)
# ---------------------------------------------------------------------------

def _themed_fig(figsize=(10, 3.0)):
    fig, ax = plt.subplots(figsize=figsize)
    fig.patch.set_facecolor(PANEL)
    ax.set_facecolor(PANEL)
    ax.tick_params(colors=MUTED, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(GRID)
    ax.grid(True, color=GRID, linewidth=0.6, alpha=0.6)
    return fig, ax


def render_timeseries(raw_df: pd.DataFrame):
    ts = raw_df.set_index("timestamp").resample("15min").size()
    fig, ax = _themed_fig()
    ax.plot(ts.index, ts.values, color=ACCENT, linewidth=1.6)
    ax.fill_between(ts.index, ts.values, color=ACCENT, alpha=0.12)
    ax.set_ylabel("queries / 15 min", fontsize=8, color=MUTED)
    fig.autofmt_xdate()
    st.pyplot(fig, use_container_width=True)
    plt.close(fig)


def render_barh(series: pd.Series, color=ACCENT, figsize=(6, 3.2)):
    fig, ax = _themed_fig(figsize)
    labels = series.index.astype(str).tolist()[::-1]
    values = series.values.tolist()[::-1]
    ax.barh(labels, values, color=color, height=0.6)
    ax.tick_params(axis="y", labelsize=8)
    st.pyplot(fig, use_container_width=True)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Small UI helpers
# ---------------------------------------------------------------------------

def render_header(raw_df: pd.DataFrame, alerts_df: pd.DataFrame):
    critical_n = int((alerts_df["severity_label"] == "Critical").sum()) if not alerts_df.empty else 0
    status_color = SEVERITY_COLORS["Critical"] if critical_n else SEVERITY_COLORS["Low"]
    status_text = f"{critical_n} CRITICAL ALERT{'S' if critical_n != 1 else ''}" if critical_n else "NO CRITICAL ALERTS"
    st.markdown(f"""
<div style="display:flex; justify-content:space-between; align-items:baseline;
            border-bottom:1px solid {GRID}; padding-bottom:12px; margin-bottom:22px;">
  <div>
    <div style="font-family:'IBM Plex Mono',monospace; color:{MUTED}; font-size:12px; letter-spacing:0.08em;">
      DNS SECURITY MONITORING
    </div>
    <div style="font-size:26px; font-weight:700;">Query Pattern Dashboard</div>
  </div>
  <div style="font-family:'IBM Plex Mono',monospace; color:{status_color}; font-size:13px;
              font-weight:600; letter-spacing:0.04em;">
    &#9679; {status_text}
  </div>
</div>
""", unsafe_allow_html=True)


def severity_chip(label: str) -> str:
    color = SEVERITY_COLORS.get(label, MUTED)
    return (
        f'<span style="background:{color}22; color:{color}; border:1px solid {color}66; '
        f'padding:2px 10px; border-radius:3px; font-family:\'IBM Plex Mono\',monospace; '
        f'font-size:12px; font-weight:600; letter-spacing:0.03em;">{html.escape(label.upper())}</span>'
    )


def render_severity_legend():
    chips = "".join(
        f'<span style="color:{color}; font-family:\'IBM Plex Mono\',monospace; font-size:11px; '
        f'margin-right:16px;">&#9679; {html.escape(label)}</span>'
        for label, color in SEVERITY_COLORS.items()
    )
    st.markdown(f'<div style="margin-bottom:12px;">{chips}</div>', unsafe_allow_html=True)


def render_alert_card(row: pd.Series):
    color = SEVERITY_COLORS.get(row["severity_label"], MUTED)
    icon = DETECTOR_META.get(row["detector"], {}).get("icon", "\u26A0\uFE0F")
    label = DETECTOR_META.get(row["detector"], {}).get("label", str(row["detector"]))
    st.markdown(f"""
<div style="border-left:4px solid {color}; background:{PANEL}; padding:10px 14px;
            margin-bottom:8px; border-radius:4px; border-top:1px solid {GRID};
            border-right:1px solid {GRID}; border-bottom:1px solid {GRID};">
  <div style="display:flex; justify-content:space-between; font-family:'IBM Plex Mono',monospace;
              font-size:12px; color:{MUTED};">
    <span>{icon} {html.escape(str(row['alert_id']))} &middot; {html.escape(label)}
      &middot; {html.escape(str(row['mitre_id']))}</span>
    <span style="color:{color}; font-weight:700;">
      {html.escape(str(row['severity_label']).upper())} ({row['severity_score']:.0f})
    </span>
  </div>
  <div style="font-family:'IBM Plex Mono',monospace; font-size:14px; margin:5px 0; color:{TEXT};">
    {html.escape(str(row['src_ip']))} &rarr; {html.escape(str(row['domain']))}
  </div>
  <div style="font-size:13px; color:{MUTED};">{html.escape(str(row['reason']))}</div>
</div>
""", unsafe_allow_html=True)


def render_domain_breadcrumb(domain: str):
    labels = domain.split(".")
    chips = [
        f'<span style="background:{BG}; border:1px solid {GRID}; color:{TEXT}; padding:4px 10px; '
        f'border-radius:3px; font-family:\'IBM Plex Mono\',monospace; font-size:13px;">{html.escape(lab)}</span>'
        for lab in labels
    ]
    sep = f'<span style="color:{MUTED}; margin:0 3px;">.</span>'
    st.markdown(f'<div style="margin:6px 0 18px 0;">{sep.join(chips)}</div>', unsafe_allow_html=True)


def render_executive_summary(raw_df: pd.DataFrame, alerts_df: pd.DataFrame, host_risk_df: pd.DataFrame):
    summary = generate_executive_summary(raw_df, alerts_df, host_risk_df)
    accent = SEVERITY_COLORS["Critical"] if not host_risk_df.empty and (host_risk_df["risk_label"] == "Critical").any() else ACCENT
    st.markdown(f"""
<div style="background:{PANEL}; border:1px solid {GRID}; border-left:4px solid {accent};
            border-radius:4px; padding:14px 16px; margin-bottom:20px;">
  <div style="font-family:'IBM Plex Mono',monospace; color:{MUTED}; font-size:11px;
              letter-spacing:0.08em; margin-bottom:6px;">EXECUTIVE SUMMARY</div>
  <div style="font-size:14.5px; line-height:1.55; color:{TEXT};">{html.escape(summary)}</div>
</div>
""", unsafe_allow_html=True)


def render_host_risk_leaderboard(host_risk_df: pd.DataFrame, limit: int = 8):
    if host_risk_df.empty:
        st.info("No host has raised an alert - nothing to rank.")
        return
    for row in host_risk_df.head(limit).itertuples():
        color = SEVERITY_COLORS.get(row.risk_label, MUTED)
        icon = DETECTOR_META.get(row.top_detector, {}).get("icon", "\u26A0\uFE0F")
        st.markdown(f"""
<div style="display:flex; align-items:center; background:{PANEL}; border:1px solid {GRID};
            border-radius:4px; padding:10px 14px; margin-bottom:6px;">
  <div style="width:54px; text-align:center; font-family:'IBM Plex Mono',monospace;
              font-weight:700; font-size:18px; color:{color};">{row.risk_score:.0f}</div>
  <div style="flex:1; padding-left:12px; border-left:1px solid {GRID};">
    <div style="font-family:'IBM Plex Mono',monospace; font-size:14px; color:{TEXT};">
      {icon} {html.escape(row.src_ip)}
      <span style="color:{color}; font-size:11px; font-weight:700; margin-left:8px;">
        {html.escape(row.risk_label.upper())}
      </span>
    </div>
    <div style="font-size:12px; color:{MUTED}; margin-top:2px;">
      {row.n_alerts} alert(s) &middot; {row.n_detectors} independent detector(s): {html.escape(row.detectors)}
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def render_tactic_strip(tactic_summary: pd.DataFrame):
    """A left-to-right strip of the real MITRE ATT&CK tactics (Reconnaissance
    -> Resource Development -> Command and Control), lit up in severity
    colour for any tactic this host actually touched and dimmed otherwise -
    a one-glance 'how far did this get' view."""
    touched = {row.tactic: row.max_severity for row in tactic_summary.itertuples()}
    cells = []
    for tactic in TACTIC_ORDER:
        if tactic in touched:
            color = SEVERITY_COLORS.get(
                "Critical" if touched[tactic] >= 85 else "High" if touched[tactic] >= 65
                else "Medium" if touched[tactic] >= 40 else "Low", ACCENT
            )
            style = f"background:{color}22; border:1px solid {color}88; color:{color}; font-weight:700;"
        else:
            style = f"background:{BG}; border:1px dashed {GRID}; color:{MUTED};"
        cells.append(
            f'<div style="flex:1; text-align:center; padding:10px 6px; border-radius:4px; '
            f'font-family:\'IBM Plex Mono\',monospace; font-size:12px; {style}">{html.escape(tactic)}</div>'
        )
    arrow = f'<div style="color:{MUTED}; padding:0 6px; align-self:center;">&rarr;</div>'
    st.markdown(
        f'<div style="display:flex; align-items:stretch; margin:10px 0 18px 0;">{arrow.join(cells)}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def render_overview(raw_df: pd.DataFrame, alerts_df: pd.DataFrame, host_risk_df: pd.DataFrame):
    render_executive_summary(raw_df, alerts_df, host_risk_df)

    st.subheader("Traffic Overview")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total queries", f"{len(raw_df):,}")
    c2.metric("Unique hosts", f"{raw_df['src_ip'].nunique():,}")
    c3.metric("Unique domains", f"{raw_df['registrable_domain'].nunique():,}")
    c4.metric("Alerts raised", f"{len(alerts_df):,}")

    if not host_risk_df.empty:
        st.markdown("**Top-risk hosts**")
        render_host_risk_leaderboard(host_risk_df, limit=5)

    st.markdown("**Query volume over time**")
    render_timeseries(raw_df)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Top talkers** (by query volume)")
        render_barh(raw_df["src_ip"].value_counts().head(10))
    with col_b:
        st.markdown("**Top queried domains**")
        render_barh(raw_df["registrable_domain"].value_counts().head(10))

    col_c, col_d = st.columns(2)
    with col_c:
        st.markdown("**Response codes**")
        render_barh(raw_df["response_code"].value_counts(), color="#7C8798")
    with col_d:
        if not alerts_df.empty:
            st.markdown("**Alerts by detector**")
            render_barh(alerts_df["detector"].value_counts(), color=SEVERITY_COLORS["High"])
        else:
            st.markdown("**Alerts by detector**")
            st.info("No alerts raised on this log.")


def render_alerts(alerts_df: pd.DataFrame):
    st.subheader("Alerts")
    if alerts_df.empty:
        st.success("No alerts - nothing crossed a detection threshold in this log.")
        return

    render_severity_legend()

    col1, col2, col3 = st.columns([1, 1, 2])
    all_sev = ["Critical", "High", "Medium", "Low"]
    sev_filter = col1.multiselect("Severity", all_sev, default=all_sev)
    detectors_present = sorted(alerts_df["detector"].unique())
    det_filter = col2.multiselect("Detector", detectors_present, default=detectors_present)
    search = col3.text_input("Search domain or IP", "")

    filtered = alerts_df[
        alerts_df["severity_label"].isin(sev_filter) & alerts_df["detector"].isin(det_filter)
    ]
    if search:
        mask = (
            filtered["domain"].str.contains(search, case=False, na=False)
            | filtered["src_ip"].str.contains(search, case=False, na=False)
        )
        filtered = filtered[mask]

    st.caption(f"{len(filtered)} of {len(alerts_df)} alerts shown")

    top_critical = filtered[filtered["severity_label"] == "Critical"].head(3)
    if not top_critical.empty:
        st.markdown("#### Highest priority")
        for _, row in top_critical.iterrows():
            render_alert_card(row)

    st.markdown("#### All matching alerts")
    display_cols = ["alert_id", "timestamp", "severity_label", "detector", "src_ip", "domain", "mitre_id", "reason"]
    nice_names = {
        "alert_id": "Alert ID", "timestamp": "Timestamp", "severity_label": "Severity",
        "detector": "Detector", "src_ip": "Source IP", "domain": "Domain",
        "mitre_id": "MITRE ID", "reason": "Reason",
    }
    st.dataframe(
        filtered[display_cols].rename(columns=nice_names).sort_values("Severity", key=lambda s: s.map(
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        )),
        use_container_width=True, hide_index=True,
    )

    csv_bytes = filtered.drop(columns=["evidence"]).to_csv(index=False).encode("utf-8")
    st.download_button("Export filtered alerts to CSV", data=csv_bytes,
                        file_name="dns_alerts_export.csv", mime="text/csv")


def render_domain_detail(raw_df: pd.DataFrame, alerts_df: pd.DataFrame):
    st.subheader("Domain Detail")

    domain_options = sorted(d for d in raw_df["registrable_domain"].dropna().unique() if d)
    if not domain_options:
        st.info("No domains to inspect in this log.")
        return

    only_flagged = st.checkbox("Show only domains with alerts", value=not alerts_df.empty)
    if only_flagged and not alerts_df.empty:
        flagged = set()
        for d in alerts_df["domain"]:
            for part in str(d).split(";"):
                flagged.add(split_domain(part)[1] or part)
        narrowed = sorted(d for d in domain_options if d in flagged)
        if narrowed:
            domain_options = narrowed

    default_idx = 0
    if not alerts_df.empty:
        top_domain_raw = str(alerts_df.iloc[0]["domain"]).split(";")[0]
        top_reg = split_domain(top_domain_raw)[1] or top_domain_raw
        if top_reg in domain_options:
            default_idx = domain_options.index(top_reg)

    selected = st.selectbox("Choose a domain", domain_options, index=default_idx)
    render_domain_breadcrumb(selected)

    domain_alerts = alerts_df[alerts_df["domain"].apply(lambda d: selected in str(d).split(";"))] \
        if not alerts_df.empty else alerts_df
    if not domain_alerts.empty:
        st.markdown(f"**Flagged by {domain_alerts['detector'].nunique()} detector(s)**")
        for _, row in domain_alerts.iterrows():
            render_alert_card(row)
    else:
        st.info("No detector flagged this domain.")

    grp = raw_df[raw_df["registrable_domain"] == selected].sort_values("timestamp")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total queries", f"{len(grp):,}")
    c2.metric("Unique source hosts", f"{grp['src_ip'].nunique():,}")
    nx_rate = (grp["response_code"] == "NXDOMAIN").mean() * 100 if len(grp) else 0.0
    c3.metric("NXDOMAIN rate", f"{nx_rate:.0f}%")

    st.markdown("**Query history**")
    st.dataframe(
        grp[["timestamp", "src_ip", "query_type", "response_code", "response_ip", "ttl"]]
        .rename(columns={"timestamp": "Timestamp", "src_ip": "Source IP", "query_type": "Type",
                          "response_code": "Response", "response_ip": "Answer IP", "ttl": "TTL"}),
        use_container_width=True, hide_index=True,
    )


def render_host_investigation(raw_df: pd.DataFrame, alerts_df: pd.DataFrame, host_risk_df: pd.DataFrame):
    st.subheader("Host Investigation")
    st.caption("Pick a flagged host to see its risk score, which real ATT&CK tactics it touched, and the chronological story of its alerts.")

    if host_risk_df.empty:
        st.info("No host has raised an alert in this log.")
        return

    options = host_risk_df["src_ip"].tolist()
    selected = st.selectbox("Choose a host", options, index=0)
    row = host_risk_df[host_risk_df["src_ip"] == selected].iloc[0]

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{row['risk_score']:.0f} / 100")
    c2.metric("Risk level", row["risk_label"])
    c3.metric("Independent detectors", int(row["n_detectors"]))
    st.caption(
        "Risk score = highest single alert severity, +8 points for every additional "
        "independent detector that also fired on this host (capped at 100)."
    )

    st.markdown("**Kill-chain progression** (real MITRE ATT&CK tactics, in ATT&CK order)")
    tactic_summary = host_tactic_summary(alerts_df, selected)
    render_tactic_strip(tactic_summary)
    if not tactic_summary.empty:
        st.dataframe(
            tactic_summary.rename(columns={
                "tactic": "Tactic", "n_alerts": "Alerts", "max_severity": "Top severity", "detectors": "Detectors",
            }),
            use_container_width=True, hide_index=True,
        )

    st.markdown(f"**Alert timeline for {selected}** (chronological)")
    timeline = host_alert_timeline(alerts_df, selected)
    for _, r in timeline.iterrows():
        render_alert_card(r)


def render_performance(raw_df: pd.DataFrame, alerts_df: pd.DataFrame):
    st.subheader("Detector Performance")
    st.caption("Only meaningful on the bundled synthetic demo data, which carries ground-truth labels.")

    result = evaluate_against_ground_truth(raw_df, alerts_df)
    if result is None:
        st.info(
            "No ground-truth labels found on this log (real / uploaded logs don't carry them). "
            "Switch to the bundled synthetic demo data to see recall and false-positive metrics."
        )
        return

    st.markdown("**Recall per injected scenario**")
    st.dataframe(result["per_scenario"], use_container_width=True, hide_index=True)

    fp_pct = result["false_positive_rate"] * 100
    st.markdown(
        f"**False-positive rate on purely-benign hosts:** {fp_pct:.1f}% "
        f"({len(result['false_positive_hosts'])} of {result['benign_hosts_total']} hosts)"
    )
    if result["false_positive_hosts"]:
        st.caption("Hosts: " + ", ".join(result["false_positive_hosts"]))

    st.markdown("""
---
**Reading this table for your report:** recall is measured at the (host, domain) pair
level for dga/tunneling/beaconing/typosquat, and at the host level for
nxdomain_flood (that detector reports a *sample* of domains per alert rather
than every one, so pair-matching would understate it). A detector below
100% recall isn't necessarily broken - e.g. DGA domains generated with a
"pronounceable" consonant/vowel-alternating style naturally score lower on
entropy than pure random strings, so a purely statistical detector will
always miss some of those. That's a real, citable limitation, not a bug.
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    st.set_page_config(page_title="DNS Security Monitoring Dashboard", page_icon="\U0001F6E1\uFE0F", layout="wide")
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    st.sidebar.markdown("## \U0001F6E1\uFE0F DNS SOC")
    page = st.sidebar.radio("Navigate", ["Overview", "Alerts", "Domain Detail", "Host Investigation", "Detector Performance"])
    st.sidebar.divider()

    st.sidebar.markdown("### Data source")
    source_choice = st.sidebar.radio("Load DNS log from:", ["Bundled synthetic demo data", "Upload a file"])

    if source_choice == "Bundled synthetic demo data":
        if st.sidebar.button("Regenerate demo data (new random seed)"):
            new_seed = random.randint(1, 1_000_000)
            generate_dataset(hours=18, num_benign_hosts=22, seed=new_seed, out_path=str(DEFAULT_LOG_PATH))
            st.cache_data.clear()
            st.rerun()
        if not DEFAULT_LOG_PATH.exists():
            generate_dataset(hours=18, num_benign_hosts=22, seed=42, out_path=str(DEFAULT_LOG_PATH))
        raw_df = cached_load_log(str(DEFAULT_LOG_PATH), "csv")
    else:
        uploaded = st.sidebar.file_uploader("DNS log file", type=["csv", "log", "txt"])
        fmt_choice = st.sidebar.selectbox("Format", ["auto", "csv", "bind", "zeek"])
        if uploaded is None:
            st.info("Upload a DNS log file in the sidebar to get started, or switch back to the bundled demo data.")
            st.stop()
        tmp_path = _save_upload_to_temp(uploaded)
        raw_df = cached_load_log(tmp_path, fmt_choice)

    if raw_df.empty:
        st.warning("This log produced zero parsable rows. Check the file format matches what you selected.")
        st.stop()

    alerts_df = cached_run_detectors(raw_df)
    host_risk_df = compute_host_risk(alerts_df)

    render_header(raw_df, alerts_df)

    if page == "Overview":
        render_overview(raw_df, alerts_df, host_risk_df)
    elif page == "Alerts":
        render_alerts(alerts_df)
    elif page == "Domain Detail":
        render_domain_detail(raw_df, alerts_df)
    elif page == "Host Investigation":
        render_host_investigation(raw_df, alerts_df, host_risk_df)
    elif page == "Detector Performance":
        render_performance(raw_df, alerts_df)

    st.sidebar.divider()
    with st.sidebar.expander("MITRE ATT&CK reference"):
        for tactic in TACTIC_ORDER:
            st.markdown(f"**{tactic}**")
            for tid, name in MITRE_TECHNIQUES.items():
                if MITRE_TACTIC.get(tid) == tactic:
                    st.markdown(f"&nbsp;&nbsp;`{tid}` {name}")
    st.sidebar.caption("Demo data generated by log_generator.py - see README.md for detector methodology.")


if __name__ == "__main__":
    main()
