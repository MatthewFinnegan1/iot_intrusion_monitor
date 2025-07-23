import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh

st_autorefresh(interval=3000, key="data_refresh")
st.set_page_config(layout="wide", page_title="Home Network Intrusion Monitor")

# Load data
def load_traffic_log():
    try:
        df = pd.read_csv("data/traffic_log.csv", header=None, names=["timestamp", "src", "dst"])
        return df
    except:
        return pd.DataFrame(columns=["timestamp", "src", "dst"])

def load_seen_ips():
    try:
        df = pd.read_csv("detection/seen_ips.csv", header=None, names=["ip", "timestamp", "score", "verdict"])
        return df.set_index("ip")
    except:
        return pd.DataFrame(columns=["ip", "timestamp", "score", "verdict"]).set_index("ip")

def get_stats_and_annotated(traffic_df, seen_df):
    verdicts = traffic_df["dst"].map(seen_df["verdict"]).fillna("Unknown")
    traffic_df = traffic_df.copy()
    traffic_df["verdict"] = verdicts
    stats = {
        "Safe": (verdicts == "Safe").sum(),
        "Suspicious": (verdicts == "Suspicious").sum(),
        "Malicious": (verdicts == "Malicious").sum(),
        "Total": len(traffic_df)
    }
    return stats, traffic_df

# Colors
SAFE_COLOR = "#4caf50"
SUSPICIOUS_COLOR = "#ff9800"
MALICIOUS_COLOR = "#f44336"
TEXT_COLOR = "#fff"
CARD_BG = "#1e1e26"

# CSS Styling
st.markdown(f"""
    <style>
    .card {{
        background: {CARD_BG};
        padding: 2rem;
        border-radius: 1.25rem;
        box-shadow: 0 2px 20px #0004;
    }}
    .button {{
        width: 100%;
        padding: 0.75rem;
        margin-top: 1rem;
        font-size: 1rem;
        font-weight: 600;
        color: {TEXT_COLOR};
        border: none;
        border-radius: 0.75rem;
        cursor: pointer;
        transition: background 0.2s ease;
        box-shadow: 0 1px 6px #0003;
    }}
    .safe {{ background: {SAFE_COLOR}; }}
    .safe:hover {{ background: #45a145; }}
    .suspicious {{ background: {SUSPICIOUS_COLOR}; color: #111; }}
    .suspicious:hover {{ background: #f4a733; }}
    .malicious {{ background: {MALICIOUS_COLOR}; }}
    .malicious:hover {{ background: #da3b2d; }}
    .metric-label {{
        font-size: 1.1rem;
        margin-bottom: 0.5rem;
        color: #aaa;
    }}
    .metric-value {{
        font-size: 2.2rem;
        font-weight: bold;
        color: white;
    }}
    </style>
""", unsafe_allow_html=True)

# Header
st.markdown("<h1 style='text-align:center; margin-bottom:2rem;'>Home Network Intrusion Monitor</h1>", unsafe_allow_html=True)

# Load & annotate
traffic_df = load_traffic_log()
seen_df = load_seen_ips()
stats, traffic_df = get_stats_and_annotated(traffic_df, seen_df)

# Layout
left, right = st.columns([1, 2], gap="large")

# ----- LEFT COLUMN -----
with left:
    

    st.markdown('<div class="card-tab-style">', unsafe_allow_html=True)
    st.markdown('<div class="tab-total">Total Packets Checked: {}</div>'.format(stats["Total"]), unsafe_allow_html=True)

    # Safe
    if st.button(f"{stats['Safe']} Safe Packets", key="safe_tab"):
        with st.modal("Safe Packet Details"):
            st.dataframe(traffic_df[traffic_df["verdict"] == "Safe"], use_container_width=True)
    

    # Suspicious
    if st.button(f"{stats['Suspicious']} Suspicious Packets", key="suspicious_tab"):
        with st.modal("Suspicious Packet Details"):
            st.dataframe(traffic_df[traffic_df["verdict"] == "Suspicious"], use_container_width=True)
   

    # Malicious
    if st.button(f"{stats['Malicious']} Malicious Packets", key="malicious_tab"):
        with st.modal("Malicious Packet Details"):
            st.dataframe(traffic_df[traffic_df["verdict"] == "Malicious"], use_container_width=True)
    

    st.markdown("</div>", unsafe_allow_html=True)


# ----- RIGHT COLUMN -----
with right:
    st.markdown("<div style='font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;'>Live Traffic Feed</div>", unsafe_allow_html=True)

    color_map = {
        "Safe": SAFE_COLOR,
        "Suspicious": SUSPICIOUS_COLOR,
        "Malicious": MALICIOUS_COLOR,
        "Unknown": "#aaa"
    }

    traffic_df["line"] = traffic_df.apply(
        lambda row: f"<span style='color: {color_map.get(row['verdict'], '#bbb')};'>"
                    f"[{row['timestamp']}] {row['src']} → {row['dst']} ({row['verdict']})</span>", axis=1)
    
    log_html = "<br>".join(traffic_df["line"].tolist()[-200:])
    st.markdown(
        f"""
        <div style='height:400px;overflow-y:auto;font-family:monospace;background:#111;
        padding:1rem;border-radius:0.8rem;border:1px solid #333;'>
        {log_html}
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)
