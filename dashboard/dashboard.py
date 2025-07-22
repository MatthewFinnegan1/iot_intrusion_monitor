import streamlit as st
import pandas as pd
import streamlit.components.v1 as components
import time

# Load CSV data
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

# Calculate stats
def calculate_stats(traffic_df, seen_df):
    verdicts = traffic_df["dst"].map(seen_df["verdict"]).fillna("Unknown")
    return {
        "total": len(traffic_df),
        "safe": (verdicts == "Safe").sum(),
        "suspicious": (verdicts == "Suspicious").sum(),
        "malicious": (verdicts == "Malicious").sum()
    }, verdicts

# Color line formatter
def format_line(row):
    color = {
        "Safe": "green",
        "Suspicious": "orange",
        "Malicious": "red"
    }.get(row["verdict"], "gray")
    return f"<span style='color:{color}'>[{row['timestamp']}] {row['src']} → {row['dst']} ({row['verdict']})</span>"

# Streamlit setup
st.set_page_config(layout="wide", page_title="Home Network Intrusion Monitor")
st.markdown("## Home Network Intrusion Monitor")

# Layout setup
left_col, right_col = st.columns([1, 2])

# Static stats
with left_col:
    st.markdown("### Packet Stats")
    stats_placeholder = st.empty()

# Live feed block
with right_col:
    st.markdown("### Live Traffic Feed")
    feed_placeholder = st.empty()

# Manual update loop
while True:
    traffic_df = load_traffic_log()
    seen_df = load_seen_ips()
    traffic_df["verdict"] = traffic_df["dst"].map(seen_df["verdict"]).fillna("Unknown")
    traffic_df["line"] = traffic_df.apply(format_line, axis=1)

    # Stats update
    verdicts = traffic_df["verdict"]
    stats = {
        "Total Packets Checked": len(traffic_df),
        "Malicious Packets": (verdicts == "Malicious").sum(),
        "Suspicious Packets": (verdicts == "Suspicious").sum(),
        "Safe Packets": (verdicts == "Safe").sum()
    }
    with stats_placeholder.container():
        for k, v in stats.items():
            st.metric(k, v)

    # Feed update (latest 200 lines)
    log_html = "<br>".join(traffic_df["line"].tolist()[-200:])
    feed_placeholder.markdown(
        f"""
        <div id='traffic-log' style='height:400px; overflow-y:auto; font-family:monospace; background:#111; padding:10px; border-radius:5px; border:1px solid #333;'>
        {log_html}
        </div>

        <script>
        const container = document.getElementById("traffic-log");
        let autoScroll = sessionStorage.getItem("autoScroll") !== "false";

        container.addEventListener("scroll", () => {{
            const atBottom = Math.abs(container.scrollHeight - container.scrollTop - container.clientHeight) < 5;
            autoScroll = atBottom;
            sessionStorage.setItem("autoScroll", autoScroll);
        }});

        const scrollToBottom = () => {{
            if (sessionStorage.getItem("autoScroll") !== "false") {{
                container.scrollTop = container.scrollHeight;
            }}
        }};
        requestAnimationFrame(scrollToBottom);
        </script>
        """,
        unsafe_allow_html=True
    )

    time.sleep(3)  # Refresh interval
