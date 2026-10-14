import json
from pathlib import Path

import pandas as pd
import streamlit as st

LOG_FILE = Path.home() / "cowrie/var/log/cowrie/cowrie.json"

st.set_page_config(
    page_title="Sentinel Trap",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sentinel Trap")
st.caption("Honeypot Intelligence Platform")

@st.cache_data(ttl=5)
def load_events(path, modified, size):
    events = []

    with open(path, "rb") as f:
        if size > 5_000_000:
            f.seek(-5_000_000, 2)
            f.readline()
        lines = f.readlines()

    for line in lines:
        try:
            item = json.loads(line)
            events.append({
                "Timestamp": item.get("timestamp", ""),
                "Event": item.get("eventid", "unknown"),
                "Source IP": item.get("src_ip", ""),
                "Username": item.get("username", ""),
            })
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

    return events

if st.button("Refresh events"):
    st.cache_data.clear()

if not LOG_FILE.exists():
    st.error(f"Cowrie log not found: {LOG_FILE}")
    st.stop()

try:
    stat = LOG_FILE.stat()
    events = load_events(str(LOG_FILE), stat.st_mtime, stat.st_size)
except OSError as error:
    st.error(f"Unable to read logs: {error}")
    st.stop()

df = pd.DataFrame(events)

if df.empty:
    st.warning("No readable events found in the Cowrie log yet.")
    st.stop()

col1, col2, col3 = st.columns(3)

col1.metric("Total Events", len(df))
col2.metric("Unique IPs", df["Source IP"].replace("", pd.NA).nunique())
col3.metric(
    "Login Attempts",
    df["Event"].isin([
        "cowrie.login.failed",
        "cowrie.login.success",
    ]).sum(),
)

st.subheader("Recent Honeypot Activity")

search = st.text_input("Search IP, username, or event")

view = df.copy()

if search:
    mask = (
        view["Source IP"].astype(str).str.contains(search, case=False, na=False)
        | view["Username"].astype(str).str.contains(search, case=False, na=False)
        | view["Event"].astype(str).str.contains(search, case=False, na=False)
    )
    view = view[mask]

st.dataframe(view.tail(200).iloc[::-1], use_container_width=True)

st.subheader("Event Breakdown")
st.bar_chart(df["Event"].value_counts().head(10))

st.caption("Local prototype — encryption and OSINT will be added next.")
