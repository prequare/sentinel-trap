import pandas as pd
import streamlit as st

from crypto_store import load_decrypted_events, store_events

st.set_page_config(
    page_title="Sentinel Trap",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sentinel Trap")
st.caption("Encrypted Honeypot Intelligence Platform")


@st.cache_data(ttl=5)
def load_dashboard_events():
    events = load_decrypted_events()

    return [
        {
            "Timestamp": event.get("timestamp", ""),
            "Event": event.get("eventid", "unknown"),
            "Source IP": event.get("src_ip", ""),
            "Username": event.get("username", ""),
        }
        for event in events
    ]


if st.button("Import new Cowrie events"):
    try:
        store_events()
        load_dashboard_events.clear()
        st.success("Cowrie events import check complete.")
    except Exception as error:
        st.error(f"Import failed: {error}")


if st.button("Refresh events"):
    load_dashboard_events.clear()

try:
    df = pd.DataFrame(
        load_dashboard_events(),
        columns=["Timestamp", "Event", "Source IP", "Username"],
    )
except Exception as error:
    st.error(f"Unable to load encrypted events: {error}")
    st.stop()

if df.empty:
    st.warning("No events found in the encrypted database yet.")
    st.info("Run `python crypto_store.py` to import Cowrie events.")
    st.stop()

col1, col2, col3 = st.columns(3)

col1.metric("Total Events", len(df))
col2.metric(
    "Unique IPs",
    df["Source IP"].replace("", pd.NA).nunique(),
)
col3.metric(
    "Login Attempts",
    df["Event"].isin(
        ["cowrie.login.failed", "cowrie.login.success"]
    ).sum(),
)

st.subheader("Recent Honeypot Activity")

search = st.text_input("Search IP, username, or event")
view = df.copy()

if search:
    mask = (
        view["Source IP"].astype(str).str.contains(
            search, case=False, na=False
        )
        | view["Username"].astype(str).str.contains(
            search, case=False, na=False
        )
        | view["Event"].astype(str).str.contains(
            search, case=False, na=False
        )
    )
    view = view[mask]

st.dataframe(
    view.tail(200).iloc[::-1],
    use_container_width=True,
)

st.subheader("Event Breakdown")
st.bar_chart(df["Event"].value_counts().head(10))

st.caption(
    "Events are decrypted from the local Fernet-encrypted database."
)
