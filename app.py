
import ipaddress
import json

import pandas as pd
import streamlit as st

from crypto_store import load_decrypted_events, store_events
from osint_enrichment import enrich_ip

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

st.divider()
st.subheader("🌐 OSINT Enrichment")
st.caption(
    "Query VirusTotal and Shodan manually for a selected public IP. "
    "Each query may use API quota. Private and local IPs are skipped."
)
public_ip_options = sorted(
    {
        ip.strip()
        for ip in df["Source IP"].dropna().astype(str).unique()
        if ip.strip()
    }
    | {"8.8.8.8"}
)

if not public_ip_options:
    st.info("No source IPs are available for enrichment yet.")
else:
    selected_ip = st.selectbox(
        "Select a captured source IP",
        public_ip_options,
    )

    try:
        selected_address = ipaddress.ip_address(selected_ip.strip())
        is_public_ip = selected_address.is_global
    except ValueError:
        is_public_ip = False

    if not is_public_ip:
        st.info("This IP is invalid or non-public. OSINT lookup will be skipped.")

    if st.button("Enrich selected IP", disabled=not is_public_ip):
        with st.spinner("Querying VirusTotal and Shodan..."):
            try:
                result = enrich_ip(selected_ip)
                st.session_state["osint_result"] = result
                st.session_state["osint_result_ip"] = selected_ip
            except Exception:
                st.error(
                    "OSINT lookup failed. Check the local API configuration "
                    "and try again. Do not share your API keys."
                )

    result = st.session_state.get("osint_result")
    result_ip = st.session_state.get("osint_result_ip")

    if result and result_ip == selected_ip:
        if result.get("status") == "skipped_non_public_ip":
            st.info("Non-public IP skipped.")
        elif result.get("status") == "invalid_ip":
            st.warning("Invalid IP address.")
        else:
            cache_status = result.get("cache")

            if cache_status == "hit":
                st.success("OSINT Cache: HIT — saved result reused")
            elif cache_status == "miss":
                st.info("OSINT Cache: MISS — fresh lookup attempted")
            else:
                st.caption("OSINT Cache: status unavailable")
            vt = result.get("virustotal", {})
            shodan = result.get("shodan", {})

            left, right = st.columns(2)

            with left:
                st.markdown("#### VirusTotal")
                st.write("Status:", vt.get("status", "unknown"))
                if vt.get("status") == "ok":
                    st.metric(
                        "Reputation",
                        vt.get("reputation")
                        if vt.get("reputation") is not None
                        else "N/A",
                    )
                    st.write("Country:", vt.get("country") or "Unknown")
                    st.write("Network owner:", vt.get("as_owner") or "Unknown")
                    st.write("Analysis counts:")
                    st.json(vt.get("detections", {}))
                elif vt.get("http_status"):
                    st.write("HTTP status:", vt["http_status"])

            with right:
                st.markdown("#### Shodan")
                st.write("Status:", shodan.get("status", "unknown"))
                if shodan.get("status") == "ok":
                    st.write(
                        "Organization:",
                        shodan.get("organization") or "Unknown",
                    )
                    st.write("Country:", shodan.get("country") or "Unknown")
                    st.write("Observed ports:", shodan.get("ports", []))
                    st.write("Hostnames:", shodan.get("hostnames", []))
                elif shodan.get("http_status"):
                    st.write("HTTP status:", shodan["http_status"])

            st.caption(
                "OSINT results are contextual and may be incomplete or outdated. "
                "A reputation score alone does not prove malicious activity."
            )


st.divider()
st.subheader("Cached OSINT Results for Captured IPs")
st.caption(
    "Shows saved enrichment for captured source IPs. "
    "New public-IP lookups are performed by the automatic ingestion process."
)

try:
    cache_path = __import__("pathlib").Path.home() / ".config/sentinel-trap/osint-cache.json"
    cache_data = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    captured_ips = set(df["Source IP"].dropna().astype(str).str.strip())
    rows = []

    for ip in sorted(captured_ips):
        entry = cache_data.get(ip)
        if not entry or not isinstance(entry.get("result"), dict):
            continue

        result = entry["result"]
        vt = result.get("virustotal", {})
        shodan = result.get("shodan", {})
        detections = vt.get("detections", {})

        rows.append({
            "Source IP": ip,
            "VirusTotal": vt.get("status", "unknown"),
            "Reputation": vt.get("reputation"),
            "Malicious detections": detections.get("malicious"),
            "Shodan": shodan.get("status", "unknown"),
            "Organization": shodan.get("organization"),
            "Country": shodan.get("country") or vt.get("country"),
            "Observed ports": ", ".join(
                str(port) for port in shodan.get("ports", [])
            ),
            "Cache updated (UTC)": pd.to_datetime(
                entry.get("cached_at"), unit="s", utc=True, errors="coerce"
            ),
        })

    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info(
            "No cached OSINT results match the captured source IPs yet. "
            "Private/local IPs are skipped."
        )
except (OSError, ValueError, TypeError) as error:
    st.warning(f"Unable to read cached OSINT results: {error}")

st.caption(
    "Events are decrypted from the local Fernet-encrypted database."
)
st.divider()
st.subheader("All Cached OSINT Results")
st.caption(
    "Includes manual test lookups as well as cached enrichment. "
    "These IPs are not necessarily captured by Cowrie."
)

try:
    all_cache_rows = []

    for ip, entry in cache_data.items():
        if not isinstance(entry, dict):
            continue

        result = entry.get("result", {})
        if not isinstance(result, dict):
            continue

        vt = result.get("virustotal", {})
        shodan = result.get("shodan", {})
        detections = vt.get("detections", {})

        all_cache_rows.append({
            "IP": ip,
            "VirusTotal": vt.get("status", "unknown"),
            "Reputation": vt.get("reputation"),
            "Malicious detections": detections.get("malicious"),
            "Shodan": shodan.get("status", "unknown"),
            "Organization": shodan.get("organization"),
            "Country": shodan.get("country") or vt.get("country"),
            "Ports": ", ".join(
                str(port) for port in shodan.get("ports", [])
            ),
        })

    if all_cache_rows:
        st.dataframe(
            pd.DataFrame(all_cache_rows),
            use_container_width=True
        )
    else:
        st.info("No cached OSINT results available yet.")

except (NameError, OSError, ValueError, TypeError, AttributeError) as error:
    st.warning(f"Unable to display all cached OSINT results: {error}")
