import time
from crypto_store import store_events
from osint_enrichment import enrich_ip

INTERVAL_SECONDS = 30


def process_new_events():
    """Store new Cowrie events and enrich each unique source IP."""
    new_events = store_events() or []
    checked_ips = set()

    for event in new_events:
        ip = event.get("src_ip")
        if not ip or ip in checked_ips:
            continue

        checked_ips.add(ip)
        try:
            result = enrich_ip(ip)
            print(
                f"OSINT {ip}: "
                f"VirusTotal={result.get('virustotal', {}).get('status', 'n/a')}, "
                f"Shodan={result.get('shodan', {}).get('status', 'n/a')}, "
                f"cache={result.get('cache', 'n/a')}"
            )
        except Exception as error:
            print(f"OSINT lookup failed for {ip}: {type(error).__name__}")

    return len(new_events)


def run_forever():
    print("Sentinel Trap automatic ingestion started.")
    print("Checking Cowrie logs every 30 seconds.")
    print("Automatic OSINT enrichment enabled.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            process_new_events()
            time.sleep(INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nAutomatic ingestion stopped.")


if __name__ == "__main__":
    run_forever()
