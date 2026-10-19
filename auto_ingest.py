import time
from crypto_store import store_events
from osint_enrichment import enrich_ip

INTERVAL_SECONDS = 30

print("Sentinel Trap automatic ingestion started.")
print("Checking Cowrie logs every 30 seconds.")
print("Automatic OSINT enrichment enabled.")
print("Press Ctrl+C to stop.")

try:
    while True:
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

        time.sleep(INTERVAL_SECONDS)

except KeyboardInterrupt:
    print("\nAutomatic ingestion stopped.")
