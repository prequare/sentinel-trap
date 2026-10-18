import time
from crypto_store import store_events

INTERVAL_SECONDS = 30

print("Sentinel Trap automatic ingestion started.")
print("Checking Cowrie logs every 30 seconds.")
print("Press Ctrl+C to stop.")

try:
    while True:
        store_events()
        time.sleep(INTERVAL_SECONDS)
except KeyboardInterrupt:
    print("\nAutomatic ingestion stopped.")
