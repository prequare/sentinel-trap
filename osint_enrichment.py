
import ipaddress
import json
import time
from pathlib import Path

import requests

KEY_FILE = Path.home() / ".config/sentinel-trap/api.env"
CACHE_FILE = Path.home() / ".config/sentinel-trap/osint-cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60
TIMEOUT = 10


def load_api_keys():
    """Load API keys from a private local configuration file."""
    if not KEY_FILE.exists():
        raise RuntimeError("OSINT configuration file not found.")

    keys = {}
    for line in KEY_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        keys[name.strip()] = value.strip().strip("'\"")

    if not keys.get("VT_API_KEY") or not keys.get("SHODAN_API_KEY"):
        raise RuntimeError("One or more OSINT API keys are missing.")

    return keys


def load_cache():
    """Read unexpired cached OSINT results."""
    try:
        cache = json.loads(CACHE_FILE.read_text())
        now = time.time()
        return {
            ip: entry
            for ip, entry in cache.items()
            if now - entry.get("cached_at", 0) < CACHE_TTL_SECONDS
        }
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}


def save_cache(cache):
    """Save cache locally with restrictive file permissions."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.parent.chmod(0o700)

    temp_file = CACHE_FILE.with_suffix(".tmp")
    temp_file.write_text(json.dumps(cache, indent=2))
    temp_file.chmod(0o600)
    temp_file.replace(CACHE_FILE)


def enrich_ip(ip):
    """Fetch or reuse threat intelligence for a public IP."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"ip": str(ip), "status": "invalid_ip"}

    if not address.is_global:
        return {"ip": str(address), "status": "skipped_non_public_ip"}

    address = str(address)
    cache = load_cache()
    cached = cache.get(address)

    if cached and "result" in cached:
        result = cached["result"].copy()
        result["cache"] = "hit"
        return result

    keys = load_api_keys()
    result = {
        "ip": address,
        "virustotal": {},
        "shodan": {},
    }

    # VirusTotal IP reputation
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{address}",
            headers={"x-apikey": keys["VT_API_KEY"]},
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            result["virustotal"] = {
                "status": "ok",
                "reputation": attributes.get("reputation"),
                "country": attributes.get("country"),
                "as_owner": attributes.get("as_owner"),
                "detections": attributes.get("last_analysis_stats", {}),
            }
        else:
            result["virustotal"] = {
                "status": "unavailable",
                "http_status": response.status_code,
            }
    except (requests.RequestException, ValueError):
        result["virustotal"] = {"status": "request_failed"}

    # Shodan host information
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{address}",
            params={"key": keys["SHODAN_API_KEY"]},
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json()
            result["shodan"] = {
                "status": "ok",
                "organization": data.get("org"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
            }
        else:
            result["shodan"] = {
                "status": "unavailable",
                "http_status": response.status_code,
            }
    except (requests.RequestException, ValueError):
        result["shodan"] = {"status": "request_failed"}

    # Cache only if at least one service returned useful data.
    if (
        result["virustotal"].get("status") == "ok"
        or result["shodan"].get("status") == "ok"
    ):
        cache[address] = {
            "cached_at": time.time(),
            "result": result,
        }
        save_cache(cache)

    result["cache"] = "miss"
    return result

