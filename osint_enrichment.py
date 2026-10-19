import ipaddress
from pathlib import Path

import requests

KEY_FILE = Path.home() / ".config/sentinel-trap/api.env"
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


def enrich_ip(ip):
    """Fetch threat intelligence for one public IP address."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"ip": str(ip), "status": "invalid_ip"}

    if not address.is_global:
        return {"ip": str(address), "status": "skipped_non_public_ip"}

    keys = load_api_keys()
    result = {
        "ip": str(address),
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
    except requests.RequestException:
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
    except requests.RequestException:
        result["shodan"] = {"status": "request_failed"}

    return result
