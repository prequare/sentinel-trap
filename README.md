# Sentinel Trap

A local honeypot intelligence platform using Cowrie, encrypted event storage, VirusTotal, Shodan, and Streamlit.

## Features

- Cowrie event ingestion
- Fernet-encrypted SQLite event storage
- Automatic ingestion every 30 seconds
- VirusTotal and Shodan IP enrichment
- Local OSINT result caching
- Streamlit dashboard with event search and metrics
- Automated tests

## Requirements

- Python 3
- Cowrie running locally
- VirusTotal API key
- Shodan API key

## Installation

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    python -m pip install -r requirements.txt

## Configuration

Local configuration files:

- `~/.config/sentinel-trap/fernet.key`
- `~/.config/sentinel-trap/api.env`
- `~/.config/sentinel-trap/osint-cache.json`

The API configuration file uses `VT_API_KEY` and `SHODAN_API_KEY`.
Keep real API keys private. Never overwrite an existing Fernet key,
because previously encrypted records may become unreadable.

## Run the dashboard

    python -m streamlit run app.py

## Run automatic ingestion

In a separate terminal:

    cd ~/sentinel-trap
    source .venv/bin/activate
    python auto_ingest.py

The ingestion process checks Cowrie logs every 30 seconds.
Press Ctrl+C to stop it.

## Cowrie safety

For local testing, keep Cowrie bound to `127.0.0.1:2222`.
Do not expose the honeypot to the public internet.

Default Cowrie log path:

    ~/cowrie/var/log/cowrie/cowrie.json

## Tests

    python -m pytest -q

    python -m py_compile app.py auto_ingest.py crypto_store.py osint_enrichment.py

## Security notes

- Database files, secrets, virtual environments, and backups must stay out of Git.
- Private and local IP addresses are skipped by OSINT enrichment.
- OSINT results may be incomplete or outdated.
- API providers may enforce quotas and rate limits.
