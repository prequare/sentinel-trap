import auto_ingest


def test_new_events_trigger_osint_once_per_unique_ip(monkeypatch):
    events = [
        {"src_ip": "198.51.100.10"},
        {"src_ip": "198.51.100.10"},
        {"src_ip": "203.0.113.25"},
        {},
    ]
    enriched = []

    monkeypatch.setattr(auto_ingest, "store_events", lambda: events)

    def fake_enrich_ip(ip):
        enriched.append(ip)
        return {
            "virustotal": {"status": "ok"},
            "shodan": {"status": "ok"},
            "cache": "miss",
        }

    monkeypatch.setattr(auto_ingest, "enrich_ip", fake_enrich_ip)

    count = auto_ingest.process_new_events()

    assert count == 4
    assert enriched == ["198.51.100.10", "203.0.113.25"]

def test_automatic_ingestion_saves_osint_cache(tmp_path, monkeypatch):
    import json
    import osint_enrichment

    cache_file = tmp_path / "osint-cache.json"
    monkeypatch.setattr(osint_enrichment, "CACHE_FILE", cache_file)
    monkeypatch.setattr(
        osint_enrichment,
        "load_api_keys",
        lambda: {
            "VT_API_KEY": "test-key",
            "SHODAN_API_KEY": "test-key",
        },
    )

    class FakeResponse:
        status_code = 200

        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data

    def fake_get(url, **kwargs):
        if "virustotal.com" in url:
            return FakeResponse({
                "data": {
                    "attributes": {
                        "reputation": 0,
                        "last_analysis_stats": {"malicious": 0},
                    }
                }
            })

        return FakeResponse({
            "org": "Example",
            "country_name": "United States",
            "ports": [443],
            "hostnames": [],
        })

    monkeypatch.setattr(osint_enrichment.requests, "get", fake_get)

    events = [{"src_ip": "8.8.4.4"}]
    monkeypatch.setattr(auto_ingest, "store_events", lambda: events)
    monkeypatch.setattr(auto_ingest, "enrich_ip", osint_enrichment.enrich_ip)

    count = auto_ingest.process_new_events()

    assert count == 1

    saved_cache = json.loads(cache_file.read_text())
    saved_result = saved_cache["8.8.4.4"]["result"]

    assert saved_result["virustotal"]["status"] == "ok"
    assert saved_result["shodan"]["status"] == "ok"
    import osint_enrichment

    events = [
        {"src_ip": "8.8.4.4"},
    ]
    calls = []

    monkeypatch.setattr(auto_ingest, "store_events", lambda: events)

    def fake_enrich_ip(ip):
        calls.append(ip)
        return osint_enrichment.enrich_ip(ip)

    monkeypatch.setattr(auto_ingest, "enrich_ip", fake_enrich_ip)

    count = auto_ingest.process_new_events()

    assert count == 1
    assert calls == ["8.8.4.4"]
