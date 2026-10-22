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
