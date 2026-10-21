import json
import time

import osint_enrichment


def test_invalid_ip_is_rejected():
    result = osint_enrichment.enrich_ip("not-an-ip")
    assert result["status"] == "invalid_ip"


def test_private_ip_is_skipped():
    result = osint_enrichment.enrich_ip("127.0.0.1")
    assert result["status"] == "skipped_non_public_ip"


def test_cached_result_does_not_need_api_keys(tmp_path, monkeypatch):
    cache_file = tmp_path / "osint-cache.json"
    expected = {
        "ip": "8.8.4.4",
        "virustotal": {"status": "ok"},
        "shodan": {"status": "ok"},
    }
    cache_file.write_text(json.dumps({
        "8.8.4.4": {
            "cached_at": time.time(),
            "result": expected,
        }
    }))

    monkeypatch.setattr(osint_enrichment, "CACHE_FILE", cache_file)

    def fail_if_keys_are_loaded():
        raise AssertionError("Cache hit should not load API keys")

    monkeypatch.setattr(osint_enrichment, "load_api_keys", fail_if_keys_are_loaded)

    result = osint_enrichment.enrich_ip("8.8.4.4")

    assert result["cache"] == "hit"
    assert result["virustotal"]["status"] == "ok"
    assert result["shodan"]["status"] == "ok"
