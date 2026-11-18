from sentinel import windows_sensor


def test_remote_sensor_url_requires_https():
    try:
        windows_sensor.validate_server_url("http://sentinel.example.com")
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("Remote HTTP must be rejected")


def test_loopback_sensor_url_is_allowed():
    assert windows_sensor.validate_server_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000/v1/events"


def test_heartbeat_posts_to_authenticated_endpoint(monkeypatch):
    calls = []

    def fake_post(url, token, payload, timeout=10):
        calls.append((url, token, payload, timeout))
        return {"status": "ok"}

    monkeypatch.setattr(windows_sensor, "_post_json", fake_post)
    windows_sensor.send_heartbeat("https://sentinel.example.com/", "x" * 40)

    assert calls == [("https://sentinel.example.com/v1/heartbeat", "x" * 40, {}, 10)]
