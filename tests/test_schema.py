import pandas as pd

from sentinel.schema import ENDPOINT_SCHEMA_VERSION, validate_endpoint_frame


def sample_frame():
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-11-18T05:08:00Z",
                "src_ip": "192.168.1.10",
                "dst_ip": "1.1.1.1",
                "src_port": 50123,
                "dst_port": 443,
                "protocol": "tcp",
                "duration": 2.5,
                "status": "ESTABLISHED",
                "pid": 1234,
                "process": "example.exe",
            }
        ]
    )


def test_endpoint_schema_is_versioned_and_normalizes_valid_rows():
    valid, errors = validate_endpoint_frame(sample_frame())
    assert ENDPOINT_SCHEMA_VERSION == "1.0"
    assert errors == []
    assert len(valid) == 1
    assert valid.iloc[0]["protocol"] == "TCP"
    assert valid.iloc[0]["src_port"] == 50123
    assert pd.notna(valid.iloc[0]["timestamp"])


def test_endpoint_schema_rejects_invalid_ip_port_and_timestamp():
    frame = sample_frame()
    frame.loc[0, "src_ip"] = "not-an-ip"
    frame.loc[0, "dst_port"] = 70000
    frame.loc[0, "timestamp"] = "not-a-date"
    valid, errors = validate_endpoint_frame(frame)
    assert valid.empty
    assert len(errors) == 1
    assert "src_ip" in errors[0]
    assert "dst_port" in errors[0]
    assert "timestamp" in errors[0]


def test_endpoint_schema_reports_missing_columns():
    valid, errors = validate_endpoint_frame(pd.DataFrame({"src_ip": ["127.0.0.1"]}))
    assert valid.empty
    assert len(errors) == 1
    assert "timestamp" in errors[0]


def test_endpoint_schema_does_not_require_or_invent_traffic_counters():
    frame = sample_frame().drop(columns=["status", "pid", "process"])
    valid, errors = validate_endpoint_frame(frame)
    assert errors == []
    assert len(valid) == 1
    assert "bytes" not in valid.columns
    assert "packets" not in valid.columns
