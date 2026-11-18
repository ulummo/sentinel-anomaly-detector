import pandas as pd
import pytest

from sentinel.data import generate_demo_data, prepare_flows
from sentinel.detector import score_flows


def test_demo_data_has_expected_columns():
    frame = generate_demo_data(rows=200, seed=7)
    assert {"timestamp", "bytes", "packets", "duration", "dst_port"}.issubset(frame.columns)
    assert len(frame) == 200


def test_detector_returns_scores_and_labels():
    frame, features = prepare_flows(generate_demo_data(rows=200, seed=7))
    result = score_flows(frame, features, contamination=0.05)
    assert {"anomaly_score", "is_anomaly", "severity"}.issubset(result.columns)
    assert result["anomaly_score"].between(0, 1).all()
    assert result["is_anomaly"].any()


def test_detector_requires_enough_rows():
    with pytest.raises(ValueError, match="At least 10"):
        score_flows(pd.DataFrame({"bytes": range(5)}), ["bytes"])
