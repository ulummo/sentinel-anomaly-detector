"""Isolation Forest based network-flow anomaly scoring."""
from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler


def score_flows(data: pd.DataFrame, features: list[str], contamination: float = 0.04,
                random_state: int = 42) -> pd.DataFrame:
    """Fit an Isolation Forest and append anomaly labels and normalized scores."""
    if len(data) < 10:
        raise ValueError("At least 10 traffic records are required for anomaly detection.")
    if not features:
        raise ValueError("At least one numeric feature is required.")
    x = data[features].apply(pd.to_numeric, errors="coerce")
    model = make_pipeline(
        SimpleImputer(strategy="median"),
        RobustScaler(),
        IsolationForest(
            n_estimators=250,
            contamination=min(max(float(contamination), 0.001), 0.25),
            random_state=random_state,
            n_jobs=-1,
        ),
    )
    model.fit(x)
    forest = model[-1]
    raw = -forest.score_samples(model[1].transform(model[0].transform(x)))
    low, high = float(raw.min()), float(raw.max())
    normalized = (raw - low) / (high - low) if high > low else raw * 0
    result = data.copy()
    result["anomaly_score"] = normalized
    result["is_anomaly"] = forest.predict(model[1].transform(model[0].transform(x))) == -1
    result["severity"] = pd.cut(
        result["anomaly_score"], bins=[-0.001, 0.65, 0.85, 1.001],
        labels=["LOW", "MEDIUM", "HIGH"], include_lowest=True
    ).astype(str)
    return result.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
