"""Demo traffic generation and input normalization."""
from __future__ import annotations

import numpy as np
import pandas as pd


def generate_demo_data(rows: int = 1200, seed: int = 42) -> pd.DataFrame:
    """Create realistic-looking baseline flows plus a small set of outliers."""
    rng = np.random.default_rng(seed)
    n = max(100, int(rows))
    timestamps = pd.date_range(end=pd.Timestamp.now().floor("min"), periods=n, freq="min")
    duration = rng.lognormal(mean=0.2, sigma=0.65, size=n).clip(0.02, 90)
    packets = rng.poisson(lam=18, size=n).clip(1)
    byte_count = (packets * rng.lognormal(mean=5.0, sigma=0.55, size=n)).astype(int)
    ports = rng.choice([53, 80, 123, 443, 8080, 22], size=n, p=[.12,.18,.08,.42,.12,.08])
    protocol = np.where(np.isin(ports, [53, 123]), "UDP", "TCP")
    src = [f"10.0.{int(x)}.{int(y)}" for x, y in zip(rng.integers(0, 12, n), rng.integers(2, 250, n))]
    dst = [f"172.16.{int(x)}.{int(y)}" for x, y in zip(rng.integers(0, 8, n), rng.integers(2, 250, n))]
    frame = pd.DataFrame({
        "timestamp": timestamps, "src_ip": src, "dst_ip": dst,
        "src_port": rng.integers(1024, 65535, n), "dst_port": ports,
        "protocol": protocol, "duration": duration, "bytes": byte_count,
        "packets": packets,
    })
    # Inject a small, deterministic set of unusual high-volume / long-lived flows.
    count = max(8, n // 70)
    idx = rng.choice(n, size=count, replace=False)
    frame.loc[idx, "duration"] *= rng.uniform(8, 25, count)
    frame.loc[idx, "bytes"] *= rng.integers(30, 100, count)
    frame.loc[idx, "packets"] *= rng.integers(12, 35, count)
    frame.loc[idx, "dst_port"] = rng.choice([4444, 31337, 9001], count)
    return frame


def prepare_flows(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Return a cleaned copy and numeric features suitable for the detector."""
    if frame.empty:
        raise ValueError("The uploaded dataset is empty.")
    data = frame.copy()
    data.columns = [str(c).strip().lower() for c in data.columns]
    numeric = data.select_dtypes(include="number").columns.tolist()
    for col in ("duration", "bytes", "packets", "src_port", "dst_port"):
        if col in data.columns and col not in numeric:
            data[col] = pd.to_numeric(data[col], errors="coerce")
            if data[col].notna().any():
                numeric.append(col)
    if "bytes_per_second" not in data and {"bytes", "duration"}.issubset(data.columns):
        data["bytes_per_second"] = data["bytes"] / data["duration"].clip(lower=0.001)
        numeric.append("bytes_per_second")
    if "packets_per_second" not in data and {"packets", "duration"}.issubset(data.columns):
        data["packets_per_second"] = data["packets"] / data["duration"].clip(lower=0.001)
        numeric.append("packets_per_second")
    features = list(dict.fromkeys(c for c in numeric if c in data.columns))
    features = [c for c in features if data[c].notna().any()]
    if not features:
        raise ValueError("No usable numeric columns found. Include fields such as bytes, packets, duration, or ports.")
    data[features] = data[features].replace([np.inf, -np.inf], np.nan)
    data[features] = data[features].fillna(data[features].median()).fillna(0)
    return data, features
