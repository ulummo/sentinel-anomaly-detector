"""Versioned data contract and validation for Sentinel endpoint observations."""
from __future__ import annotations

import ipaddress
from typing import Iterable

import pandas as pd

ENDPOINT_SCHEMA_VERSION = "1.0"

REQUIRED_ENDPOINT_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration",
)

OPTIONAL_ENDPOINT_COLUMNS = ("status", "pid", "process")


def validate_endpoint_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Return normalized valid endpoint rows and human-readable row errors.

    This validates socket metadata emitted by the Windows endpoint sensor. It
    intentionally does not require or fabricate bytes/packet counters.
    """
    if not isinstance(frame, pd.DataFrame):
        raise TypeError("Expected a pandas DataFrame.")
    if frame.empty:
        return frame.copy(), ["No endpoint observations were supplied."]

    data = frame.copy()
    data.columns = [str(column).strip().lower() for column in data.columns]
    missing = [column for column in REQUIRED_ENDPOINT_COLUMNS if column not in data.columns]
    if missing:
        return data.iloc[0:0].copy(), [
            "Missing required endpoint columns: " + ", ".join(missing)
        ]

    # pandas 3 may infer Arrow-backed string columns; normalize into object
    # columns so parsed timestamps and integer ports can be assigned safely.
    for column in REQUIRED_ENDPOINT_COLUMNS:
        data[column] = data[column].astype("object")

    valid_indices: list[int] = []
    errors: list[str] = []

    for index, row in data.iterrows():
        problems: list[str] = []
        timestamp = pd.to_datetime(row["timestamp"], errors="coerce", utc=True)
        if pd.isna(timestamp):
            problems.append("timestamp is not a valid date/time")

        for column in ("src_ip", "dst_ip"):
            try:
                ipaddress.ip_address(str(row[column]).strip())
            except ValueError:
                problems.append(f"{column} is not a valid IP address")

        ports: dict[str, int] = {}
        for column in ("src_port", "dst_port"):
            try:
                value = float(row[column])
                if not value.is_integer() or not 0 <= value <= 65535:
                    raise ValueError
                ports[column] = int(value)
            except (TypeError, ValueError, OverflowError):
                problems.append(f"{column} must be an integer from 0 to 65535")

        protocol = str(row["protocol"]).strip().upper()
        if protocol not in {"TCP", "UDP"}:
            problems.append("protocol must be TCP or UDP")

        try:
            duration = float(row["duration"])
            if pd.isna(duration) or duration < 0:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            problems.append("duration must be a non-negative number")

        if problems:
            errors.append(f"Row {index}: " + "; ".join(problems))
            continue

        data.at[index, "timestamp"] = timestamp
        data.at[index, "src_ip"] = str(row["src_ip"]).strip()
        data.at[index, "dst_ip"] = str(row["dst_ip"]).strip()
        data.at[index, "src_port"] = ports["src_port"]
        data.at[index, "dst_port"] = ports["dst_port"]
        data.at[index, "protocol"] = protocol
        data.at[index, "duration"] = duration
        valid_indices.append(index)

    return data.loc[valid_indices].copy(), errors
