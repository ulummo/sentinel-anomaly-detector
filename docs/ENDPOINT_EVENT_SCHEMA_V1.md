# Endpoint event schema v1

**Schema version:** `1.0`

This contract describes connection observations collected by the experimental Windows endpoint sensor. One row represents one observation of a TCP socket visible to that Windows host.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | ISO 8601 datetime | Time the socket was observed (UTC recommended) |
| `src_ip` | IP address | Local endpoint address |
| `dst_ip` | IP address | Remote endpoint address |
| `src_port` | integer, 0–65535 | Local endpoint port |
| `dst_port` | integer, 0–65535 | Remote endpoint port |
| `protocol` | `TCP` or `UDP` | Transport protocol |
| `duration` | non-negative number | Time the sensor has observed this socket |

## Optional fields

| Field | Meaning |
|---|---|
| `status` | Operating-system socket state, when available |
| `pid` | Process identifier, when available |
| `process` | Process name, when available |

## Explicitly not provided by the current socket sensor

The current sensor does not capture packet payloads or measure per-connection byte and packet counts. Do not populate `bytes`, `packets`, or throughput fields with guessed values. Those fields may be present in other imported datasets, but they are not part of this sensor's v1 contract.

## Validation behavior

The validator normalizes column names and protocol casing, parses timestamps, checks IP addresses, validates port ranges, and rejects rows with invalid required values. It returns valid rows separately from row-level error messages. Missing optional metadata does not invalidate an observation.

## Trust boundaries

The values are endpoint-reported telemetry, not independently verified network truth. Future server ingestion must authenticate the reporting device, validate organization ownership, impose payload limits, and record the agent version before accepting events.
