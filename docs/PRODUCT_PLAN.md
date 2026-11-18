# Sentinel SMB Product Plan

## Product goal

Build a practical security-monitoring platform for small and medium-sized businesses. The first release should help a small IT team understand which managed Windows endpoints are reporting, review unusual connection metadata, and investigate alerts with enough context to decide what to do next.

Sentinel is not currently an antivirus, EDR replacement, firewall, packet-capture system, or certified intrusion-prevention product. The current Streamlit application is a local prototype.

## Initial customer and use case

- Customer: an SMB with roughly 5–100 Windows workstations and no dedicated 24/7 SOC.
- Primary user: an IT generalist or managed service provider.
- Core job: answer "Which devices reported unusual network activity, what happened, and what should I check next?"
- Deployment assumption for MVP: a small centrally managed server plus an explicitly installed Windows endpoint agent.

## MVP scope

### 1. Endpoint inventory and health
- Give each enrolled endpoint a stable device identity.
- Report hostname, agent version, OS version, last check-in, and sensor status.
- Show stale/offline endpoints separately from healthy endpoints.
- Do not collect unrelated personal files or content.

### 2. Secure event ingestion
- Agent sends structured connection metadata to an authenticated HTTPS API.
- Each device receives a revocable enrollment credential.
- Validate payload shape, timestamps, size limits, and device ownership.
- Use TLS in transit; store secrets as hashes where practical.
- Do not trust a device-supplied company or device identifier without verifying its credential.

### 3. Detection and investigation
- Preserve source observations separately from derived features and model output.
- Show why an event was flagged: feature values, baseline/context, model version, and rule matches.
- Distinguish anomaly score from confirmed severity or incident status.
- Provide analyst states: New, In review, Benign, Escalated, Resolved.
- Keep an audit trail for analyst actions.

### 4. SMB dashboard
- Overview: enrolled devices, online devices, recent alerts, and sensor health.
- Devices: inventory and last check-in.
- Alerts: searchable queue with filters and investigation details.
- Reports: time-bounded CSV/PDF export with clear limitations.
- Settings: organization and enrollment management (later MVP milestone).

## Non-goals for the first MVP

- Automatic blocking or remediation.
- Packet payload capture or TLS interception.
- Whole-LAN visibility from a single workstation.
- Claims that an anomaly is a confirmed attack.
- Multi-region high availability or enterprise compliance certification.

## Current prototype baseline

The repository currently contains:
- A Streamlit dashboard that accepts CSV uploads, generates demo data, runs Isolation Forest, and exports findings.
- An experimental Windows sensor that enumerates TCP sockets visible to one Windows host using psutil.
- The sensor records connection metadata such as local/remote IP and port, status, PID, process name, timestamp, and observed duration.
- The sensor does not capture packet payloads, bytes, or packet counts, and does not see other LAN devices' unicast traffic.

The dashboard can derive frequency features from available columns. Such scores are relative to the dataset and model settings; they are not proof of malicious activity.

## Delivery sequence

1. **Reliability and data contract**
   - Define a versioned event schema.
   - Add input validation and tests for endpoint CSVs and uploaded datasets.
   - Make the UI clearly label Demo, Uploaded, and Local Sensor data.
2. **Single-server ingestion prototype**
   - Add an API service and persistent database.
   - Enroll one endpoint with a revocable token.
   - Receive and query heartbeat and connection metadata.
3. **Device inventory**
   - Show device identity, health, last-seen time, and agent version.
4. **Alert workflow**
   - Store alert lifecycle and analyst notes.
   - Add transparent rule-based context alongside anomaly scoring.
5. **Organization accounts and deployment**
   - Add tenant isolation, user authentication, roles, backups, and operational monitoring.
   - Complete security review before external customer pilots.

## Security and privacy principles

- Collect the minimum telemetry needed for the stated security purpose.
- Make collection scope visible to administrators.
- Authenticate every enrolled agent and support credential revocation.
- Enforce organization-level data isolation on the server.
- Encrypt traffic in transit and protect stored credentials.
- Log administrative and investigation actions.
- Set retention periods and provide deletion/export controls.
- Require explicit authorization to monitor each endpoint and network.

## Definition of a credible pilot

A pilot is not ready until:
- An administrator can enroll and revoke a test endpoint.
- The endpoint can securely check in and send schema-validated events.
- The dashboard correctly shows device health and recent events.
- An analyst can investigate, annotate, and resolve an alert.
- Automated tests cover authentication, tenant isolation, validation, and alert workflow.
- Documentation explains exactly what the sensor observes and does not observe.
