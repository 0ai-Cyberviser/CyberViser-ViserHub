# CyberViser Defensive Honeypot Dataset Pipeline

This document defines a public-safe blueprint for collecting defensive cybersecurity telemetry and converting it into sanitized datasets for Hancock, PeachTree, and PeachFuzz.

## Objective

Collect real-world internet attack patterns from isolated decoy services, normalize the observations, sanitize sensitive data, and transform the results into:

- detection engineering examples
- fuzzing seed corpora
- parser regression tests
- incident triage prompts
- safe LLM fine-tuning records

## Hard safety boundaries

Do not place honeypots on the same infrastructure as:

- GitHub Pages
- Google Workspace
- Google Admin
- Google Drive
- production email
- production APIs
- private repositories
- customer systems

Do not publish:

- raw source IP addresses
- credentials submitted by third parties
- malware binaries
- exploit kits
- private victim data
- session cookies or tokens
- cloud metadata tokens
- personally identifiable information

Publish only:

- sanitized schemas
- aggregate statistics
- redacted request examples
- benign synthetic reproducers
- defensive detection logic
- fuzz-safe minimized parser inputs

## Recommended architecture

```text
Internet
  |
  v
Isolated decoy sensors
  |-- HTTP/API low-interaction sensor
  |-- SSH/Telnet credential-attempt sensor
  |-- GraphQL/API schema lure
  |-- Object-storage path lure
  |-- Log/parser payload collector
  |
  v
Telemetry queue
  |
  v
Sanitizer + normalizer
  |-- redact secrets
  |-- hash IP addresses with private salt
  |-- truncate payloads
  |-- classify event type
  |-- map ATT&CK techniques
  |
  v
PeachTree dataset builder
  |
  +--> JSONL for Hancock triage training
  +--> NDJSON for detection analytics
  +--> fuzz seeds for PeachFuzz
  +--> minimized regression reproducers
```

## Sensor classes

| Sensor | Purpose | Dataset value |
|---|---|---|
| HTTP low-interaction | Capture paths, methods, headers, probes, payload shapes | web attack classification, fuzz seeds |
| SSH/Telnet low-interaction | Capture username/password attempts and client fingerprints | credential attack analytics, detection examples |
| GraphQL/API decoy | Capture introspection, malformed queries, injection attempts | GraphQL parser fuzzing and detection |
| Object-storage lure | Capture bucket enumeration and path traversal attempts | cloud detection examples |
| Parser payload collector | Capture malformed JSON/YAML/XML/archive payload structures | PeachFuzz corpora |

## Event schema

```json
{
  "schema_version": "1.0",
  "sensor": "http-lowint-01",
  "timestamp": "2026-04-24T00:00:00Z",
  "event_type": "http_probe",
  "attack_surface": "decoy_api",
  "source": {
    "ip_hash": "sha256:salted-redacted",
    "asn": 0,
    "country": "ZZ"
  },
  "request": {
    "method": "GET",
    "path_class": "path_traversal_probe",
    "headers_redacted": {
      "user-agent": "scanner-family-or-redacted"
    },
    "body_len": 0,
    "payload_excerpt_redacted": "GET /REDACTED HTTP/1.1"
  },
  "classification": {
    "payload_class": "path_traversal_probe",
    "mitre_attack": ["T1595", "T1190"],
    "confidence": 0.76,
    "safety_label": "defensive_telemetry_sanitized"
  },
  "dataset_use": ["detection", "fuzz_seed", "llm_triage"]
}
```

## PeachTree normalization tasks

1. Load raw sensor logs from private storage.
2. Validate each record against the schema.
3. Redact or drop sensitive fields.
4. Map payloads to parser target classes.
5. Assign safety labels.
6. Emit sanitized JSONL/NDJSON.
7. Store raw logs separately with restricted access and retention limits.

## PeachFuzz conversion tasks

1. Extract sanitized payload structure.
2. Remove third-party secrets, tokens, and personal data.
3. Minimize payload while preserving parser behavior.
4. Save safe seeds by target type: `json`, `graphql`, `http`, `yaml`, `xml`, `archive`, `log`.
5. Run fuzz campaigns in isolated CI or disposable runners.
6. Store crashes privately until triaged.
7. Publish only benign minimized reproducers and patch notes.

## Hancock training record shape

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are Hancock, a defensive cybersecurity triage assistant. Analyze sanitized honeypot telemetry safely."
    },
    {
      "role": "user",
      "content": "Classify this sanitized event and propose defensive detections: {event_json}"
    },
    {
      "role": "assistant",
      "content": "Classification: reconnaissance against exposed web API. ATT&CK: T1595/T1190. Recommended detections: ..."
    }
  ],
  "metadata": {
    "source": "sanitized_honeypot",
    "safety_label": "defensive",
    "dataset_version": "hancock-honeypot-v1"
  }
}
```

## Security controls

- deny egress from honeypot containers except telemetry shipping
- no real secrets, real admin panels, or production credentials in decoys
- immutable infrastructure rebuilds
- short raw log retention
- private salt for IP hashing
- malware quarantine policy
- rate limits and resource caps
- legal notice and acceptable-use documentation
- abuse mailbox monitoring
- cloud spend alarms

## Public website rule

The public site may describe the architecture and show sanitized examples. It must not expose raw telemetry, private dashboards, cloud hostnames, API keys, Drive links, admin URLs, or operational sensor secrets.
