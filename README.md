# HRTIP - Healthcare & Retail Threat Intelligence Platform

An automated threat intelligence platform purpose-built for healthcare and retail sector threats.

## Features

- Multi-source threat intelligence collection (OSINT feeds, dark web monitoring)
- Automated IOC extraction and enrichment
- MITRE ATT&CK mapping
- ML-powered threat actor clustering and anomaly detection
- SIEM/SOAR/EDR integrations
- Executive-ready automated reporting

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Project Structure

- `collector/` - Data collection modules
- `processor/` - IOC extraction and enrichment
- `analyzer/` - ML models and analysis
- `integrations/` - SIEM/SOAR/EDR connectors
- `dashboard/` - Web UI and reporting
- `shared/` - Shared utilities
- `tests/` - Unit and integration tests
- `docs/` - Documentation

## License

MIT
