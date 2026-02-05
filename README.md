# HRTIP - Healthcare & Retail Threat Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.12-blue)
![React](https://img.shields.io/badge/React-19-61dafb)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![License](https://img.shields.io/badge/License-MIT-green)

An automated threat intelligence platform that collects, processes, analyzes, and visualizes IOCs (Indicators of Compromise) from multiple threat feeds. Features ML-powered clustering, anomaly detection, MITRE ATT&CK mapping, and enterprise SIEM/SOAR integrations.

![Dashboard Screenshot](docs/dashboard.png)

## Features

### 🔍 Multi-Source Collection
- **URLhaus** - Malware distribution URLs
- **Feodo Tracker** - Botnet C2 infrastructure
- **ThreatFox** - IOCs with malware context
- **MalwareBazaar** - Malware sample hashes
- **OpenPhish** - Phishing URLs
- **AlienVault OTX** - Community threat pulses
- **Mastodon** - Infosec community monitoring
- **RSS Feeds** - Security blog aggregation

### 🧠 ML-Powered Analysis
- **DBSCAN Clustering** - Groups related IOCs into threat campaigns
- **Isolation Forest** - Detects anomalous indicators
- **Feature Engineering** - Temporal patterns, ASN diversity, domain entropy
- **Confidence Scoring** - Multi-factor reliability scoring (0-100)

### 🎯 MITRE ATT&CK Integration
- Automatic technique mapping based on threat type and malware
- Kill chain coverage analysis
- Tactic distribution visualization

### 🔗 Enterprise Integrations
- **Splunk** - HEC ingestion + SPL query generation
- **Microsoft Sentinel** - Log Analytics API + KQL queries
- **CrowdStrike Falcon** - IOC management via API
- **SOAR Platforms** - Webhook integration (TheHive, Cortex XSOAR)
- **STIX/TAXII** - Export to STIX 2.1 bundles

### 📊 Real-Time Dashboard
- React-based SPA with live API connection
- IOC distribution charts
- MITRE ATT&CK heatmap
- Threat campaign visualization
- Feed status monitoring

### 📄 Executive Reporting
- Automated PDF report generation
- Professional formatting for stakeholder presentations

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- npm

### Installation
```bash
# Clone repository
git clone https://github.com/iojini/hrtip.git
cd hrtip

# Setup Python environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd dashboard/frontend
npm install
cd ../..
```

### Running the Platform

**Terminal 1 - Collect Threat Data:**
```bash
source venv/bin/activate
python -c "
import sys; sys.path.insert(0, '.')
from collector import urlhaus, feodotracker, threatfox, openphish, malwarebazaar
urlhaus.collect()
feodotracker.collect()
threatfox.collect()
openphish.collect()
malwarebazaar.collect()
"
```

**Terminal 2 - Start API Server:**
```bash
source venv/bin/activate
python -m analyzer.api
```

**Terminal 3 - Start Dashboard:**
```bash
cd dashboard/frontend
npm run dev
```

**Access:**
- Dashboard: http://localhost:5173
- API Docs: http://localhost:8000/docs

## Project Structure
```
hrtip/
├── collector/              # Data collection modules
│   ├── urlhaus.py         # Malware URLs
│   ├── feodotracker.py    # Botnet C2 IPs
│   ├── threatfox.py       # IOCs with context
│   ├── malwarebazaar.py   # Malware hashes
│   ├── openphish.py       # Phishing URLs
│   ├── alienvault.py      # OTX pulses
│   ├── mastodon.py        # Social monitoring
│   └── rss_feeds.py       # Blog aggregation
│
├── processor/              # Data processing
│   ├── extractor.py       # IOC extraction (regex + NLP)
│   ├── enricher.py        # VirusTotal, Shodan, GeoIP
│   ├── scorer.py          # Confidence scoring
│   ├── mitre_mapper.py    # ATT&CK mapping
│   └── cross_reference.py # Feed correlation
│
├── analyzer/               # ML analysis
│   ├── clustering.py      # DBSCAN campaigns
│   ├── anomaly_detector.py # Isolation Forest
│   ├── feature_engineering.py
│   └── api.py             # FastAPI server
│
├── integrations/           # SIEM/SOAR/EDR
│   ├── splunk.py          # Splunk HEC + SPL
│   ├── sentinel.py        # Azure Sentinel + KQL
│   ├── crowdstrike.py     # Falcon API
│   ├── soar_webhook.py    # Generic webhooks
│   └── stix_taxii.py      # STIX 2.1 export
│
├── dashboard/frontend/     # React dashboard
│   └── src/
│       ├── App.jsx
│       ├── components/
│       └── pages/
│
├── reports/                # Report generation
│   └── pdf_generator.py   # Executive PDFs
│
└── data/                   # Collected IOC data
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/dashboard-data` | GET | Aggregated dashboard data |
| `/enrich` | POST | Enrich single IOC |
| `/score` | POST | Calculate confidence score |
| `/deduplicate` | POST | Deduplicate IOC list |
| `/cluster` | POST | Cluster into campaigns |
| `/detect-anomalies` | POST | Find anomalous IOCs |
| `/map-mitre` | POST | Map to MITRE ATT&CK |
| `/analyze` | POST | Full analysis pipeline |

## Generate Reports
```bash
# Generate PDF report from live data
python -m reports.pdf_generator

# Export to STIX 2.1
python integrations/stix_taxii.py
```

## Configuration

### Environment Variables (Optional)
```bash
# Enrichment APIs
export VIRUSTOTAL_API_KEY=your_key
export SHODAN_API_KEY=your_key
export OTX_API_KEY=your_key

# SIEM Integration
export SPLUNK_HEC_URL=https://splunk:8088/services/collector/event
export SPLUNK_HEC_TOKEN=your_token
export SENTINEL_WORKSPACE_ID=your_workspace
export SENTINEL_SHARED_KEY=your_key

# EDR Integration
export CS_CLIENT_ID=your_client_id
export CS_CLIENT_SECRET=your_secret
```

## Tech Stack

**Backend:**
- Python 3.12
- FastAPI (REST API)
- scikit-learn (ML models)
- pandas, numpy (data processing)

**Frontend:**
- React 19
- Vite (build tool)
- Tailwind CSS (styling)
- Recharts (visualization)

**Integrations:**
- STIX 2.1 (threat intel format)
- Splunk HEC (SIEM)
- Azure Sentinel (SIEM)
- CrowdStrike Falcon (EDR)

## License

MIT License - See [LICENSE](LICENSE) for details.

## Author

Built as a demonstration of threat intelligence automation and ML-powered security analytics.
