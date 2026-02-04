"""
ML Model API Server - serves ML models via FastAPI
Allows SOAR playbooks, SIEM alerts, and other tools to call models in real-time
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.clustering import ThreatClusterer
from analyzer.anomaly_detector import AnomalyDetector
from analyzer.feature_engineering import FeatureEngineer
from processor.enricher import FullEnricher
from processor.scorer import IOCDeduplicator
from processor.mitre_mapper import MITREMapper
from processor.cross_reference import CrossReference

app = FastAPI(
    title="HRTIP ML API",
    description="Healthcare & Retail Threat Intelligence Platform - ML Model Serving API",
    version="1.0.0"
)

# Initialize models (loaded once at startup)
clusterer = ThreatClusterer()
anomaly_detector = AnomalyDetector(contamination=0.1)
feature_engineer = FeatureEngineer()
mitre_mapper = MITREMapper()
deduplicator = IOCDeduplicator()

# Lazy-load enricher and cross-reference (require API keys / data)
_enricher = None
_xref = None

def get_enricher():
    global _enricher
    if _enricher is None:
        _enricher = FullEnricher()
    return _enricher

def get_xref():
    global _xref
    if _xref is None:
        _xref = CrossReference()
    return _xref


# --- Request/Response Models ---

class IOC(BaseModel):
    type: str  # ipv4, domain, url, sha256, md5
    value: str
    source: Optional[str] = "api"
    threat_type: Optional[str] = None
    malware: Optional[str] = None
    port: Optional[int] = None
    tags: Optional[List[str]] = []
    confidence_score: Optional[int] = None
    first_seen: Optional[str] = None

class IOCList(BaseModel):
    iocs: List[IOC]

class EnrichRequest(BaseModel):
    ioc: IOC
    include_virustotal: bool = True
    include_shodan: bool = True
    include_geoip: bool = True
    include_threat_feeds: bool = True

class AnalyzeRequest(BaseModel):
    iocs: List[IOC]
    include_clustering: bool = True
    include_anomaly_detection: bool = True
    include_features: bool = True
    include_mitre: bool = True


# --- Health Check ---

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "HRTIP ML API"}


# --- Enrichment Endpoints ---

@app.post("/enrich")
async def enrich_ioc(request: EnrichRequest):
    """
    Enrich a single IOC with threat intelligence
    """
    try:
        enricher = get_enricher()
        ioc_dict = request.ioc.model_dump()
        enriched = enricher.enrich(ioc_dict)
        return {"status": "success", "enriched_ioc": enriched}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cross-reference")
async def cross_reference_ioc(ioc: IOC):
    """
    Check if an IOC exists in collected threat feeds
    """
    try:
        xref = get_xref()
        result = xref.check_ioc(ioc.type, ioc.value)
        return {"status": "success", "ioc": ioc.model_dump(), "threat_feed_match": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Scoring Endpoints ---

@app.post("/score")
async def score_ioc(ioc: IOC):
    """
    Calculate confidence score for an IOC
    """
    try:
        scored = deduplicator.scorer.score_ioc(ioc.model_dump())
        return {
            "status": "success",
            "ioc": ioc.value,
            "confidence_score": scored.get("confidence_score"),
            "scoring_factors": scored.get("scoring_factors")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/deduplicate")
async def deduplicate_iocs(request: IOCList):
    """
    Deduplicate and score a list of IOCs
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        deduplicated = deduplicator.deduplicate(ioc_dicts)
        stats = deduplicator.get_stats(ioc_dicts, deduplicated)
        return {
            "status": "success",
            "deduplicated_iocs": deduplicated,
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- ML Analysis Endpoints ---

@app.post("/cluster")
async def cluster_iocs(request: IOCList):
    """
    Cluster IOCs into potential threat campaigns
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        clustered = clusterer.cluster(ioc_dicts, eps=1.0, min_samples=2)
        analysis = clusterer.analyze_clusters(clustered)
        return {
            "status": "success",
            "clustered_iocs": clustered,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect-anomalies")
async def detect_anomalies(request: IOCList):
    """
    Detect anomalous IOCs using Isolation Forest
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        analysis = anomaly_detector.analyze_anomalies(ioc_dicts)
        return {
            "status": "success",
            "total_iocs": analysis["total_iocs"],
            "anomalies_found": analysis["anomalies_found"],
            "anomaly_rate": analysis["anomaly_rate"],
            "top_anomalies": analysis["top_anomalies"][:10],
            "anomaly_by_type": dict(analysis["anomaly_by_type"]),
            "anomaly_by_source": dict(analysis["anomaly_by_source"])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/extract-features")
async def extract_features(request: IOCList):
    """
    Extract ML features from IOCs
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        features = feature_engineer.extract_all_features(ioc_dicts)
        return {"status": "success", "features": features}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- MITRE ATT&CK Endpoints ---

@app.post("/map-mitre")
async def map_to_mitre(request: IOCList):
    """
    Map IOCs to MITRE ATT&CK techniques
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        mapped = mitre_mapper.map_multiple(ioc_dicts)
        summary = mitre_mapper.generate_attack_summary(mapped)
        return {
            "status": "success",
            "mapped_iocs": mapped,
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Full Analysis Pipeline ---

@app.post("/analyze")
async def full_analysis(request: AnalyzeRequest):
    """
    Run full analysis pipeline on IOCs
    """
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        
        result = {
            "status": "success",
            "input_count": len(ioc_dicts)
        }
        
        # Deduplicate and score
        deduplicated = deduplicator.deduplicate(ioc_dicts)
        result["deduplicated_count"] = len(deduplicated)
        result["dedup_stats"] = deduplicator.get_stats(ioc_dicts, deduplicated)
        
        # MITRE mapping
        if request.include_mitre:
            mapped = mitre_mapper.map_multiple(deduplicated)
            result["mitre_summary"] = mitre_mapper.generate_attack_summary(mapped)
            deduplicated = mapped
        
        # Clustering
        if request.include_clustering:
            clustered = clusterer.cluster(deduplicated.copy(), eps=1.0, min_samples=2)
            result["clustering"] = clusterer.analyze_clusters(clustered)
        
        # Anomaly detection
        if request.include_anomaly_detection:
            anomaly_analysis = anomaly_detector.analyze_anomalies(deduplicated.copy())
            result["anomaly_detection"] = {
                "anomalies_found": anomaly_analysis["anomalies_found"],
                "anomaly_rate": anomaly_analysis["anomaly_rate"],
                "top_anomalies": [
                    {"value": a.get("value"), "type": a.get("type"), "score": a.get("anomaly", {}).get("anomaly_score")}
                    for a in anomaly_analysis["top_anomalies"][:5]
                ],
                "by_type": dict(anomaly_analysis["anomaly_by_type"]),
                "by_source": dict(anomaly_analysis["anomaly_by_source"])
            }
        
        # Feature extraction
        if request.include_features:
            result["features"] = feature_engineer.extract_all_features(deduplicated)
        
        # Top IOCs by confidence
        result["top_iocs"] = [
            {
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence_score": ioc.get("confidence_score"),
                "malware": ioc.get("malware"),
                "threat_type": ioc.get("threat_type")
            }
            for ioc in sorted(deduplicated, key=lambda x: x.get("confidence_score", 0), reverse=True)[:10]
        ]
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    print("Starting HRTIP ML API Server...")
    print("API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
