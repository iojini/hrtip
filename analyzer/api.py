"""
ML Model API Server - serves ML models via FastAPI
Uses Supabase for persistent storage
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sys
import os
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.clustering import ThreatClusterer
from analyzer.anomaly_detector import AnomalyDetector
from analyzer.feature_engineering import FeatureEngineer
from processor.scorer import IOCDeduplicator
from processor.mitre_mapper import MITREMapper

app = FastAPI(
    title="Nexus API",
    description="Healthcare & Retail Threat Intelligence Platform - ML Model Serving API",
    version="1.0.0"
)

# Add CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize models
clusterer = ThreatClusterer()
anomaly_detector = AnomalyDetector(contamination=0.1)
feature_engineer = FeatureEngineer()
mitre_mapper = MITREMapper()
deduplicator = IOCDeduplicator()


class IOC(BaseModel):
    type: str
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


def get_iocs_from_db():
    """Get IOCs from Supabase database"""
    try:
        from database import get_all_iocs
        return get_all_iocs(limit=2000)
    except Exception as e:
        print(f"Database error: {e}")
        return []


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "Nexus API"}


@app.get("/dashboard-data")
async def get_dashboard_data():
    """Get aggregated data for the dashboard"""
    
    # Get IOCs from database
    all_iocs = get_iocs_from_db()
    
    if not all_iocs:
        return {"error": "No IOC data found in database."}
    
    # Build feed status from IOC sources
    source_counts = Counter(ioc.get("source") for ioc in all_iocs)
    feed_status = {}
    for source, count in source_counts.items():
        feed_status[source or "unknown"] = {
            "status": "active",
            "last_run": all_iocs[0].get("last_seen") if all_iocs else None,
            "iocs_collected": count
        }
    
    # Process IOCs
    mapped = mitre_mapper.map_multiple(all_iocs)
    mitre_summary = mitre_mapper.generate_attack_summary(mapped)
    
    clustered = clusterer.cluster(mapped.copy(), eps=1.0, min_samples=2)
    cluster_analysis = clusterer.analyze_clusters(clustered)
    
    anomaly_analysis = anomaly_detector.analyze_anomalies(mapped.copy())
    features = feature_engineer.extract_all_features(mapped)
    
    # Build summary
    sources = Counter(ioc.get("source") for ioc in mapped)
    types = Counter(ioc.get("type") for ioc in mapped)
    threats = Counter(ioc.get("threat_type") for ioc in mapped)
    malware_counts = Counter(ioc.get("malware") for ioc in mapped if ioc.get("malware"))
    
    top_iocs = sorted(mapped, key=lambda x: x.get("confidence_score", 0), reverse=True)[:20]
    
    return {
        "summary": {
            "total_iocs": len(mapped),
            "sources": dict(sources),
            "ioc_types": dict(types),
            "threat_types": dict(threats)
        },
        "top_iocs": [
            {
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence_score": ioc.get("confidence_score"),
                "malware": ioc.get("malware"),
                "threat_type": ioc.get("threat_type"),
                "sources": ioc.get("corroborated_by", [ioc.get("source")])
            }
            for ioc in top_iocs
        ],
        "mitre_summary": {
            "total_iocs_mapped": mitre_summary.get("total_iocs_mapped", 0),
            "unique_techniques": mitre_summary.get("unique_techniques", 0),
            "unique_tactics": mitre_summary.get("unique_tactics", 0),
            "kill_chain_coverage": features.get("ttp_features", {}).get("kill_chain_coverage", 0),
            "top_techniques": mitre_summary.get("top_techniques", [])[:10],
            "top_tactics": mitre_summary.get("top_tactics", [])[:10],
            "malware_families": list(malware_counts.most_common(10))
        },
        "clusters": cluster_analysis.get("clusters", []),
        "anomalies": {
            "anomalies_found": anomaly_analysis.get("anomalies_found", 0),
            "anomaly_rate": anomaly_analysis.get("anomaly_rate", 0),
            "top_anomalies": [
                {
                    "value": a.get("value"),
                    "type": a.get("type"),
                    "score": a.get("anomaly", {}).get("anomaly_score", 0)
                }
                for a in anomaly_analysis.get("top_anomalies", [])[:5]
            ]
        },
        "feeds": feed_status,
        "temporal": features.get("temporal_features", {}),
    }


@app.post("/analyze")
async def full_analysis(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        
        result = {
            "status": "success",
            "input_count": len(ioc_dicts)
        }
        
        deduplicated = deduplicator.deduplicate(ioc_dicts)
        result["deduplicated_count"] = len(deduplicated)
        
        mapped = mitre_mapper.map_multiple(deduplicated)
        result["mitre_summary"] = mitre_mapper.generate_attack_summary(mapped)
        
        clustered = clusterer.cluster(mapped.copy(), eps=1.0, min_samples=2)
        result["clustering"] = clusterer.analyze_clusters(clustered)
        
        anomaly_analysis = anomaly_detector.analyze_anomalies(mapped.copy())
        result["anomaly_detection"] = {
            "anomalies_found": anomaly_analysis["anomalies_found"],
            "anomaly_rate": anomaly_analysis["anomaly_rate"],
        }
        
        result["features"] = feature_engineer.extract_all_features(mapped)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get database statistics"""
    try:
        from database import get_stats
        return get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"Starting Nexus API Server on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)
