"""
IOC Scorer - deduplication and confidence scoring
Weights IOCs by source reliability, age, and corroboration count
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List
from collections import defaultdict


# Source reliability scores (0-100)
SOURCE_RELIABILITY = {
    "feodotracker": 95,      # Abuse.ch curated, high confidence
    "urlhaus": 90,           # Abuse.ch community, verified
    "threatfox": 90,         # Abuse.ch community, verified
    "malwarebazaar": 90,     # Abuse.ch, confirmed malware
    "alienvault_otx": 75,    # Community contributed, variable quality
    "openphish": 80,         # Automated detection, good accuracy
    "virustotal": 85,        # Multi-engine consensus
    "shodan": 70,            # Exposure data, not inherently malicious
    "telemetry": 60,         # Internal logs, context-dependent
    "unknown": 50,           # Unknown source
}

# Threat type severity multipliers
THREAT_SEVERITY = {
    "botnet_c2": 1.0,        # Critical - active C2
    "ransomware": 1.0,       # Critical
    "malware": 0.9,          # High
    "malware_download": 0.9, # High
    "phishing": 0.8,         # Medium-high
    "exposed_service": 0.5,  # Medium - potential risk
    "unknown": 0.6,          # Default
}

# Age decay - IOCs lose relevance over time
AGE_DECAY = {
    "hours_24": 1.0,         # Fresh - full score
    "days_7": 0.9,           # Recent
    "days_30": 0.7,          # Aging
    "days_90": 0.5,          # Old
    "days_180": 0.3,         # Very old
    "older": 0.1,            # Stale
}


class IOCScorer:
    def __init__(self):
        self.source_reliability = SOURCE_RELIABILITY
        self.threat_severity = THREAT_SEVERITY
    
    def calculate_age_factor(self, ioc: Dict) -> float:
        """Calculate age decay factor"""
        
        # Try to get the date from various fields
        date_str = (
            ioc.get("date_added") or 
            ioc.get("first_seen") or 
            ioc.get("collected_at") or
            ioc.get("created")
        )
        
        if not date_str:
            return 0.5  # Unknown age, moderate penalty
        
        try:
            # Parse various date formats
            if isinstance(date_str, str):
                if "T" in date_str:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                else:
                    dt = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S")
                    dt = dt.replace(tzinfo=timezone.utc)
            else:
                return 0.5
            
            age = datetime.now(timezone.utc) - dt
            
            if age < timedelta(hours=24):
                return AGE_DECAY["hours_24"]
            elif age < timedelta(days=7):
                return AGE_DECAY["days_7"]
            elif age < timedelta(days=30):
                return AGE_DECAY["days_30"]
            elif age < timedelta(days=90):
                return AGE_DECAY["days_90"]
            elif age < timedelta(days=180):
                return AGE_DECAY["days_180"]
            else:
                return AGE_DECAY["older"]
                
        except Exception:
            return 0.5
    
    def calculate_confidence_score(self, ioc: Dict, corroboration_count: int = 1) -> Dict:
        """
        Calculate confidence score for an IOC
        
        Formula: 
        score = (source_reliability * threat_severity * age_factor * corroboration_boost) 
        
        Returns score 0-100
        """
        
        # Base source reliability
        source = ioc.get("source", "unknown")
        source_score = self.source_reliability.get(source, 50)
        
        # Threat severity multiplier
        threat_type = ioc.get("threat_type", "unknown")
        severity = self.threat_severity.get(threat_type, 0.6)
        
        # Age decay
        age_factor = self.calculate_age_factor(ioc)
        
        # Corroboration boost (seen by multiple sources)
        corroboration_boost = min(1.0 + (corroboration_count - 1) * 0.1, 1.5)
        
        # Calculate final score
        raw_score = source_score * severity * age_factor * corroboration_boost
        final_score = min(round(raw_score), 100)
        
        return {
            "confidence_score": final_score,
            "scoring_factors": {
                "source_reliability": source_score,
                "threat_severity": severity,
                "age_factor": round(age_factor, 2),
                "corroboration_count": corroboration_count,
                "corroboration_boost": round(corroboration_boost, 2)
            }
        }
    
    def score_ioc(self, ioc: Dict, corroboration_count: int = 1) -> Dict:
        """Add confidence score to an IOC"""
        result = ioc.copy()
        scoring = self.calculate_confidence_score(ioc, corroboration_count)
        result["confidence_score"] = scoring["confidence_score"]
        result["scoring_factors"] = scoring["scoring_factors"]
        return result


class IOCDeduplicator:
    def __init__(self):
        self.scorer = IOCScorer()
    
    def deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """
        Deduplicate IOCs and merge information from multiple sources
        Returns unique IOCs with corroboration counts and merged data
        """
        
        # Group IOCs by type and value
        grouped = defaultdict(list)
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            value = str(ioc.get("value", "")).lower().strip()
            
            if value:
                key = f"{ioc_type}:{value}"
                grouped[key].append(ioc)
        
        # Merge duplicates
        deduplicated = []
        
        for key, group in grouped.items():
            if len(group) == 1:
                # Single occurrence
                merged = self.scorer.score_ioc(group[0], corroboration_count=1)
            else:
                # Multiple occurrences - merge
                merged = self._merge_iocs(group)
            
            deduplicated.append(merged)
        
        # Sort by confidence score (highest first)
        deduplicated.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)
        
        return deduplicated
    
    def _merge_iocs(self, iocs: List[Dict]) -> Dict:
        """Merge multiple IOCs for the same indicator"""
        
        # Start with the first IOC as base
        merged = iocs[0].copy()
        
        # Collect data from all sources
        sources = set()
        threat_types = set()
        malware_families = set()
        all_tags = set()
        
        for ioc in iocs:
            sources.add(ioc.get("source", "unknown"))
            
            if ioc.get("threat_type"):
                threat_types.add(ioc.get("threat_type"))
            
            if ioc.get("malware"):
                malware_families.add(ioc.get("malware"))
            
            tags = ioc.get("tags", [])
            if isinstance(tags, list):
                all_tags.update(tags)
        
        # Update merged IOC
        merged["sources"] = list(sources)
        merged["corroboration_count"] = len(iocs)
        merged["threat_types"] = list(threat_types)
        merged["malware_families"] = list(malware_families)
        merged["all_tags"] = list(all_tags)[:20]  # Limit tags
        
        # Pick the most severe threat type
        severity_order = ["botnet_c2", "ransomware", "malware", "malware_download", "phishing"]
        for tt in severity_order:
            if tt in threat_types:
                merged["threat_type"] = tt
                break
        
        # Score with corroboration
        scoring = self.scorer.calculate_confidence_score(merged, len(iocs))
        merged["confidence_score"] = scoring["confidence_score"]
        merged["scoring_factors"] = scoring["scoring_factors"]
        
        return merged
    
    def get_stats(self, original: List[Dict], deduplicated: List[Dict]) -> Dict:
        """Get deduplication statistics"""
        
        score_distribution = {"high": 0, "medium": 0, "low": 0}
        for ioc in deduplicated:
            score = ioc.get("confidence_score", 0)
            if score >= 70:
                score_distribution["high"] += 1
            elif score >= 40:
                score_distribution["medium"] += 1
            else:
                score_distribution["low"] += 1
        
        corroborated = [i for i in deduplicated if i.get("corroboration_count", 1) > 1]
        
        return {
            "original_count": len(original),
            "deduplicated_count": len(deduplicated),
            "duplicates_removed": len(original) - len(deduplicated),
            "corroborated_iocs": len(corroborated),
            "score_distribution": score_distribution,
            "avg_confidence": round(
                sum(i.get("confidence_score", 0) for i in deduplicated) / len(deduplicated), 1
            ) if deduplicated else 0
        }


if __name__ == "__main__":
    print("=" * 60)
    print("IOC Scorer & Deduplicator - Testing")
    print("=" * 60)
    
    # Test IOCs with duplicates
    test_iocs = [
        # Same IP from multiple sources
        {"type": "ip", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet", "first_seen": "2026-02-02 10:00:00"},
        {"type": "ip", "value": "45.33.32.156", "source": "threatfox", "threat_type": "botnet_c2", "first_seen": "2026-02-01 10:00:00"},
        {"type": "ip", "value": "45.33.32.156", "source": "alienvault_otx", "threat_type": "malware", "tags": ["apt", "china"]},
        
        # Unique IOCs
        {"type": "url", "value": "http://evil.com/malware.exe", "source": "urlhaus", "threat_type": "malware_download", "date_added": "2026-02-03 08:00:00"},
        {"type": "domain", "value": "phishing-site.xyz", "source": "openphish", "threat_type": "phishing", "collected_at": "2026-02-03T07:00:00Z"},
        
        # Old IOC
        {"type": "sha256", "value": "abc123def456", "source": "malwarebazaar", "threat_type": "malware", "first_seen": "2025-06-01 10:00:00"},
    ]
    
    deduplicator = IOCDeduplicator()
    deduplicated = deduplicator.deduplicate(test_iocs)
    
    print(f"\nOriginal IOCs: {len(test_iocs)}")
    print(f"After deduplication: {len(deduplicated)}")
    
    print("\n" + "-" * 60)
    print("Deduplicated & Scored IOCs:")
    print("-" * 60)
    
    for ioc in deduplicated:
        print(f"\n[{ioc['type']}] {ioc['value'][:40]}")
        print(f"  Confidence Score: {ioc['confidence_score']}/100")
        print(f"  Sources: {ioc.get('sources', [ioc.get('source')])}")
        print(f"  Corroboration: {ioc.get('corroboration_count', 1)}")
        factors = ioc.get("scoring_factors", {})
        print(f"  Factors: reliability={factors.get('source_reliability')}, "
              f"severity={factors.get('threat_severity')}, "
              f"age={factors.get('age_factor')}")
    
    print("\n" + "=" * 60)
    print("Statistics:")
    print("=" * 60)
    stats = deduplicator.get_stats(test_iocs, deduplicated)
    for key, value in stats.items():
        print(f"  {key}: {value}")
