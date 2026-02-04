"""
Feature Engineering - extracts advanced features for ML analysis
- Domain registration cadence
- IP ASN diversity
- TTP co-occurrence patterns
- Temporal behavior (time-of-day activity)
"""

import numpy as np
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
import re


class FeatureEngineer:
    """Extracts advanced features from IOCs and threat data"""
    
    def __init__(self):
        # ASN risk ratings (example - in production, use a real database)
        self.high_risk_asns = [
            "AS4134",   # China Telecom
            "AS4837",   # China Unicom
            "AS9009",   # M247 (commonly abused)
            "AS14061",  # DigitalOcean (commonly abused)
            "AS16276",  # OVH (commonly abused)
            "AS24940",  # Hetzner
            "AS202425", # IP Volume Inc
            "AS62904",  # Eonix
        ]
    
    def extract_all_features(self, iocs: List[Dict]) -> Dict:
        """Extract all feature sets from IOCs"""
        
        return {
            "temporal_features": self.extract_temporal_features(iocs),
            "asn_features": self.extract_asn_features(iocs),
            "domain_features": self.extract_domain_features(iocs),
            "ttp_features": self.extract_ttp_features(iocs),
            "network_features": self.extract_network_features(iocs),
            "summary": self._generate_summary(iocs)
        }
    
    def extract_temporal_features(self, iocs: List[Dict]) -> Dict:
        """Extract time-based behavioral features"""
        
        timestamps = []
        
        for ioc in iocs:
            # Try to parse timestamp from various fields
            ts_str = (
                ioc.get("first_seen") or 
                ioc.get("date_added") or 
                ioc.get("collected_at") or
                ioc.get("created")
            )
            
            if ts_str:
                try:
                    if isinstance(ts_str, str):
                        if "T" in ts_str:
                            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        else:
                            dt = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                            dt = dt.replace(tzinfo=timezone.utc)
                        timestamps.append(dt)
                except:
                    pass
        
        if not timestamps:
            return {"error": "No valid timestamps found"}
        
        # Time-of-day distribution (hour buckets)
        hours = [ts.hour for ts in timestamps]
        hour_distribution = Counter(hours)
        
        # Day-of-week distribution
        days = [ts.weekday() for ts in timestamps]
        day_distribution = Counter(days)
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        
        # Activity windows
        business_hours = sum(1 for h in hours if 9 <= h <= 17)
        night_hours = sum(1 for h in hours if h < 6 or h > 22)
        weekend_activity = sum(1 for d in days if d >= 5)
        
        # Calculate time gaps between IOCs
        timestamps_sorted = sorted(timestamps)
        time_gaps = []
        for i in range(1, len(timestamps_sorted)):
            gap = (timestamps_sorted[i] - timestamps_sorted[i-1]).total_seconds() / 3600  # hours
            time_gaps.append(gap)
        
        # Burst detection (many IOCs in short time)
        bursts = sum(1 for gap in time_gaps if gap < 1)  # Less than 1 hour apart
        
        return {
            "total_timestamps": len(timestamps),
            "hour_distribution": dict(hour_distribution.most_common()),
            "peak_hours": [h for h, _ in hour_distribution.most_common(3)],
            "day_distribution": {day_names[d]: c for d, c in day_distribution.items()},
            "business_hours_ratio": round(business_hours / len(hours), 2) if hours else 0,
            "night_activity_ratio": round(night_hours / len(hours), 2) if hours else 0,
            "weekend_ratio": round(weekend_activity / len(days), 2) if days else 0,
            "avg_time_gap_hours": round(np.mean(time_gaps), 2) if time_gaps else 0,
            "burst_count": bursts,
            "time_span_days": (max(timestamps) - min(timestamps)).days if len(timestamps) > 1 else 0,
            "behavioral_pattern": self._classify_temporal_pattern(hours, days)
        }
    
    def _classify_temporal_pattern(self, hours: List[int], days: List[int]) -> str:
        """Classify the temporal behavior pattern"""
        
        if not hours:
            return "unknown"
        
        business_ratio = sum(1 for h in hours if 9 <= h <= 17) / len(hours)
        night_ratio = sum(1 for h in hours if h < 6 or h > 22) / len(hours)
        weekend_ratio = sum(1 for d in days if d >= 5) / len(days) if days else 0
        
        if night_ratio > 0.5:
            return "night_owl_attacker"
        elif business_ratio > 0.7 and weekend_ratio < 0.2:
            return "business_hours_operator"
        elif weekend_ratio > 0.4:
            return "weekend_warrior"
        else:
            return "mixed_schedule"
    
    def extract_asn_features(self, iocs: List[Dict]) -> Dict:
        """Extract ASN-related features"""
        
        asns = []
        countries = []
        orgs = []
        
        for ioc in iocs:
            # Check enrichment data
            enrichment = ioc.get("enrichment", {})
            
            # From GeoIP
            geoip = enrichment.get("geoip", {})
            if geoip.get("as"):
                asn = geoip.get("as", "").split()[0] if geoip.get("as") else None
                if asn:
                    asns.append(asn)
            if geoip.get("country_code"):
                countries.append(geoip.get("country_code"))
            if geoip.get("org"):
                orgs.append(geoip.get("org"))
            
            # From Shodan
            shodan = enrichment.get("shodan", {})
            if shodan.get("org"):
                orgs.append(shodan.get("org"))
        
        asn_counts = Counter(asns)
        country_counts = Counter(countries)
        org_counts = Counter(orgs)
        
        # Calculate diversity metrics
        asn_diversity = len(set(asns)) / len(asns) if asns else 0
        country_diversity = len(set(countries)) / len(countries) if countries else 0
        
        # High-risk ASN ratio
        high_risk_count = sum(1 for asn in asns if asn in self.high_risk_asns)
        
        return {
            "unique_asns": len(set(asns)),
            "asn_diversity_ratio": round(asn_diversity, 2),
            "top_asns": asn_counts.most_common(5),
            "unique_countries": len(set(countries)),
            "country_diversity_ratio": round(country_diversity, 2),
            "top_countries": country_counts.most_common(5),
            "top_orgs": org_counts.most_common(5),
            "high_risk_asn_ratio": round(high_risk_count / len(asns), 2) if asns else 0,
            "infrastructure_pattern": self._classify_infrastructure(asn_diversity, country_diversity)
        }
    
    def _classify_infrastructure(self, asn_div: float, country_div: float) -> str:
        """Classify infrastructure pattern"""
        
        if asn_div > 0.8 and country_div > 0.8:
            return "distributed_global"
        elif asn_div < 0.3 and country_div < 0.3:
            return "concentrated_single_provider"
        elif country_div < 0.3:
            return "regional_operation"
        else:
            return "mixed_infrastructure"
    
    def extract_domain_features(self, iocs: List[Dict]) -> Dict:
        """Extract domain-specific features"""
        
        domains = [ioc.get("value", "") for ioc in iocs if ioc.get("type") == "domain"]
        
        if not domains:
            return {"error": "No domains found"}
        
        # Domain length statistics
        lengths = [len(d) for d in domains]
        
        # TLD distribution
        tlds = []
        for d in domains:
            parts = d.split(".")
            if parts:
                tlds.append(parts[-1])
        tld_counts = Counter(tlds)
        
        # Subdomain depth
        subdomain_depths = [d.count(".") for d in domains]
        
        # Entropy (DGA detection)
        entropies = [self._calculate_entropy(d.split(".")[0]) for d in domains]
        
        # Numeric ratio (DGA indicator)
        numeric_ratios = [sum(c.isdigit() for c in d) / len(d) if d else 0 for d in domains]
        
        # Suspicious TLDs
        suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club"]
        suspicious_count = sum(1 for tld in tlds if tld in suspicious_tlds)
        
        # Domain age estimation from enrichment
        ages = []
        for ioc in iocs:
            if ioc.get("type") == "domain":
                enrichment = ioc.get("enrichment", {})
                vt = enrichment.get("virustotal", {})
                creation = vt.get("creation_date")
                if creation and isinstance(creation, (int, float)):
                    age_days = (datetime.now().timestamp() - creation) / 86400
                    ages.append(age_days)
        
        return {
            "total_domains": len(domains),
            "avg_length": round(np.mean(lengths), 1),
            "max_length": max(lengths),
            "tld_distribution": dict(tld_counts.most_common(10)),
            "suspicious_tld_ratio": round(suspicious_count / len(tlds), 2) if tlds else 0,
            "avg_subdomain_depth": round(np.mean(subdomain_depths), 1),
            "avg_entropy": round(np.mean(entropies), 2),
            "high_entropy_ratio": round(sum(1 for e in entropies if e > 3.5) / len(entropies), 2),
            "avg_numeric_ratio": round(np.mean(numeric_ratios), 2),
            "dga_likelihood": self._assess_dga_likelihood(entropies, numeric_ratios, lengths),
            "avg_domain_age_days": round(np.mean(ages), 0) if ages else None,
            "new_domain_ratio": round(sum(1 for a in ages if a < 30) / len(ages), 2) if ages else None
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0
        freq = Counter(text)
        length = len(text)
        return -sum((c/length) * np.log2(c/length) for c in freq.values())
    
    def _assess_dga_likelihood(self, entropies: List[float], numeric_ratios: List[float], lengths: List[int]) -> str:
        """Assess likelihood of DGA-generated domains"""
        
        high_entropy = sum(1 for e in entropies if e > 3.5) / len(entropies) if entropies else 0
        high_numeric = sum(1 for r in numeric_ratios if r > 0.3) / len(numeric_ratios) if numeric_ratios else 0
        unusual_length = sum(1 for l in lengths if l > 20 or l < 5) / len(lengths) if lengths else 0
        
        score = (high_entropy * 0.4) + (high_numeric * 0.3) + (unusual_length * 0.3)
        
        if score > 0.6:
            return "high"
        elif score > 0.3:
            return "medium"
        else:
            return "low"
    
    def extract_ttp_features(self, iocs: List[Dict]) -> Dict:
        """Extract TTP co-occurrence patterns"""
        
        # Collect all techniques
        all_techniques = []
        all_tactics = []
        technique_pairs = []
        
        for ioc in iocs:
            mitre = ioc.get("mitre_attack", {})
            techniques = mitre.get("techniques", [])
            tactics = mitre.get("tactics", [])
            
            all_techniques.extend(techniques)
            all_tactics.extend(tactics)
            
            # Track co-occurring techniques
            for i, t1 in enumerate(techniques):
                for t2 in techniques[i+1:]:
                    pair = tuple(sorted([t1, t2]))
                    technique_pairs.append(pair)
        
        technique_counts = Counter(all_techniques)
        tactic_counts = Counter(all_tactics)
        pair_counts = Counter(technique_pairs)
        
        # Calculate kill chain coverage
        kill_chain_phases = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement", "Collection",
            "Command and Control", "Exfiltration", "Impact"
        ]
        
        covered_phases = set(all_tactics)
        coverage = len(covered_phases) / len(kill_chain_phases)
        
        return {
            "unique_techniques": len(set(all_techniques)),
            "unique_tactics": len(set(all_tactics)),
            "top_techniques": technique_counts.most_common(10),
            "top_tactics": tactic_counts.most_common(10),
            "top_technique_pairs": pair_counts.most_common(5),
            "kill_chain_coverage": round(coverage, 2),
            "covered_phases": list(covered_phases),
            "attack_pattern": self._classify_attack_pattern(tactic_counts)
        }
    
    def _classify_attack_pattern(self, tactic_counts: Counter) -> str:
        """Classify the overall attack pattern"""
        
        tactics = set(tactic_counts.keys())
        
        if "Initial Access" in tactics and "Execution" in tactics and "Command and Control" in tactics:
            if "Impact" in tactics:
                return "full_kill_chain"
            return "standard_intrusion"
        elif "Credential Access" in tactics and "Collection" in tactics:
            return "data_theft_focused"
        elif "Impact" in tactics:
            return "destructive_attack"
        elif "Command and Control" in tactics:
            return "c2_infrastructure"
        else:
            return "reconnaissance_or_partial"
    
    def extract_network_features(self, iocs: List[Dict]) -> Dict:
        """Extract network-level features"""
        
        ips = [ioc for ioc in iocs if ioc.get("type") == "ipv4"]
        ports = [ioc.get("port") for ioc in iocs if ioc.get("port")]
        
        # Port analysis
        port_counts = Counter(ports)
        
        # Standard ports vs non-standard
        standard_ports = [80, 443, 8080, 8443, 22, 21, 25, 53]
        standard_count = sum(1 for p in ports if p in standard_ports)
        
        # IP class distribution
        ip_classes = []
        for ioc in ips:
            ip = ioc.get("value", "")
            octets = ip.split(".")
            if octets:
                first = int(octets[0])
                if first < 128:
                    ip_classes.append("A")
                elif first < 192:
                    ip_classes.append("B")
                else:
                    ip_classes.append("C")
        
        return {
            "total_ips": len(ips),
            "unique_ports": len(set(ports)),
            "port_distribution": dict(port_counts.most_common(10)),
            "standard_port_ratio": round(standard_count / len(ports), 2) if ports else 0,
            "high_port_ratio": round(sum(1 for p in ports if p > 1024) / len(ports), 2) if ports else 0,
            "ip_class_distribution": dict(Counter(ip_classes)),
            "common_c2_ports": [p for p in [443, 8080, 4444, 1337, 9999] if p in ports]
        }
    
    def _generate_summary(self, iocs: List[Dict]) -> Dict:
        """Generate a summary of the threat landscape"""
        
        sources = Counter(ioc.get("source") for ioc in iocs)
        types = Counter(ioc.get("type") for ioc in iocs)
        threat_types = Counter(ioc.get("threat_type") for ioc in iocs if ioc.get("threat_type"))
        malware = Counter(ioc.get("malware") for ioc in iocs if ioc.get("malware"))
        
        return {
            "total_iocs": len(iocs),
            "sources": dict(sources),
            "ioc_types": dict(types),
            "threat_types": dict(threat_types),
            "top_malware": malware.most_common(5)
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Feature Engineering - Testing")
    print("=" * 60)
    
    # Test with sample IOCs
    test_iocs = [
        {
            "type": "ipv4", "value": "45.33.32.156", "source": "feodotracker",
            "threat_type": "botnet_c2", "malware": "Emotet", "port": 8080,
            "first_seen": "2026-02-03 14:30:00",
            "enrichment": {
                "geoip": {"country_code": "US", "as": "AS63949 Linode", "org": "Linode"},
            },
            "mitre_attack": {"techniques": ["T1071.001", "T1573"], "tactics": ["Command and Control"]}
        },
        {
            "type": "ipv4", "value": "162.243.103.246", "source": "feodotracker",
            "threat_type": "botnet_c2", "malware": "Emotet", "port": 443,
            "first_seen": "2026-02-03 15:45:00",
            "enrichment": {
                "geoip": {"country_code": "US", "as": "AS14061 DigitalOcean", "org": "DigitalOcean"},
            },
            "mitre_attack": {"techniques": ["T1071.001", "T1055"], "tactics": ["Command and Control", "Defense Evasion"]}
        },
        {
            "type": "domain", "value": "evil-phishing.xyz", "source": "openphish",
            "threat_type": "phishing", "first_seen": "2026-02-03 02:15:00",
            "mitre_attack": {"techniques": ["T1566.001"], "tactics": ["Initial Access"]}
        },
        {
            "type": "domain", "value": "x7k9m2p4q8.tk", "source": "threatfox",
            "threat_type": "malware", "first_seen": "2026-02-02 23:30:00",
            "mitre_attack": {"techniques": ["T1071.001"], "tactics": ["Command and Control"]}
        },
        {
            "type": "sha256", "value": "a" * 64, "source": "malwarebazaar",
            "threat_type": "malware", "malware": "Mirai", "first_seen": "2026-02-03 08:00:00",
            "mitre_attack": {"techniques": ["T1059.004", "T1110.001"], "tactics": ["Execution", "Credential Access"]}
        },
    ]
    
    engineer = FeatureEngineer()
    features = engineer.extract_all_features(test_iocs)
    
    print("\n--- TEMPORAL FEATURES ---")
    for k, v in features["temporal_features"].items():
        print(f"  {k}: {v}")
    
    print("\n--- DOMAIN FEATURES ---")
    for k, v in features["domain_features"].items():
        print(f"  {k}: {v}")
    
    print("\n--- TTP FEATURES ---")
    for k, v in features["ttp_features"].items():
        print(f"  {k}: {v}")
    
    print("\n--- NETWORK FEATURES ---")
    for k, v in features["network_features"].items():
        print(f"  {k}: {v}")
    
    print("\n--- SUMMARY ---")
    for k, v in features["summary"].items():
        print(f"  {k}: {v}")
