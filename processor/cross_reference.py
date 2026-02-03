"""
Cross-Reference - checks IOCs against collected threat feeds
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone


class CrossReference:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.ioc_database = {}
        self.load_collected_iocs()
    
    def load_collected_iocs(self):
        """Load all previously collected IOCs into memory"""
        self.ioc_database = {
            "urls": {},
            "ips": {},
            "domains": {},
            "hashes": {}
        }
        
        if not self.data_dir.exists():
            print("[CrossRef] No data directory found")
            return
        
        # Load all IOC files
        for filepath in self.data_dir.glob("iocs_*.json"):
            try:
                with open(filepath, "r") as f:
                    iocs = json.load(f)
                    
                for ioc in iocs:
                    self._index_ioc(ioc)
                    
            except Exception as e:
                print(f"[CrossRef] Error loading {filepath}: {e}")
        
        total = sum(len(v) for v in self.ioc_database.values())
        print(f"[CrossRef] Loaded {total} IOCs from threat feeds")
    
    def _index_ioc(self, ioc: Dict):
        """Index a single IOC for fast lookup"""
        ioc_type = ioc.get("type", "").lower()
        value = ioc.get("value", "").lower()
        source = ioc.get("source", "unknown")
        
        if not value:
            return
        
        # Categorize by type
        if ioc_type == "url" or "url" in ioc_type:
            if value not in self.ioc_database["urls"]:
                self.ioc_database["urls"][value] = []
            self.ioc_database["urls"][value].append({
                "source": source,
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "tags": ioc.get("tags", []),
                "date_added": ioc.get("date_added") or ioc.get("first_seen")
            })
        
        elif ioc_type in ["ip", "ipv4", "ip:port"]:
            # Extract IP from ip:port format
            ip = value.split(":")[0] if ":" in value else value
            if ip not in self.ioc_database["ips"]:
                self.ioc_database["ips"][ip] = []
            self.ioc_database["ips"][ip].append({
                "source": source,
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "port": ioc.get("port") or (value.split(":")[1] if ":" in value else None),
                "tags": ioc.get("tags", [])
            })
        
        elif ioc_type in ["domain", "hostname"]:
            if value not in self.ioc_database["domains"]:
                self.ioc_database["domains"][value] = []
            self.ioc_database["domains"][value].append({
                "source": source,
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "tags": ioc.get("tags", [])
            })
        
        elif ioc_type in ["md5", "sha1", "sha256", "hash"]:
            if value not in self.ioc_database["hashes"]:
                self.ioc_database["hashes"][value] = []
            self.ioc_database["hashes"][value].append({
                "source": source,
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "tags": ioc.get("tags", [])
            })
    
    def check_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Check if an IOC exists in our threat feeds"""
        value = value.lower()
        matches = []
        
        if ioc_type == "ipv4":
            matches = self.ioc_database["ips"].get(value, [])
        elif ioc_type == "domain":
            matches = self.ioc_database["domains"].get(value, [])
        elif ioc_type in ["md5", "sha1", "sha256"]:
            matches = self.ioc_database["hashes"].get(value, [])
        elif ioc_type == "url":
            matches = self.ioc_database["urls"].get(value, [])
            # Also check partial URL matches
            if not matches:
                for url, data in self.ioc_database["urls"].items():
                    if value in url or url in value:
                        matches.extend(data)
        
        if matches:
            return {
                "found": True,
                "match_count": len(matches),
                "sources": list(set(m["source"] for m in matches)),
                "threat_types": list(set(m.get("threat_type") for m in matches if m.get("threat_type"))),
                "malware_families": list(set(m.get("malware") for m in matches if m.get("malware"))),
                "all_tags": list(set(tag for m in matches for tag in m.get("tags", []) if tag)),
                "matches": matches[:5]  # Return first 5 matches
            }
        else:
            return {
                "found": False,
                "match_count": 0
            }
    
    def check_multiple(self, iocs: List[Dict]) -> List[Dict]:
        """Check multiple IOCs against threat feeds"""
        results = []
        
        for ioc in iocs:
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            
            result = ioc.copy()
            result["threat_feed_match"] = self.check_ioc(ioc_type, value)
            results.append(result)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get statistics about loaded IOCs"""
        return {
            "total_urls": len(self.ioc_database["urls"]),
            "total_ips": len(self.ioc_database["ips"]),
            "total_domains": len(self.ioc_database["domains"]),
            "total_hashes": len(self.ioc_database["hashes"]),
            "total": sum(len(v) for v in self.ioc_database.values())
        }


if __name__ == "__main__":
    print("=" * 60)
    print("HRTIP Cross-Reference - Testing")
    print("=" * 60)
    
    xref = CrossReference()
    
    print(f"\nDatabase Stats: {xref.get_stats()}")
    
    # Test with some IOCs that might be in our feeds
    test_iocs = [
        {"type": "ipv4", "value": "162.243.103.246"},  # Emotet C2 from FeodoTracker
        {"type": "ipv4", "value": "45.33.32.156"},      # Likely not in feeds
        {"type": "url", "value": "http://evil-test.com"},  # Test URL
    ]
    
    print("\n" + "=" * 60)
    print("Cross-Reference Results")
    print("=" * 60)
    
    for ioc in test_iocs:
        result = xref.check_ioc(ioc["type"], ioc["value"])
        print(f"\n[{ioc['type']}] {ioc['value']}")
        if result["found"]:
            print(f"  ✓ FOUND in {result['match_count']} feed(s)")
            print(f"    Sources: {result['sources']}")
            print(f"    Threat Types: {result['threat_types']}")
            print(f"    Malware: {result['malware_families']}")
        else:
            print(f"  ✗ Not found in threat feeds")
