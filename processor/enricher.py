"""
IOC Enricher - enriches indicators using multiple sources
- VirusTotal
- Shodan
- WHOIS
- GeoIP
- Passive DNS
"""

import requests
import os
import socket
from datetime import datetime, timezone
from typing import Dict, Optional
import time
import json


class Enricher:
    def __init__(self):
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        
    def enrich(self, ioc: Dict) -> Dict:
        """Enrich a single IOC with threat intel"""
        
        enriched = ioc.copy()
        enriched["enrichment"] = {}
        enriched["enriched_at"] = datetime.now(timezone.utc).isoformat()
        
        ioc_type = ioc.get("type")
        value = ioc.get("value")
        
        if ioc_type == "ipv4":
            enriched["enrichment"]["virustotal"] = self.enrich_ip_virustotal(value)
            enriched["enrichment"]["shodan"] = self.enrich_ip_shodan(value)
            enriched["enrichment"]["geoip"] = self.enrich_geoip(value)
            enriched["enrichment"]["reverse_dns"] = self.reverse_dns(value)
        elif ioc_type in ["md5", "sha1", "sha256"]:
            enriched["enrichment"]["virustotal"] = self.enrich_hash_virustotal(value)
        elif ioc_type == "domain":
            enriched["enrichment"]["virustotal"] = self.enrich_domain_virustotal(value)
            enriched["enrichment"]["whois"] = self.enrich_whois(value)
            enriched["enrichment"]["dns"] = self.resolve_domain(value)
        elif ioc_type == "url":
            enriched["enrichment"]["virustotal"] = self.enrich_url_virustotal(value)
        
        # Calculate risk score
        enriched["risk_score"] = self.calculate_risk_score(enriched)
        
        return enriched
    
    def enrich_geoip(self, ip: str) -> Optional[Dict]:
        """Get GeoIP information using free ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as")
                    }
                else:
                    return {"error": data.get("message", "Unknown error")}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def reverse_dns(self, ip: str) -> Optional[Dict]:
        """Perform reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {"hostname": hostname}
        except socket.herror:
            return {"hostname": None, "error": "No PTR record"}
        except Exception as e:
            return {"error": str(e)}
    
    def resolve_domain(self, domain: str) -> Optional[Dict]:
        """Resolve domain to IPs (passive DNS simulation)"""
        try:
            ips = socket.gethostbyname_ex(domain)
            return {
                "hostname": ips[0],
                "aliases": ips[1],
                "ips": ips[2]
            }
        except socket.gaierror:
            return {"error": "DNS resolution failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_whois(self, domain: str) -> Optional[Dict]:
        """Get WHOIS information using free API"""
        try:
            # Using whoisjson.com free API
            url = f"https://whoisjson.com/api/v1/whois?domain={domain}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "registrar": data.get("registrar"),
                    "creation_date": data.get("created"),
                    "expiration_date": data.get("expires"),
                    "name_servers": data.get("nameservers", [])[:3],
                    "status": data.get("status", [])[:3] if isinstance(data.get("status"), list) else data.get("status")
                }
            elif response.status_code == 402:
                # Fallback - try basic info from VT
                return {"error": "WHOIS API requires payment, using VT data"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_ip_virustotal(self, ip: str) -> Optional[Dict]:
        """Enrich IP using VirusTotal"""
        if not self.vt_api_key:
            return {"error": "No API key"}
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "country": data.get("country"),
                    "as_owner": data.get("as_owner"),
                    "reputation": data.get("reputation", 0)
                }
            elif response.status_code == 429:
                return {"error": "Rate limited"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_ip_shodan(self, ip: str) -> Optional[Dict]:
        """Enrich IP using Shodan"""
        if not self.shodan_api_key:
            return {"error": "No API key"}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": self.shodan_api_key}
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                if isinstance(vulns, dict):
                    vulns = list(vulns.keys())
                return {
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "country": data.get("country_name"),
                    "vulns": vulns[:10]  # Limit to first 10
                }
            elif response.status_code == 404:
                return {"error": "Not found"}
            elif response.status_code == 429:
                return {"error": "Rate limited"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_hash_virustotal(self, file_hash: str) -> Optional[Dict]:
        """Enrich file hash using VirusTotal"""
        if not self.vt_api_key:
            return {"error": "No API key"}
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "type": data.get("type_description"),
                    "names": data.get("names", [])[:5],
                    "threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label")
                }
            elif response.status_code == 404:
                return {"error": "Not found"}
            elif response.status_code == 429:
                return {"error": "Rate limited"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_domain_virustotal(self, domain: str) -> Optional[Dict]:
        """Enrich domain using VirusTotal"""
        if not self.vt_api_key:
            return {"error": "No API key"}
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": data.get("reputation", 0),
                    "registrar": data.get("registrar"),
                    "creation_date": data.get("creation_date")
                }
            elif response.status_code == 404:
                return {"error": "Not found"}
            elif response.status_code == 429:
                return {"error": "Rate limited"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_url_virustotal(self, url_to_check: str) -> Optional[Dict]:
        """Enrich URL using VirusTotal"""
        if not self.vt_api_key:
            return {"error": "No API key"}
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "threat_names": data.get("threat_names", [])
                }
            elif response.status_code == 404:
                return {"error": "Not found"}
            elif response.status_code == 429:
                return {"error": "Rate limited"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_risk_score(self, enriched: Dict) -> int:
        """Calculate risk score 0-100 based on enrichment data"""
        score = 0
        
        vt = enriched.get("enrichment", {}).get("virustotal", {})
        if vt and "error" not in vt:
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            
            if malicious > 10:
                score += 50
            elif malicious > 5:
                score += 35
            elif malicious > 0:
                score += 20
            
            if suspicious > 5:
                score += 15
            elif suspicious > 0:
                score += 10
        
        shodan = enriched.get("enrichment", {}).get("shodan", {})
        if shodan and "error" not in shodan:
            vulns = shodan.get("vulns", [])
            if len(vulns) > 5:
                score += 25
            elif len(vulns) > 0:
                score += 15
            
            ports = shodan.get("ports", [])
            if len(ports) > 20:
                score += 10
        
        # GeoIP risk factors (high-risk countries)
        geoip = enriched.get("enrichment", {}).get("geoip", {})
        if geoip and "error" not in geoip:
            high_risk_countries = ["RU", "CN", "KP", "IR"]
            if geoip.get("country_code") in high_risk_countries:
                score += 15
        
        return min(score, 100)


if __name__ == "__main__":
    enricher = Enricher()
    
    # Test with sample IOCs
    test_iocs = [
        {"type": "ipv4", "value": "45.33.32.156"},
        {"type": "domain", "value": "scanme.nmap.org"},
    ]
    
    print("=" * 60)
    print("HRTIP IOC Enricher - Full Enrichment Test")
    print("=" * 60)
    
    for ioc in test_iocs:
        print(f"\n{'='*60}")
        print(f"Enriching [{ioc['type']}] {ioc['value']}")
        print("=" * 60)
        
        enriched = enricher.enrich(ioc)
        
        print(f"\nRisk Score: {enriched['risk_score']}/100\n")
        
        for source, data in enriched.get("enrichment", {}).items():
            print(f"--- {source.upper()} ---")
            if isinstance(data, dict):
                for key, val in data.items():
                    if isinstance(val, list) and len(val) > 5:
                        print(f"  {key}: {val[:5]} ... ({len(val)} total)")
                    else:
                        print(f"  {key}: {val}")
            else:
                print(f"  {data}")
            print()
        
        time.sleep(1)  # Respect rate limits


# Import and integrate cross-reference
from processor.cross_reference import CrossReference

class FullEnricher(Enricher):
    """Extended enricher with threat feed cross-reference"""
    
    def __init__(self):
        super().__init__()
        self.xref = CrossReference()
    
    def enrich(self, ioc: Dict) -> Dict:
        """Enrich IOC with all sources including threat feed cross-reference"""
        
        # Get base enrichment
        enriched = super().enrich(ioc)
        
        # Add threat feed cross-reference
        ioc_type = ioc.get("type")
        value = ioc.get("value")
        enriched["enrichment"]["threat_feeds"] = self.xref.check_ioc(ioc_type, value)
        
        # Recalculate risk score with threat feed data
        enriched["risk_score"] = self.calculate_full_risk_score(enriched)
        
        return enriched
    
    def calculate_full_risk_score(self, enriched: Dict) -> int:
        """Calculate risk score including threat feed matches"""
        
        # Start with base score
        score = self.calculate_risk_score(enriched)
        
        # Add threat feed score
        threat_feeds = enriched.get("enrichment", {}).get("threat_feeds", {})
        if threat_feeds.get("found"):
            match_count = threat_feeds.get("match_count", 0)
            if match_count >= 3:
                score += 30
            elif match_count >= 1:
                score += 20
            
            # Extra points for known malware families
            if threat_feeds.get("malware_families"):
                score += 10
        
        return min(score, 100)
