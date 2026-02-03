"""
PhishTank collector - fetches verified phishing URLs
https://phishtank.org/
Uses the free data feed (no API key required)
"""

import requests
from datetime import datetime, timezone


def collect():
    """Fetch verified phishing URLs from PhishTank"""
    
    # Free JSON feed of verified phishing URLs
    url = "http://data.phishtank.com/data/online-valid.json"
    
    try:
        headers = {"User-Agent": "HRTIP/1.0"}
        response = requests.get(url, headers=headers, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        # Limit to most recent 100
        results = []
        for item in data[:100]:
            results.append({
                "source": "phishtank",
                "type": "url",
                "value": item.get("url"),
                "threat_type": "phishing",
                "target": item.get("target"),
                "verified": True,
                "verification_time": item.get("verification_time"),
                "collected_at": datetime.now(timezone.utc).isoformat()
            })
        
        print(f"[PhishTank] Collected {len(results)} phishing URLs")
        return results
        
    except requests.RequestException as e:
        print(f"[PhishTank] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
