"""
OpenPhish collector - fetches phishing URLs
https://openphish.com/
Uses the free community feed (no API key required)
"""

import requests
from datetime import datetime, timezone


def collect():
    """Fetch phishing URLs from OpenPhish free feed"""
    
    url = "https://openphish.com/feed.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Each line is a phishing URL
        lines = response.text.strip().split("\n")
        
        results = []
        for line in lines[:100]:  # Limit to 100
            if line.strip():
                results.append({
                    "source": "openphish",
                    "type": "url",
                    "value": line.strip(),
                    "threat_type": "phishing",
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
        
        print(f"[OpenPhish] Collected {len(results)} phishing URLs")
        return results
        
    except requests.RequestException as e:
        print(f"[OpenPhish] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
