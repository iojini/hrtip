"""
AlienVault OTX collector - fetches pulses (threat reports with IOCs)
https://otx.alienvault.com/
Requires free API key from https://otx.alienvault.com/api
"""

import requests
from datetime import datetime, timezone
import os


def collect(api_key=None):
    """Fetch recent pulses from AlienVault OTX"""
    
    api_key = api_key or os.getenv("OTX_API_KEY")
    
    if not api_key:
        print("[AlienVault] No API key found. Set OTX_API_KEY environment variable.")
        print("[AlienVault] Get a free key at: https://otx.alienvault.com/api")
        return []
    
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": 10, "page": 1}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        results = []
        for pulse in data.get("results", []):
            # Extract IOCs from each pulse
            for indicator in pulse.get("indicators", [])[:20]:
                results.append({
                    "source": "alienvault_otx",
                    "type": indicator.get("type"),
                    "value": indicator.get("indicator"),
                    "pulse_name": pulse.get("name"),
                    "tags": pulse.get("tags", []),
                    "created": indicator.get("created"),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
        
        # Limit to 100
        results = results[:100]
        
        print(f"[AlienVault] Collected {len(results)} IOCs")
        return results
        
    except requests.RequestException as e:
        print(f"[AlienVault] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
