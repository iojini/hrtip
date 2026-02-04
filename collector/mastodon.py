"""
Mastodon collector - monitors infosec community for threat intel
Uses public API (no auth required for public posts)
"""

import requests
from datetime import datetime, timezone
from typing import List, Dict
import re


# Popular infosec Mastodon instances
INFOSEC_INSTANCES = [
    "infosec.exchange",
    "ioc.exchange",
]

# Hashtags to monitor
THREAT_HASHTAGS = [
    "threatintel",
    "malware",
    "ransomware",
    "phishing",
    "ioc",
    "cybersecurity",
    "infosec",
]


def fetch_hashtag_timeline(instance: str, hashtag: str, limit: int = 20) -> List[Dict]:
    """Fetch public posts for a hashtag from a Mastodon instance"""
    
    url = f"https://{instance}/api/v1/timelines/tag/{hashtag}"
    params = {"limit": limit}
    
    try:
        response = requests.get(url, params=params, timeout=15, headers={
            "User-Agent": "HRTIP/1.0 Security Research Tool"
        })
        
        if response.status_code == 200:
            return response.json()
        else:
            return []
    except Exception as e:
        print(f"[Mastodon] Error fetching {hashtag} from {instance}: {e}")
        return []


def extract_iocs_from_text(text: str) -> List[Dict]:
    """Extract IOCs from post text"""
    
    iocs = []
    
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', ' ', text)
    
    # IP addresses
    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', clean_text)
    for ip in ips:
        if not ip.startswith(('10.', '192.168.', '127.')):
            iocs.append({"type": "ipv4", "value": ip})
    
    # Domains (defanged and normal)
    # Handle defanged: evil[.]com, evil[dot]com, evil(.)com
    defanged = re.sub(r'\[\.?\]|\(\.?\)|[\[\(]dot[\]\)]', '.', clean_text, flags=re.IGNORECASE)
    domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|tk)\b', defanged)
    for domain in domains:
        iocs.append({"type": "domain", "value": domain.lower()})
    
    # Hashes
    md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', clean_text)
    sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', clean_text)
    
    for h in md5s:
        iocs.append({"type": "md5", "value": h.lower()})
    for h in sha256s:
        iocs.append({"type": "sha256", "value": h.lower()})
    
    # CVEs
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', clean_text, re.IGNORECASE)
    for cve in cves:
        iocs.append({"type": "cve", "value": cve.upper()})
    
    return iocs


def collect() -> List[Dict]:
    """Collect threat intel from Mastodon infosec community"""
    
    all_posts = []
    seen_ids = set()
    
    for instance in INFOSEC_INSTANCES:
        for hashtag in THREAT_HASHTAGS[:3]:  # Limit hashtags to avoid rate limits
            posts = fetch_hashtag_timeline(instance, hashtag, limit=10)
            
            for post in posts:
                post_id = post.get("id")
                if post_id in seen_ids:
                    continue
                seen_ids.add(post_id)
                
                content = post.get("content", "")
                extracted_iocs = extract_iocs_from_text(content)
                
                all_posts.append({
                    "source": "mastodon",
                    "instance": instance,
                    "post_id": post_id,
                    "author": post.get("account", {}).get("acct", "unknown"),
                    "content_preview": re.sub(r'<[^>]+>', '', content)[:200],
                    "url": post.get("url"),
                    "hashtags": [t.get("name") for t in post.get("tags", [])],
                    "extracted_iocs": extracted_iocs,
                    "created_at": post.get("created_at"),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
    
    print(f"[Mastodon] Collected {len(all_posts)} posts from infosec community")
    
    # Extract IOCs into flat list
    iocs = []
    for post in all_posts:
        for ioc in post.get("extracted_iocs", []):
            ioc_entry = ioc.copy()
            ioc_entry["source"] = "mastodon"
            ioc_entry["context"] = post.get("content_preview", "")[:100]
            ioc_entry["post_url"] = post.get("url")
            ioc_entry["collected_at"] = post.get("collected_at")
            iocs.append(ioc_entry)
    
    return iocs


def get_posts() -> List[Dict]:
    """Get raw posts for analysis"""
    all_posts = []
    seen_ids = set()
    
    for instance in INFOSEC_INSTANCES:
        for hashtag in THREAT_HASHTAGS[:3]:
            posts = fetch_hashtag_timeline(instance, hashtag, limit=10)
            
            for post in posts:
                post_id = post.get("id")
                if post_id in seen_ids:
                    continue
                seen_ids.add(post_id)
                all_posts.append(post)
    
    return all_posts


if __name__ == "__main__":
    print("=" * 60)
    print("HRTIP Mastodon Infosec Monitor")
    print("=" * 60)
    
    iocs = collect()
    
    print(f"\nExtracted {len(iocs)} IOCs from posts")
    
    if iocs:
        print("\nSample IOCs found:")
        for ioc in iocs[:10]:
            print(f"  [{ioc['type']}] {ioc['value']}")
            if ioc.get('context'):
                print(f"      Context: {ioc['context'][:60]}...")
