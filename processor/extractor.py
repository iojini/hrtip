"""
IOC Extractor - extracts indicators from unstructured text
"""

import re
from typing import List, Dict


PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|co|uk|de|fr|jp)\b",
    "url": r"https?://[^\s<>\"'\)]+",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
}

# Private IPs to ignore
PRIVATE_IP_PATTERNS = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^192\.168\.",
    r"^127\.",
]


def extract(text: str, include_private_ips: bool = False) -> List[Dict]:
    """Extract all IOCs from text"""
    
    results = []
    seen = set()
    
    for ioc_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        for match in matches:
            value = match.lower() if ioc_type not in ["url", "cve"] else match
            
            # Skip private IPs unless requested
            if ioc_type == "ipv4" and not include_private_ips:
                if any(re.match(p, value) for p in PRIVATE_IP_PATTERNS):
                    continue
            
            # Deduplicate
            key = f"{ioc_type}:{value}"
            if key in seen:
                continue
            seen.add(key)
            
            results.append({
                "type": ioc_type,
                "value": value
            })
    
    return results


def extract_from_file(filepath: str) -> List[Dict]:
    """Extract IOCs from a file"""
    with open(filepath, "r") as f:
        return extract(f.read())


if __name__ == "__main__":
    sample = """
    THREAT REPORT: Healthcare Ransomware Campaign
    
    C2 Servers:
    - 45.33.32.156 (primary)
    - 185.220.101.34 (backup)
    
    Malicious domains:
    - data-exfil.malware.ru
    - pharmacy-login.xyz
    
    Phishing URL: https://fake-pharmacy.xyz/login.php
    
    File hashes:
    - MD5: 5d41402abc4b2a76b9719d911017c592
    - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    
    Exploits: CVE-2024-1234
    Contact: attacker@evil-mail.com
    
    Internal (ignored): 192.168.1.100, 10.0.0.50
    """
    
    iocs = extract(sample)
    print(f"Extracted {len(iocs)} IOCs:\n")
    for ioc in iocs:
        print(f"  [{ioc['type']:8}] {ioc['value']}")
