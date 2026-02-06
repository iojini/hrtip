"""
Database module for HRTIP - connects to Supabase PostgreSQL
"""

import os
from supabase import create_client, Client
from datetime import datetime
from typing import List, Dict, Optional
import json

# Supabase credentials - will be set via environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

_client: Optional[Client] = None

def get_client() -> Client:
    """Get or create Supabase client"""
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set")
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client


def save_iocs(iocs: List[Dict]) -> int:
    """Save IOCs to database, returns count of inserted records"""
    if not iocs:
        return 0
    
    client = get_client()
    inserted = 0
    
    for ioc in iocs:
        try:
            record = {
                "type": ioc.get("type", "unknown"),
                "value": ioc.get("value", ""),
                "source": ioc.get("source"),
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "confidence_score": ioc.get("confidence_score", 50),
                "tags": ioc.get("tags", []),
                "first_seen": ioc.get("first_seen", datetime.now().isoformat()),
                "last_seen": datetime.now().isoformat(),
                "raw_data": json.dumps(ioc) if isinstance(ioc, dict) else None
            }
            
            # Upsert - insert or update on conflict
            client.table("iocs").upsert(
                record, 
                on_conflict="type,value"
            ).execute()
            inserted += 1
            
        except Exception as e:
            print(f"Error saving IOC {ioc.get('value', 'unknown')}: {e}")
            continue
    
    return inserted


def get_all_iocs(limit: int = 1000) -> List[Dict]:
    """Get all IOCs from database"""
    client = get_client()
    
    response = client.table("iocs")\
        .select("*")\
        .order("confidence_score", desc=True)\
        .limit(limit)\
        .execute()
    
    return response.data


def get_iocs_by_source(source: str, limit: int = 500) -> List[Dict]:
    """Get IOCs filtered by source"""
    client = get_client()
    
    response = client.table("iocs")\
        .select("*")\
        .eq("source", source)\
        .order("last_seen", desc=True)\
        .limit(limit)\
        .execute()
    
    return response.data


def get_iocs_by_type(ioc_type: str, limit: int = 500) -> List[Dict]:
    """Get IOCs filtered by type"""
    client = get_client()
    
    response = client.table("iocs")\
        .select("*")\
        .eq("type", ioc_type)\
        .order("confidence_score", desc=True)\
        .limit(limit)\
        .execute()
    
    return response.data


def get_recent_iocs(hours: int = 24, limit: int = 500) -> List[Dict]:
    """Get IOCs from the last N hours"""
    client = get_client()
    
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    
    response = client.table("iocs")\
        .select("*")\
        .gte("last_seen", cutoff)\
        .order("last_seen", desc=True)\
        .limit(limit)\
        .execute()
    
    return response.data


def get_stats() -> Dict:
    """Get database statistics"""
    client = get_client()
    
    # Total count
    total = client.table("iocs").select("id", count="exact").execute()
    
    # Count by source
    all_iocs = client.table("iocs").select("source").execute()
    source_counts = {}
    for ioc in all_iocs.data:
        src = ioc.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    
    # Count by type
    type_counts = {}
    all_types = client.table("iocs").select("type").execute()
    for ioc in all_types.data:
        t = ioc.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    
    return {
        "total_iocs": total.count,
        "by_source": source_counts,
        "by_type": type_counts
    }


def search_ioc(value: str) -> List[Dict]:
    """Search for a specific IOC value"""
    client = get_client()
    
    response = client.table("iocs")\
        .select("*")\
        .ilike("value", f"%{value}%")\
        .limit(100)\
        .execute()
    
    return response.data


def delete_old_iocs(days: int = 30) -> int:
    """Delete IOCs older than N days"""
    client = get_client()
    
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    response = client.table("iocs")\
        .delete()\
        .lt("last_seen", cutoff)\
        .execute()
    
    return len(response.data) if response.data else 0


if __name__ == "__main__":
    # Test connection
    print("Testing Supabase connection...")
    try:
        stats = get_stats()
        print(f"Connected! Total IOCs: {stats['total_iocs']}")
    except Exception as e:
        print(f"Connection failed: {e}")
        print("Make sure SUPABASE_URL and SUPABASE_KEY are set")
