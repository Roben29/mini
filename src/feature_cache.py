"""
Feature Extraction Cache Manager
=================================
Caches DNS, SSL, and web content checks to speed up feature extraction.
Uses SQLite database for persistent caching.
"""

import sqlite3
import hashlib
import json
import time
import os
from datetime import datetime, timedelta

# Cache database path
CACHE_DB = 'data/feature_cache.db'

class FeatureCache:
    """
    Persistent cache for feature extraction results
    """
    
    def __init__(self, db_path=CACHE_DB, ttl_hours=24):
        """
        Initialize cache
        
        Args:
            db_path: Path to SQLite database
            ttl_hours: Cache time-to-live in hours (default 24h)
        """
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self._ensure_database()
    
    def _ensure_database(self):
        """Create database and tables if they don't exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feature_cache (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                check_type TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                access_count INTEGER DEFAULT 1
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_url_hash_type 
            ON feature_cache(url_hash, check_type)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_created_at 
            ON feature_cache(created_at)
        ''')
        
        conn.commit()
        conn.close()
    
    def _get_url_hash(self, url):
        """Generate hash for URL"""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def get(self, url, check_type):
        """
        Get cached result
        
        Args:
            url: URL to check
            check_type: Type of check (dns, ssl, whois, content)
            
        Returns:
            Cached result dict or None if not found/expired
        """
        url_hash = self._get_url_hash(url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get cached result
        cursor.execute('''
            SELECT result, created_at FROM feature_cache 
            WHERE url_hash = ? AND check_type = ?
        ''', (url_hash, check_type))
        
        row = cursor.fetchone()
        
        if row:
            result_json, created_at = row
            
            # Check if expired
            created_time = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
            age_hours = (datetime.now() - created_time).total_seconds() / 3600
            
            if age_hours < self.ttl_hours:
                # Update access statistics
                cursor.execute('''
                    UPDATE feature_cache 
                    SET accessed_at = CURRENT_TIMESTAMP,
                        access_count = access_count + 1
                    WHERE url_hash = ? AND check_type = ?
                ''', (url_hash, check_type))
                conn.commit()
                conn.close()
                
                # Return cached result
                return json.loads(result_json)
            else:
                # Expired - delete old entry
                cursor.execute('''
                    DELETE FROM feature_cache 
                    WHERE url_hash = ? AND check_type = ?
                ''', (url_hash, check_type))
                conn.commit()
        
        conn.close()
        return None
    
    def set(self, url, check_type, result):
        """
        Save result to cache
        
        Args:
            url: URL
            check_type: Type of check
            result: Result dict to cache
        """
        url_hash = self._get_url_hash(url)
        result_json = json.dumps(result)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert or replace
        cursor.execute('''
            INSERT OR REPLACE INTO feature_cache 
            (url_hash, url, check_type, result, created_at, accessed_at, access_count)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
        ''', (url_hash, url, check_type, result_json))
        
        conn.commit()
        conn.close()
    
    def clear_expired(self):
        """Remove expired cache entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=self.ttl_hours)
        cutoff_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            DELETE FROM feature_cache 
            WHERE created_at < ?
        ''', (cutoff_str,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def get_stats(self):
        """Get cache statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total entries
        cursor.execute('SELECT COUNT(*) FROM feature_cache')
        total_entries = cursor.fetchone()[0]
        
        # Entries by type
        cursor.execute('''
            SELECT check_type, COUNT(*) 
            FROM feature_cache 
            GROUP BY check_type
        ''')
        by_type = dict(cursor.fetchall())
        
        # Most accessed URLs
        cursor.execute('''
            SELECT url, access_count 
            FROM feature_cache 
            ORDER BY access_count DESC 
            LIMIT 10
        ''')
        most_accessed = cursor.fetchall()
        
        # Database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_entries': total_entries,
            'by_type': by_type,
            'most_accessed': most_accessed,
            'db_size_mb': db_size / (1024 * 1024)
        }
    
    def clear_all(self):
        """Clear entire cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM feature_cache')
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted

# Global cache instance
_cache = None

def get_cache():
    """Get global cache instance"""
    global _cache
    if _cache is None:
        _cache = FeatureCache()
    return _cache

def cached_dns_check(url, check_function):
    """
    Cached DNS check wrapper
    
    Args:
        url: URL to check
        check_function: Function that performs the actual DNS check
        
    Returns:
        Result from check_function (cached or fresh)
    """
    cache = get_cache()
    
    # Try to get from cache
    cached_result = cache.get(url, 'dns')
    if cached_result is not None:
        return cached_result['has_dns'], cached_result['ip_count']
    
    # Perform actual check
    has_dns, ip_count = check_function(url)
    
    # Cache result
    cache.set(url, 'dns', {
        'has_dns': has_dns,
        'ip_count': ip_count
    })
    
    return has_dns, ip_count

def cached_ssl_check(url, check_function):
    """
    Cached SSL check wrapper
    
    Args:
        url: URL to check
        check_function: Function that performs the actual SSL check
        
    Returns:
        Result from check_function (cached or fresh)
    """
    cache = get_cache()
    
    # Try to get from cache
    cached_result = cache.get(url, 'ssl')
    if cached_result is not None:
        return (cached_result['has_ssl'], 
                cached_result['days_valid'], 
                cached_result['is_trusted'])
    
    # Perform actual check
    has_ssl, days_valid, is_trusted = check_function(url)
    
    # Cache result
    cache.set(url, 'ssl', {
        'has_ssl': has_ssl,
        'days_valid': days_valid,
        'is_trusted': is_trusted
    })
    
    return has_ssl, days_valid, is_trusted

def cached_whois_check(url, check_function):
    """
    Cached WHOIS check wrapper
    
    Args:
        url: URL to check
        check_function: Function that performs the actual WHOIS check
        
    Returns:
        Result from check_function (cached or fresh)
    """
    cache = get_cache()
    
    # Try to get from cache (longer TTL for WHOIS - 7 days)
    cached_result = cache.get(url, 'whois')
    if cached_result is not None:
        # Check if less than 7 days old
        return cached_result['domain_age_days']
    
    # Perform actual check
    domain_age_days = check_function(url)
    
    # Cache result
    cache.set(url, 'whois', {
        'domain_age_days': domain_age_days
    })
    
    return domain_age_days

def cached_content_check(url, check_function):
    """
    Cached web content check wrapper
    
    Args:
        url: URL to check
        check_function: Function that performs the actual content check
        
    Returns:
        Result from check_function (cached or fresh)
    """
    cache = get_cache()
    
    # Try to get from cache
    cached_result = cache.get(url, 'content')
    if cached_result is not None:
        return (cached_result['status_code'],
                cached_result['num_forms'],
                cached_result['num_links'],
                cached_result['has_login'],
                cached_result['page_rank_est'])
    
    # Perform actual check
    status_code, num_forms, num_links, has_login, page_rank_est = check_function(url)
    
    # Cache result
    cache.set(url, 'content', {
        'status_code': status_code,
        'num_forms': num_forms,
        'num_links': num_links,
        'has_login': has_login,
        'page_rank_est': page_rank_est
    })
    
    return status_code, num_forms, num_links, has_login, page_rank_est

if __name__ == "__main__":
    # Test cache
    cache = get_cache()
    
    print("Cache Statistics:")
    stats = cache.get_stats()
    print(f"  Total entries: {stats['total_entries']}")
    print(f"  By type: {stats['by_type']}")
    print(f"  Database size: {stats['db_size_mb']:.2f} MB")
    
    if stats['most_accessed']:
        print("\n  Most accessed URLs:")
        for url, count in stats['most_accessed'][:5]:
            print(f"    {url[:50]}... ({count} hits)")
    
    # Clean expired entries
    deleted = cache.clear_expired()
    print(f"\nCleaned {deleted} expired entries")
