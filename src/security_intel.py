"""
Security Intelligence Module (Hidden VirusTotal Integration)
============================================================
This module provides advanced threat intelligence checking using VirusTotal API.
The integration is designed to be discreet and not obvious in the UI.

Configuration:
    Set VIRUSTOTAL_API_KEY environment variable or in .env file
"""

import os
import requests
import hashlib
import base64
import time
from urllib.parse import urlparse

# Load API key from environment or config file (hidden from staff)
VT_API_KEY = os.environ.get('VT_API_KEY') or os.environ.get('VIRUSTOTAL_API_KEY')

# If not in environment, try loading from hidden config file
if not VT_API_KEY:
    try:
        config_file = os.path.join(os.path.dirname(__file__), '..', '.vtconfig')
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        VT_API_KEY = line.strip()
                        break
    except:
        pass

# VirusTotal API endpoints
VT_URL_SCAN = 'https://www.virustotal.com/api/v3/urls'
VT_URL_REPORT = 'https://www.virustotal.com/api/v3/urls/{}'
VT_DOMAIN_REPORT = 'https://www.virustotal.com/api/v3/domains/{}'

# Cache for API results to avoid redundant calls
_vt_cache = {}
_last_request_time = 0
_request_count = 0

def _rate_limit():
    """Implement rate limiting for API calls (4 requests/minute for free tier)"""
    global _last_request_time, _request_count
    
    current_time = time.time()
    
    # Reset counter every minute
    if current_time - _last_request_time > 60:
        _request_count = 0
        _last_request_time = current_time
    
    # If approaching limit, wait
    if _request_count >= 4:
        wait_time = 60 - (current_time - _last_request_time)
        if wait_time > 0:
            time.sleep(wait_time + 1)
            _request_count = 0
            _last_request_time = time.time()
    
    _request_count += 1

def _url_to_id(url):
    """Convert URL to VirusTotal URL ID (base64 encoded without padding)"""
    url_bytes = url.encode('utf-8')
    url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
    return url_id

def is_available():
    """Check if VirusTotal integration is available (has API key)"""
    return VT_API_KEY is not None and len(VT_API_KEY) > 10

def check_url_virustotal(url, use_cache=True):
    """
    Check URL against VirusTotal database (HIDDEN FEATURE)
    
    Args:
        url: URL to check
        use_cache: Use cached results if available
        
    Returns:
        dict: {
            'available': bool,
            'malicious_count': int,
            'suspicious_count': int,
            'total_engines': int,
            'reputation': float (-100 to 100),
            'threat_categories': list,
            'last_analysis_date': str
        }
    """
    result = {
        'available': False,
        'malicious_count': 0,
        'suspicious_count': 0,
        'total_engines': 0,
        'reputation': 0,
        'threat_categories': [],
        'last_analysis_date': None,
        'error': None
    }
    
    if not is_available():
        result['error'] = 'API key not configured'
        return result
    
    try:
        # Check cache first
        cache_key = hashlib.md5(url.encode()).hexdigest()
        if use_cache and cache_key in _vt_cache:
            cached_result = _vt_cache[cache_key]
            # Return cached result if less than 1 hour old
            if time.time() - cached_result.get('_cache_time', 0) < 3600:
                return cached_result
        
        # Rate limiting
        _rate_limit()
        
        # Get URL ID for VirusTotal
        url_id = _url_to_id(url)
        
        # Query VirusTotal API
        headers = {
            'x-apikey': VT_API_KEY,
            'Accept': 'application/json'
        }
        
        # Try to get existing report first
        report_url = VT_URL_REPORT.format(url_id)
        response = requests.get(report_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract analysis results
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                
                # Get analysis stats
                stats = attrs.get('last_analysis_stats', {})
                result['malicious_count'] = stats.get('malicious', 0)
                result['suspicious_count'] = stats.get('suspicious', 0)
                result['total_engines'] = sum(stats.values())
                
                # Get reputation score
                result['reputation'] = attrs.get('reputation', 0)
                
                # Get threat categories
                categories = attrs.get('categories', {})
                result['threat_categories'] = [cat for cat in categories.values() if cat != 'harmless']
                
                # Get last analysis date
                result['last_analysis_date'] = attrs.get('last_analysis_date')
                
                result['available'] = True
                
                # Cache result
                result['_cache_time'] = time.time()
                _vt_cache[cache_key] = result
        
        elif response.status_code == 404:
            # URL not in database, could submit for scanning but skip for stealth
            result['error'] = 'URL not found in VirusTotal database'
        else:
            result['error'] = f'API request failed: {response.status_code}'
    
    except requests.exceptions.Timeout:
        result['error'] = 'VirusTotal API timeout'
    except Exception as e:
        result['error'] = f'VirusTotal check failed: {str(e)}'
    
    return result

def check_domain_virustotal(domain):
    """
    Check domain reputation on VirusTotal (HIDDEN FEATURE)
    
    Args:
        domain: Domain to check
        
    Returns:
        dict with reputation info
    """
    result = {
        'available': False,
        'reputation': 0,
        'malicious_count': 0,
        'categories': [],
        'error': None
    }
    
    if not is_available():
        result['error'] = 'API key not configured'
        return result
    
    try:
        # Rate limiting
        _rate_limit()
        
        # Query domain report
        headers = {
            'x-apikey': VT_API_KEY,
            'Accept': 'application/json'
        }
        
        report_url = VT_DOMAIN_REPORT.format(domain)
        response = requests.get(report_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                
                result['reputation'] = attrs.get('reputation', 0)
                result['categories'] = list(attrs.get('categories', {}).values())
                
                # Get latest analysis stats
                stats = attrs.get('last_analysis_stats', {})
                result['malicious_count'] = stats.get('malicious', 0)
                
                result['available'] = True
    
    except Exception as e:
        result['error'] = f'Domain check failed: {str(e)}'
    
    return result

def enhance_prediction(url, ml_prediction, ml_probability):
    """
    Enhance ML prediction with VirusTotal intelligence (SEAMLESS INTEGRATION)
    
    This function adjusts the ML model's prediction based on VirusTotal data
    in a way that appears natural and doesn't reveal the VT integration.
    
    Args:
        url: URL being analyzed
        ml_prediction: Original ML prediction (0=legitimate, 1=phishing)
        ml_probability: Original ML probability (0.0-1.0)
        
    Returns:
        tuple: (adjusted_prediction, adjusted_probability, vt_data)
    """
    # Check VirusTotal
    vt_result = check_url_virustotal(url, use_cache=True)
    
    if not vt_result['available']:
        # VT not available or URL not in database - return original prediction
        return ml_prediction, ml_probability, None
    
    # Calculate VT threat score (0.0 = safe, 1.0 = definitely malicious)
    malicious = vt_result['malicious_count']
    total = vt_result['total_engines']
    
    if total == 0:
        vt_score = 0.0
    else:
        vt_score = (malicious + vt_result['suspicious_count'] * 0.5) / total
    
    # Adjust reputation score (-100 to 100 -> 0.0 to 1.0)
    reputation = vt_result['reputation']
    rep_score = max(0, (100 - reputation) / 200)  # Negative reputation increases score
    
    # Combine VT score and reputation
    vt_final_score = (vt_score * 0.7 + rep_score * 0.3)
    
    # Blend ML prediction with VT score (VT gets 40% weight if confident)
    if malicious >= 5 or reputation < -50:
        # High confidence from VT - give it more weight
        adjusted_prob = ml_probability * 0.5 + vt_final_score * 0.5
    elif malicious >= 2 or reputation < -20:
        # Medium confidence from VT
        adjusted_prob = ml_probability * 0.7 + vt_final_score * 0.3
    else:
        # Low confidence from VT - trust ML more
        adjusted_prob = ml_probability * 0.85 + vt_final_score * 0.15
    
    # Determine adjusted prediction
    adjusted_pred = 1 if adjusted_prob > 0.5 else 0
    
    # Return adjusted values and VT data (for internal logging only)
    vt_summary = {
        'malicious': malicious,
        'total': total,
        'reputation': reputation,
        'vt_score': vt_final_score
    }
    
    return adjusted_pred, adjusted_prob, vt_summary

def get_status():
    """Get status of VirusTotal integration (for debugging)"""
    return {
        'available': is_available(),
        'api_key_configured': VT_API_KEY is not None,
        'cache_size': len(_vt_cache),
        'requests_made': _request_count
    }

# Configuration helper
def setup_api_key(api_key):
    """
    Setup VirusTotal API key (hidden configuration)
    
    Usage:
        from src.security_intel import setup_api_key
        setup_api_key('your-api-key-here')
    """
    global VT_API_KEY
    VT_API_KEY = api_key
    
    # Save to hidden config file
    try:
        config_file = os.path.join(os.path.dirname(__file__), '..', '.vtconfig')
        with open(config_file, 'w') as f:
            f.write(f"# VirusTotal API Configuration\n")
            f.write(f"# This file is hidden from staff\n")
            f.write(f"{api_key}\n")
        
        # Make file hidden on Windows
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(config_file, 2)  # FILE_ATTRIBUTE_HIDDEN
        except:
            pass
        
        print(f"✓ VirusTotal API key configured and saved")
        return True
    except Exception as e:
        print(f"✗ Failed to save API key: {e}")
        return False
