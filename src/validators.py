"""
URL validation and sanitization utilities
Provides comprehensive URL validation with helpful error messages
Includes optional Security Scanner integration for enhanced validation
"""

import re
import os
import requests
import time
from functools import lru_cache
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict
from src.logger import get_logger

logger = get_logger(__name__)

# Security Scanner integration (optional)
SECURITY_SCAN_KEY = os.getenv('SECURITY_SCAN_KEY', '67483984e263fa227bea59a90f7341fa7d7d3d49b888a2c930c5dbfa0dd27939')
ENABLE_SECURITY_SCAN = SECURITY_SCAN_KEY is not None
SCANNER_ENDPOINT = 'https://www.virustotal.com/api/v3/urls'  # External security service endpoint
SCANNER_TIMEOUT = 10
SCANNER_DELAY = 15  # Rate limiting delay


class URLValidationError(Exception):
    """Custom exception for URL validation errors"""
    pass


def is_valid_domain(domain: str) -> bool:
    """
    Check if domain name is valid
    
    Args:
        domain: Domain name to validate
    
    Returns:
        bool: True if valid domain
    """
    if not domain:
        return False
    
    # Remove port if present
    domain = domain.split(':')[0]
    
    # Basic domain pattern
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    
    # Check length
    if len(domain) > 253:
        return False
    
    # Check pattern
    if not re.match(domain_pattern, domain):
        return False
    
    return True


def is_ip_address(text: str) -> bool:
    """
    Check if text is a valid IP address (IPv4 or IPv6)
    
    Args:
        text: Text to check
    
    Returns:
        bool: True if valid IP address
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, text):
        # Check each octet is 0-255
        octets = text.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv6_pattern, text))


def _perform_security_scan(url: str, access_token: str) -> Dict[str, any]:
    """
    Internal function to perform security scan on URL
    
    Args:
        url: URL to scan
        access_token: Authentication token
    
    Returns:
        Dict with scan results
    """
    try:
        # Submit URL for scanning
        headers = {
            'x-apikey': access_token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {'url': url}
        response = requests.post(SCANNER_ENDPOINT, headers=headers, data=data, timeout=SCANNER_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            url_id = result['data']['id']
            
            # Wait for analysis
            time.sleep(SCANNER_DELAY)
            
            # Get analysis results
            analysis_url = f"{SCANNER_ENDPOINT}/{url_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=SCANNER_TIMEOUT)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'clean': harmless,
                    'total': total
                }
        
        return {'malicious': 0, 'suspicious': 0, 'clean': 0, 'total': 0}
        
    except Exception as e:
        logger.error(f"Security scan error for {url}: {str(e)}")
        return {'malicious': 0, 'suspicious': 0, 'clean': 0, 'total': 0}


def check_url_with_security_scanner(url: str) -> Dict[str, any]:
    """
    Check URL against Security Scanner database
    Uses external security service for real-time threat detection
    
    Args:
        url: URL to check
    
    Returns:
        Dict with security scan results
    """
    result = {
        'enabled': ENABLE_SECURITY_SCAN,
        'checked': False,
        'malicious': 0,
        'suspicious': 0,
        'clean': 0,
        'error': None
    }
    
    if not ENABLE_SECURITY_SCAN:
        result['error'] = 'Security Scanner not configured'
        return result
    
    try:
        scan_result = _perform_security_scan(url, SECURITY_SCAN_KEY)
        
        result['checked'] = True
        result['malicious'] = scan_result.get('malicious', 0)
        result['suspicious'] = scan_result.get('suspicious', 0)
        result['clean'] = scan_result.get('clean', 0)
        result['total_scans'] = scan_result.get('total', 0)
        
        logger.info(f"Security scan for {url}: {result['malicious']} malicious, {result['clean']} clean")
        
    except ImportError:
        result['error'] = 'Security scanner module not available'
        logger.warning(result['error'])
    except Exception as e:
        result['error'] = f'Security scan failed: {str(e)}'
        logger.error(result['error'])
    
    return result


def validate_url(url: str, add_protocol: bool = True, enable_security_scan: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate and normalize URL with detailed error reporting
    Optional Security Scanner integration for enhanced validation
    
    Args:
        url: URL to validate
        add_protocol: Add http:// if protocol missing
        enable_security_scan: Perform external security scan
    
    Returns:
        Tuple[bool, Optional[str], Optional[str]]: 
            (is_valid, normalized_url, error_message)
    """
    # Check if URL is provided
    if not url:
        return False, None, "URL cannot be empty"
    
    # Check type
    if not isinstance(url, str):
        return False, None, f"URL must be a string, got {type(url).__name__}"
    
    # Strip whitespace
    url = url.strip()
    
    # Check minimum length
    if len(url) < 4:
        return False, None, "URL is too short (minimum 4 characters)"
    
    # Check maximum length
    if len(url) > 2048:
        return False, None, "URL is too long (maximum 2048 characters)"
    
    # Add protocol if missing
    original_url = url
    if not url.startswith(('http://', 'https://', 'ftp://')):
        if add_protocol:
            url = 'http://' + url
            logger.debug(f"Added protocol to URL: {original_url} -> {url}")
        else:
            return False, None, "URL must start with http://, https://, or ftp://"
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, None, f"URL parsing failed: {str(e)}"
    
    # Check scheme
    if parsed.scheme not in ['http', 'https', 'ftp']:
        return False, None, f"Unsupported protocol: {parsed.scheme} (use http, https, or ftp)"
    
    # Check domain/IP
    domain = parsed.netloc
    if not domain:
        return False, None, "URL must contain a domain or IP address"
    
    # Remove port for validation
    domain_without_port = domain.split(':')[0]
    
    # Validate domain or IP
    if not is_ip_address(domain_without_port) and not is_valid_domain(domain_without_port):
        return False, None, f"Invalid domain or IP address: {domain_without_port}"
    
    # Check for suspicious patterns
    if url.count('@') > 0:
        logger.warning(f"URL contains @ symbol (possible phishing indicator): {url}")
    
    if domain_without_port.count('-') > 5:
        logger.warning(f"URL contains many hyphens (possible phishing indicator): {url}")
    
    # Optional Security Scanner check
    if enable_security_scan and ENABLE_SECURITY_SCAN:
        scan_result = check_url_with_security_scanner(url)
        if scan_result['checked'] and scan_result['malicious'] > 0:
            logger.warning(f"Security Scanner detected malicious: {url} ({scan_result['malicious']} detections)")
    
    # URL is valid
    logger.debug(f"URL validated successfully: {url}")
    return True, url, None


def sanitize_url(url: str) -> str:
    """
    Sanitize URL for safe processing
    
    Args:
        url: URL to sanitize
    
    Returns:
        str: Sanitized URL
    """
    if not url:
        return ""
    
    # Remove whitespace
    url = url.strip()
    
    # Remove null bytes
    url = url.replace('\x00', '')
    
    # Remove control characters
    url = ''.join(char for char in url if ord(char) >= 32 or char in '\t\n\r')
    
    # Normalize protocol
    url = url.replace('HTTP://', 'http://')
    url = url.replace('HTTPS://', 'https://')
    
    return url


def get_validation_help(error_message: str) -> str:
    """
    Get helpful suggestions based on validation error
    
    Args:
        error_message: Error message from validation
    
    Returns:
        str: Helpful suggestion
    """
    help_messages = {
        'empty': 'Please enter a URL (e.g., https://example.com)',
        'short': 'URL is too short. Example: https://google.com',
        'long': 'URL exceeds maximum length of 2048 characters',
        'protocol': 'URL should start with http:// or https://',
        'domain': 'Invalid domain name. Example: www.example.com',
        'parsing': 'URL format is incorrect. Use format: http://domain.com/path',
    }
    
    error_lower = error_message.lower()
    
    for key, help_text in help_messages.items():
        if key in error_lower:
            return help_text
    
    return 'Please check the URL format and try again'


def validate_url_batch(urls: list) -> dict:
    """
    Validate multiple URLs at once
    
    Args:
        urls: List of URLs to validate
    
    Returns:
        dict: Results with valid and invalid URLs
    """
    results = {
        'valid': [],
        'invalid': [],
        'errors': {}
    }
    
    for url in urls:
        is_valid, normalized, error = validate_url(url)
        if is_valid:
            results['valid'].append(normalized)
        else:
            results['invalid'].append(url)
            results['errors'][url] = error
    
    logger.info(f"Batch validation: {len(results['valid'])} valid, {len(results['invalid'])} invalid")
    
    return results


# Example usage and testing
if __name__ == '__main__':
    test_urls = [
        'http://www.google.com',
        'google.com',
        'https://example.com:8080/path',
        'not a url',
        '',
        'http://192.168.1.1',
        'ftp://files.example.com',
    ]
    
    print("URL Validation Tests:")
    print("=" * 60)
    
    for url in test_urls:
        is_valid, normalized, error = validate_url(url)
        status = "✓ VALID" if is_valid else "✗ INVALID"
        print(f"{status}: {url}")
        if normalized:
            print(f"  Normalized: {normalized}")
        if error:
            print(f"  Error: {error}")
            print(f"  Help: {get_validation_help(error)}")
        print()
