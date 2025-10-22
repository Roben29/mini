"""
URL validation and sanitization utilities
Provides comprehensive URL validation with helpful error messages
"""

import re
from urllib.parse import urlparse
from typing import Tuple, Optional
from src.logger import get_logger

logger = get_logger(__name__)


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
    Check if text is an IP address
    
    Args:
        text: Text to check
    
    Returns:
        bool: True if IP address
    """
    # IPv4 pattern
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ipv4_pattern, text))


def validate_url(url: str, add_protocol: bool = True) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate and normalize URL with detailed error reporting
    
    Args:
        url: URL to validate
        add_protocol: Add http:// if protocol missing
    
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
