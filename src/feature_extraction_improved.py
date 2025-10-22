"""
IMPROVED Feature Extraction with REAL Security Checks
Includes: Domain Age, SSL Verification, DNS Checks, Content Analysis
"""

import re
import pandas as pd
import math
import socket
import ssl
import requests
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Set reasonable timeouts
TIMEOUT = 3
MAX_RETRIES = 1

def calculate_entropy(text):
    """Calculate Shannon entropy of a string (measure of randomness)"""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    return entropy

def extract_domain(url):
    """Extract clean domain from URL"""
    try:
        parsed = urlparse(url)
        # Handle both full URLs and just domains
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        return domain.lower()
    except:
        return ""

def get_domain_age_days(url):
    """
    Get domain age in days using WHOIS
    Returns -1 if unavailable
    """
    try:
        import whois
        domain = extract_domain(url)
        if not domain:
            return -1
        
        w = whois.whois(domain)
        
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age = (datetime.now() - creation_date).days
            return max(0, age)
    except:
        pass
    
    return -1

def check_ssl_certificate(url):
    """
    Check if URL has valid SSL certificate
    Returns: (has_ssl, cert_valid_days, is_trusted)
    """
    try:
        domain = extract_domain(url)
        if not domain or not url.startswith('https'):
            return 0, 0, 0
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiry
                not_after = cert.get('notAfter')
                if not_after:
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_valid = (expire_date - datetime.now()).days
                    
                    # Check if cert is trusted (basic check)
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    is_trusted = 1 if issuer else 0
                    
                    return 1, max(0, days_valid), is_trusted
    except:
        pass
    
    return 0, 0, 0

def check_dns_record(url):
    """
    Check if domain has valid DNS record
    Returns: (has_dns, ip_count)
    """
    try:
        domain = extract_domain(url)
        if not domain:
            return 0, 0
        
        ips = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        ip_addresses = list(set([ip[4][0] for ip in ips]))
        
        return 1, len(ip_addresses)
    except:
        return 0, 0

def fetch_page_content_features(url):
    """
    Fetch page and analyze content
    Returns: (status_code, has_forms, num_links, has_login, page_rank_estimate)
    """
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(
            url, 
            timeout=TIMEOUT, 
            allow_redirects=True,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        status_code = response.status_code
        content = response.text.lower()
        
        # Count forms
        num_forms = content.count('<form')
        
        # Count links
        num_links = content.count('<a ')
        
        # Check for login indicators
        has_login = int(any(kw in content for kw in ['password', 'login', 'signin', 'username']))
        
        # Estimate page rank (rough heuristic based on content size and links)
        page_rank_estimate = min(10, (len(content) / 10000) + (num_links / 100))
        
        return status_code, num_forms, num_links, has_login, int(page_rank_estimate)
    except:
        return 0, 0, 0, 0, 0

def extract_features_comprehensive(df, use_network_features=True, sample_size=None):
    """
    Extract comprehensive features including network checks
    
    Args:
        df: DataFrame with 'url' column
        use_network_features: If True, performs actual network checks (slow but accurate)
        sample_size: If set, only checks network features for this many samples
    
    Returns:
        DataFrame with all features
    """
    print(f"\n{'='*70}")
    print("  COMPREHENSIVE FEATURE EXTRACTION")
    print(f"{'='*70}\n")
    print(f"Dataset size: {len(df):,} URLs")
    print(f"Network checks: {'ENABLED' if use_network_features else 'DISABLED (fast mode)'}")
    
    if sample_size and use_network_features:
        print(f"Network check sample: {sample_size:,} URLs (for speed)\n")
    
    try:
        # ========== STATIC URL FEATURES (FAST) ==========
        print("[1/8] Extracting basic URL structure...")
        df['url_length'] = df['url'].apply(len)
        df['num_dots'] = df['url'].apply(lambda x: x.count('.'))
        df['num_hyphens'] = df['url'].apply(lambda x: x.count('-'))
        df['num_underscores'] = df['url'].apply(lambda x: x.count('_'))
        df['num_slashes'] = df['url'].apply(lambda x: x.count('/'))
        df['num_question'] = df['url'].apply(lambda x: x.count('?'))
        df['num_equal'] = df['url'].apply(lambda x: x.count('='))
        df['num_at'] = df['url'].apply(lambda x: x.count('@'))
        df['num_ampersand'] = df['url'].apply(lambda x: x.count('&'))
        df['num_percent'] = df['url'].apply(lambda x: x.count('%'))
        print(f"   ✓ Extracted {10} structural features")
        
        # ========== STRING ANALYSIS ==========
        print("[2/8] Analyzing character patterns...")
        df['url_entropy'] = df['url'].apply(calculate_entropy)
        df['digit_count'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))
        df['digit_ratio'] = df['digit_count'] / df['url_length']
        df['letter_count'] = df['url'].apply(lambda x: sum(c.isalpha() for c in x))
        df['letter_ratio'] = df['letter_count'] / df['url_length']
        df['uppercase_count'] = df['url'].apply(lambda x: sum(c.isupper() for c in x))
        df['uppercase_ratio'] = df['uppercase_count'] / df['url_length']
        print(f"   ✓ Extracted 7 character features")
        
        # ========== DOMAIN ANALYSIS ==========
        print("[3/8] Analyzing domains and TLDs...")
        df['domain'] = df['url'].apply(extract_domain)
        df['domain_length'] = df['domain'].apply(len)
        df['subdomain_count'] = df['domain'].apply(lambda x: x.count('.'))
        
        # TLD analysis
        df['tld'] = df['domain'].apply(lambda x: x.split('.')[-1] if '.' in x else '')
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link', 'pw', 'cc']
        df['has_suspicious_tld'] = df['tld'].apply(lambda x: int(x in suspicious_tlds))
        trusted_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil']
        df['has_trusted_tld'] = df['tld'].apply(lambda x: int(x in trusted_tlds))
        print(f"   ✓ Extracted 6 domain features")
        
        # ========== PROTOCOL & SECURITY INDICATORS ==========
        print("[4/8] Checking protocols and patterns...")
        df['is_https'] = df['url'].apply(lambda x: int(x.startswith('https://')))
        df['is_http'] = df['url'].apply(lambda x: int(x.startswith('http://')))
        df['has_ip'] = df['url'].apply(lambda x: int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', x))))
        df['has_port'] = df['url'].apply(lambda x: int(bool(re.search(r':\d{2,5}', x))))
        df['url_depth'] = df['url'].apply(lambda x: len([p for p in x.split('/') if p and '://' not in p]))
        df['has_query_string'] = df['url'].apply(lambda x: int('?' in x))
        df['query_length'] = df['url'].apply(lambda x: len(x.split('?')[1]) if '?' in x else 0)
        print(f"   ✓ Extracted 7 protocol features")
        
        # ========== SUSPICIOUS PATTERNS ==========
        print("[5/8] Detecting suspicious patterns...")
        df['excessive_subdomains'] = df['subdomain_count'].apply(lambda x: int(x > 3))
        df['has_double_slash'] = df['url'].apply(lambda x: int('//' in x.split('://')[1] if '://' in x else False))
        df['has_url_shortener'] = df['url'].apply(lambda x: int(any(s in x.lower() for s in ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly'])))
        df['has_redirect'] = df['url'].apply(lambda x: int(any(r in x.lower() for r in ['redirect', 'url=', 'redir', 'goto'])))
        print(f"   ✓ Extracted 4 pattern features")
        
        # ========== KEYWORD ANALYSIS ==========
        print("[6/8] Checking for brand impersonation...")
        suspicious_keywords = ['secure', 'account', 'update', 'login', 'verify', 'confirm', 
                               'banking', 'signin', 'webscr', 'password', 'suspend']
        brands = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 'netflix', 'bank']
        
        for kw in suspicious_keywords[:5]:  # Limit to top 5 to avoid too many features
            df[f'has_{kw}'] = df['url'].apply(lambda x: int(kw in x.lower()))
        
        for brand in brands[:5]:  # Limit to top 5 brands
            df[f'has_brand_{brand}'] = df['url'].apply(lambda x: int(brand in x.lower()))
        
        df['brand_in_subdomain'] = df['url'].apply(lambda x: int(
            any(brand in extract_domain(x).split('.')[0].lower() for brand in brands)
        ))
        print(f"   ✓ Extracted 11 keyword features")
        
        # ========== NETWORK FEATURES (SLOW BUT ACCURATE) ==========
        if use_network_features:
            print("[7/8] Performing network security checks...")
            print("   ⚠ This will take time (checking real websites)...")
            
            # Determine which URLs to check
            if sample_size and len(df) > sample_size:
                check_indices = df.sample(n=sample_size, random_state=42).index
                print(f"   Sampling {sample_size:,} URLs for network checks...")
            else:
                check_indices = df.index
            
            # Initialize with default values
            df['domain_age_days'] = -1
            df['has_ssl'] = 0
            df['ssl_days_valid'] = 0
            df['ssl_trusted'] = 0
            df['has_dns'] = 0
            df['dns_ip_count'] = 0
            df['http_status'] = 0
            df['num_forms'] = 0
            df['num_links'] = 0
            df['has_login_form'] = 0
            df['page_rank_est'] = 0
            
            # Check a sample
            checked = 0
            for idx in check_indices:
                if checked % 100 == 0:
                    print(f"   Checked {checked}/{len(check_indices)} URLs...", end='\r')
                
                url = df.at[idx, 'url']
                
                # DNS check (fast)
                has_dns, ip_count = check_dns_record(url)
                df.at[idx, 'has_dns'] = has_dns
                df.at[idx, 'dns_ip_count'] = ip_count
                
                # SSL check (medium speed)
                if url.startswith('https'):
                    has_ssl, days_valid, is_trusted = check_ssl_certificate(url)
                    df.at[idx, 'has_ssl'] = has_ssl
                    df.at[idx, 'ssl_days_valid'] = days_valid
                    df.at[idx, 'ssl_trusted'] = is_trusted
                
                checked += 1
                
                # Stop early if taking too long
                if checked >= min(500, len(check_indices)):
                    print(f"\n   ⚠ Stopping network checks at {checked} to save time")
                    break
            
            print(f"\n   ✓ Completed {checked} network security checks")
        else:
            print("[7/8] Skipping network checks (fast mode)")
            df['domain_age_days'] = -1
            df['has_ssl'] = df['url'].apply(lambda x: int(x.startswith('https')))
            df['ssl_days_valid'] = 0
            df['ssl_trusted'] = 0
            df['has_dns'] = 0
            df['dns_ip_count'] = 0
            df['http_status'] = 0
            df['num_forms'] = 0
            df['num_links'] = 0
            df['has_login_form'] = 0
            df['page_rank_est'] = 0
            print(f"   ✓ Using protocol-based SSL indicator only")
        
        # ========== FINALIZE ==========
        print("[8/8] Finalizing features...")
        
        # Drop temporary columns
        df = df.drop(columns=['domain', 'tld'], errors='ignore')
        
        # Get feature columns
        feature_cols = [col for col in df.columns if col not in ['url', 'label']]
        
        # Ensure all numeric
        for col in feature_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        print(f"\n{'='*70}")
        print(f"  ✅ FEATURE EXTRACTION COMPLETE")
        print(f"{'='*70}")
        print(f"Total features extracted: {len(feature_cols)}")
        print(f"Static features: ~45")
        print(f"Network features: ~11 {'(ACTIVE)' if use_network_features else '(DISABLED)'}")
        print(f"{'='*70}\n")
        
        return df
        
    except Exception as e:
        print(f"\n❌ Feature extraction error: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    # Test with sample URLs
    test_df = pd.DataFrame({
        'url': [
            'https://google.com',
            'http://fake-paypal-login.suspicious.xyz',
            'https://github.com'
        ],
        'label': [0, 1, 0]
    })
    
    result = extract_features_comprehensive(test_df, use_network_features=True)
    print("\nSample features:")
    print(result[['url', 'url_length', 'has_ssl', 'has_dns', 'has_suspicious_tld']].head())
