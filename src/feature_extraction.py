import re
import pandas as pd
import math
import socket
import ssl as ssl_module
import requests
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime
import warnings
import time
warnings.filterwarnings('ignore')

# Set reasonable timeouts for network operations
TIMEOUT = 5
MAX_RETRIES = 1

def calculate_entropy(text):
    """Calculate Shannon entropy of a string (measure of randomness)"""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    return entropy

def get_tld(url):
    """Extract top-level domain from URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-1].lower()
        return 'unknown'
    except:
        return 'unknown'

def count_special_chars(text):
    """Count special characters in text"""
    special = set('!@#$%^&*()_+={}[]|\\:;"\'<>,.?/~`')
    return sum(1 for char in text if char in special)

def extract_domain(url):
    """Extract clean domain from URL"""
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        return domain.lower()
    except:
        return ""

def check_dns_record(url):
    """Check if domain has valid DNS record"""
    try:
        domain = extract_domain(url)
        if not domain:
            return 0, 0
        
        # Try to resolve domain
        socket.setdefaulttimeout(TIMEOUT)
        ips = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        ip_addresses = list(set([ip[4][0] for ip in ips]))
        
        return 1, len(ip_addresses)
    except:
        return 0, 0

def check_ssl_certificate(url):
    """Check SSL certificate validity"""
    try:
        domain = extract_domain(url)
        if not domain or not url.startswith('https'):
            return 0, 0, 0
        
        context = ssl_module.create_default_context()
        socket.setdefaulttimeout(TIMEOUT)
        
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiry
                not_after = cert.get('notAfter')
                if not_after:
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_valid = (expire_date - datetime.now()).days
                    
                    # Check if cert is trusted
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    is_trusted = 1 if issuer else 0
                    
                    return 1, max(0, days_valid), is_trusted
    except:
        pass
    
    return 0, 0, 0

def get_domain_age_whois(url):
    """Get domain age using WHOIS"""
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

def check_page_content(url):
    """Fetch and analyze page content"""
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        status = response.status_code
        content = response.text.lower() if response.status_code == 200 else ""
        
        # Analyze content
        num_forms = content.count('<form')
        num_inputs = content.count('<input')
        has_password = int('password' in content or 'passwd' in content)
        num_links = content.count('<a ')
        num_scripts = content.count('<script')
        
        # Check for suspicious patterns
        has_iframe = int('<iframe' in content)
        has_redirect = int('window.location' in content or 'document.location' in content)
        
        return status, num_forms, num_inputs, has_password, num_links, num_scripts, has_iframe, has_redirect
    except:
        return 0, 0, 0, 0, 0, 0, 0, 0

def extract_features(df):
    print(f"\n{'='*70}")
    print(f"  COMPREHENSIVE FEATURE EXTRACTION WITH REAL SECURITY CHECKS")
    print(f"{'='*70}\n")
    print(f"Dataset size: {len(df):,} URLs")
    print(f"⚠️  This will take time - checking real websites!\n")
    
    start_time = time.time()
    
    try:
        # ========== BASIC URL STRUCTURE FEATURES ==========
        print("[1/9] Extracting basic URL structure...")
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
        print(f"   ✓ Extracted 10 features ({time.time() - start_time:.1f}s)")
        
        # ========== ADVANCED STRING ANALYSIS ==========
        print("Calculating entropy and character ratios...")
        df['url_entropy'] = df['url'].apply(calculate_entropy)
        df['special_char_count'] = df['url'].apply(count_special_chars)
        df['special_char_ratio'] = df['special_char_count'] / df['url_length']
        df['digit_count'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))
        df['digit_ratio'] = df['digit_count'] / df['url_length']
        df['letter_count'] = df['url'].apply(lambda x: sum(c.isalpha() for c in x))
        df['letter_ratio'] = df['letter_count'] / df['url_length']
        
        # ========== IP ADDRESS DETECTION ==========
        print("Detecting IP addresses and hexadecimal patterns...")
        df['has_ip'] = df['url'].apply(lambda x: int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', x))))
        df['has_port'] = df['url'].apply(lambda x: int(bool(re.search(r':\d{2,5}', x))))
        
        # ========== DOMAIN ANALYSIS ==========
        print("Analyzing domain characteristics...")
        df['domain'] = df['url'].apply(extract_domain)
        df['domain_length'] = df['domain'].apply(len)
        df['subdomain_count'] = df['domain'].apply(lambda x: x.count('.'))
        df['tld'] = df['url'].apply(get_tld)
        
        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link']
        df['has_suspicious_tld'] = df['tld'].apply(lambda x: int(x in suspicious_tlds))
        
        # Check for trusted TLDs
        trusted_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil']
        df['has_trusted_tld'] = df['tld'].apply(lambda x: int(x in trusted_tlds))
        
        # ========== PROTOCOL AND SECURITY ==========
        print("Checking protocol and security indicators...")
        df['is_https'] = df['url'].apply(lambda x: int(x.startswith('https://')))
        df['is_http'] = df['url'].apply(lambda x: int(x.startswith('http://')))
        
        # ========== PATH AND STRUCTURE ==========
        print("Analyzing URL path structure...")
        df['url_depth'] = df['url'].apply(lambda x: len([p for p in x.split('/') if p and '://' not in p]))
        df['has_query_string'] = df['url'].apply(lambda x: int('?' in x))
        df['query_length'] = df['url'].apply(lambda x: len(x.split('?')[1]) if '?' in x else 0)
        
        # ========== SUSPICIOUS PATTERNS ==========
        print("Detecting suspicious patterns...")
        
        # Multiple subdomains (phishing often uses: legitimate-looking.actual-domain.com)
        df['excessive_subdomains'] = df['subdomain_count'].apply(lambda x: int(x > 3))
        
        # Suspicious character sequences
        df['has_double_slash'] = df['url'].apply(lambda x: int('//' in x.split('://')[1] if '://' in x else False))
        df['has_url_shortener'] = df['url'].apply(lambda x: int(any(short in x.lower() for short in ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly'])))
        
        # ========== BRAND/KEYWORD IMPERSONATION ==========
        print("Checking for brand impersonation...")
        # Suspicious keywords that appear in phishing URLs
        suspicious_keywords = [
            'secure', 'account', 'update', 'login', 'verify', 'confirm', 'banking',
            'signin', 'webscr', 'password', 'suspend', 'restricted', 'alert',
            'credential', 'authenticate', 'validation'
        ]
        
        # Brand names often impersonated
        brands = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 
                  'netflix', 'bank', 'chase', 'wellsfargo', 'dhl', 'fedex']
        
        for kw in suspicious_keywords:
            df[f'has_{kw}'] = df['url'].apply(lambda x: int(kw in x.lower()))
        
        for brand in brands:
            df[f'has_brand_{brand}'] = df['url'].apply(lambda x: int(brand in x.lower()))
        
        # Check if brand name appears in subdomain (common phishing tactic)
        df['brand_in_subdomain'] = df['url'].apply(lambda x: int(
            any(brand in extract_domain(x).split('.')[0].lower() for brand in brands)
        ))
        
        # ========== URL SHORTENING AND REDIRECTION ==========
        df['has_redirect'] = df['url'].apply(lambda x: int(
            'redirect' in x.lower() or 'url=' in x.lower() or 'redir' in x.lower()
        ))
        
        # ========== NETWORK-BASED SECURITY FEATURES ==========
        print(f"\n[7/9] PERFORMING REAL SECURITY CHECKS (This will take time)...")
        print(f"   Checking DNS, SSL, and web content for {len(df):,} URLs...")
        print(f"   Estimated time: {len(df) * 2 / 60:.1f} minutes\n")
        
        # Initialize columns
        df['has_dns'] = 0
        df['dns_ip_count'] = 0
        df['has_ssl'] = 0
        df['ssl_days_valid'] = 0
        df['ssl_trusted'] = 0
        df['http_status'] = 0
        df['num_forms'] = 0
        df['num_inputs'] = 0
        df['has_password_field'] = 0
        df['num_page_links'] = 0
        df['num_scripts'] = 0
        df['has_iframe'] = 0
        df['has_js_redirect'] = 0
        
        # Process each URL
        total = len(df)
        checked = 0
        start_network = time.time()
        
        for idx in df.index:
            if checked % 50 == 0 and checked > 0:
                elapsed = time.time() - start_network
                rate = checked / elapsed
                remaining = (total - checked) / rate
                print(f"   Progress: {checked}/{total} ({checked/total*100:.1f}%) - "
                      f"ETA: {remaining/60:.1f} min", end='\r')
            
            url = df.at[idx, 'url']
            
            # DNS Check (fast)
            has_dns, ip_count = check_dns_record(url)
            df.at[idx, 'has_dns'] = has_dns
            df.at[idx, 'dns_ip_count'] = ip_count
            
            # Only do further checks if DNS exists
            if has_dns:
                # SSL Check (for HTTPS URLs)
                if url.startswith('https'):
                    has_ssl, days_valid, is_trusted = check_ssl_certificate(url)
                    df.at[idx, 'has_ssl'] = has_ssl
                    df.at[idx, 'ssl_days_valid'] = days_valid
                    df.at[idx, 'ssl_trusted'] = is_trusted
                
                # Page Content Check (slower)
                status, forms, inputs, has_pwd, links, scripts, iframe, redirect = check_page_content(url)
                df.at[idx, 'http_status'] = status
                df.at[idx, 'num_forms'] = forms
                df.at[idx, 'num_inputs'] = inputs
                df.at[idx, 'has_password_field'] = has_pwd
                df.at[idx, 'num_page_links'] = links
                df.at[idx, 'num_scripts'] = scripts
                df.at[idx, 'has_iframe'] = iframe
                df.at[idx, 'has_js_redirect'] = redirect
            
            checked += 1
        
        network_time = time.time() - start_network
        print(f"\n   ✓ Completed {checked:,} network security checks ({network_time/60:.1f} minutes)")
        print(f"   Average: {network_time/checked:.2f}s per URL")
        
        # WHOIS domain age (very slow, skip for large datasets)
        print(f"\n[8/9] Domain age check...")
        print(f"   ⚠️  Skipping WHOIS checks (too slow for large datasets)")
        print(f"   Using DNS and SSL data as age proxies")
        df['domain_age_days'] = -1  # Would need dedicated WHOIS service
        
        # ========== FINALIZE FEATURES ==========
        print(f"\n[9/9] Finalizing features...")
        
        # Remove temporary columns
        if 'domain' in df.columns:
            df = df.drop(columns=['domain'])
        if 'tld' in df.columns:
            df = df.drop(columns=['tld'])
        
        # Get all feature columns
        feature_cols = [col for col in df.columns if col not in ['url', 'label']]
        
        print(f"   Converting {len(feature_cols)} features to numeric format...")
        for col in feature_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        total_time = time.time() - start_time
        print(f"\n{'='*70}")
        print(f"  ✅ FEATURE EXTRACTION COMPLETE")
        print(f"{'='*70}")
        print(f"Total features: {len(feature_cols)}")
        print(f"Static features: ~55 (URL patterns)")
        print(f"Network features: ~13 (DNS, SSL, Content)")
        print(f"Total time: {total_time/60:.1f} minutes")
        print(f"Average: {total_time/len(df):.2f}s per URL")
        print(f"{'='*70}\n")
        
        return df
        
    except Exception as e:
        print(f"Feature extraction error: {e}")
        import traceback
        traceback.print_exc()
        
        # Return minimal features if extraction fails
        basic_df = df.copy()
        basic_df['url_length'] = basic_df['url'].apply(len)
        basic_df['num_dots'] = basic_df['url'].apply(lambda x: x.count('.'))
        basic_df['is_https'] = basic_df['url'].apply(lambda x: int(x.startswith('https')))
        basic_df['url_entropy'] = basic_df['url'].apply(calculate_entropy)
        
        for col in ['url_length', 'num_dots', 'is_https', 'url_entropy']:
            basic_df[col] = pd.to_numeric(basic_df[col], errors='coerce').fillna(0)
        return basic_df
