"""
Dataset Label Validator
========================
Validates that URLs in the dataset are correctly labeled by checking them against
multiple security indicators and online databases.

Usage:
    python validate_dataset_labels.py data/urls.csv
"""

import pandas as pd
import sys
import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import time

# Known phishing indicators
PHISHING_INDICATORS = {
    'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', 
                        '.link', '.pw', '.cc', '.info', '.biz'],
    'suspicious_keywords': ['verify', 'account', 'update', 'secure', 'banking', 'signin', 
                           'login', 'suspended', 'locked', 'confirm', 'urgent', 'alert'],
    'trusted_domains': ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 
                       'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
                       'youtube.com', 'linkedin.com', 'twitter.com', 'instagram.com',
                       'netflix.com', 'adobe.com', 'ibm.com', 'oracle.com', 'paypal.com',
                       'ebay.com', 'walmart.com', 'target.com', 'bankofamerica.com',
                       'chase.com', 'wellsfargo.com', 'citibank.com']
}

def extract_domain(url):
    """Extract clean domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        domain = domain.split(':')[0].lower()
        return domain
    except:
        return ""

def check_url_accessibility(url, timeout=5):
    """Check if URL is accessible online"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.head(url, timeout=timeout, allow_redirects=True,
                                verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        return response.status_code < 400, response.status_code
    except:
        return False, 0

def check_dns_exists(url):
    """Check if domain has valid DNS record"""
    try:
        domain = extract_domain(url)
        if not domain:
            return False
        socket.gethostbyname(domain)
        return True
    except:
        return False

def check_ssl_valid(url):
    """Check if HTTPS site has valid SSL certificate"""
    try:
        if not url.startswith('https://'):
            return None  # Not applicable
        
        domain = extract_domain(url)
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert is not None
    except:
        return False

def analyze_url_patterns(url):
    """Analyze URL for suspicious patterns"""
    url_lower = url.lower()
    domain = extract_domain(url)
    
    score = 0  # Higher score = more likely phishing
    reasons = []
    
    # Check for suspicious TLD
    for tld in PHISHING_INDICATORS['suspicious_tlds']:
        if url_lower.endswith(tld):
            score += 30
            reasons.append(f"Suspicious TLD: {tld}")
            break
    
    # Check for trusted domain
    is_trusted = False
    for trusted in PHISHING_INDICATORS['trusted_domains']:
        if trusted in domain:
            score -= 40
            reasons.append(f"Trusted domain: {trusted}")
            is_trusted = True
            break
    
    # Check for IP address instead of domain
    if any(char.isdigit() for char in domain.replace('.', '')):
        import re
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 25
            reasons.append("Uses IP address instead of domain")
    
    # Check for suspicious keywords
    keyword_count = sum(1 for kw in PHISHING_INDICATORS['suspicious_keywords'] if kw in url_lower)
    if keyword_count > 0:
        score += keyword_count * 10
        reasons.append(f"Contains {keyword_count} suspicious keywords")
    
    # Check for excessive subdomains
    subdomain_count = domain.count('.') - 1
    if subdomain_count > 3:
        score += 15
        reasons.append(f"Excessive subdomains: {subdomain_count}")
    
    # Check for HTTP vs HTTPS (legitimate sites usually use HTTPS)
    if url.startswith('http://') and not is_trusted:
        score += 10
        reasons.append("Uses HTTP instead of HTTPS")
    
    # Check URL length (phishing URLs tend to be longer)
    if len(url) > 80:
        score += 10
        reasons.append(f"Long URL: {len(url)} characters")
    
    # Determine predicted label
    predicted_label = 1 if score > 20 else 0
    
    return predicted_label, score, reasons

def validate_single_url(url, expected_label, verbose=False):
    """Validate a single URL against its expected label"""
    results = {
        'url': url,
        'expected_label': expected_label,
        'is_accessible': False,
        'has_dns': False,
        'has_valid_ssl': None,
        'pattern_score': 0,
        'predicted_label': expected_label,
        'is_correct': True,
        'confidence': 0,
        'reasons': []
    }
    
    # Check accessibility
    is_accessible, status_code = check_url_accessibility(url, timeout=5)
    results['is_accessible'] = is_accessible
    results['status_code'] = status_code
    
    # Check DNS
    results['has_dns'] = check_dns_exists(url)
    
    # Check SSL
    if url.startswith('https://'):
        results['has_valid_ssl'] = check_ssl_valid(url)
    
    # Analyze patterns
    predicted, score, reasons = analyze_url_patterns(url)
    results['pattern_score'] = score
    results['predicted_label'] = predicted
    results['reasons'] = reasons
    
    # Calculate confidence
    confidence = abs(score) / 100.0
    results['confidence'] = min(confidence, 1.0)
    
    # Check if label matches prediction
    results['is_correct'] = (predicted == expected_label)
    
    if verbose:
        label_name = "LEGITIMATE" if expected_label == 0 else "PHISHING"
        pred_name = "LEGITIMATE" if predicted == 0 else "PHISHING"
        status = "✓ CORRECT" if results['is_correct'] else "✗ MISLABELED"
        
        print(f"\n{status} - {url}")
        print(f"  Expected: {label_name} (label={expected_label})")
        print(f"  Predicted: {pred_name} (score={score})")
        print(f"  Accessible: {is_accessible} | DNS: {results['has_dns']} | SSL: {results['has_valid_ssl']}")
        if reasons:
            print(f"  Reasons: {', '.join(reasons)}")
    
    return results

def validate_dataset(csv_file, sample_size=None, output_file=None):
    """Validate all URLs in dataset"""
    print("\n" + "="*80)
    print("  DATASET LABEL VALIDATION")
    print("="*80 + "\n")
    
    # Load dataset
    print(f"Loading dataset: {csv_file}")
    df = pd.read_csv(csv_file)
    
    total_urls = len(df)
    print(f"Total URLs: {total_urls:,}")
    
    # Sample if requested
    if sample_size and sample_size < total_urls:
        print(f"Sampling {sample_size:,} URLs for validation...")
        df = df.sample(n=sample_size, random_state=42)
    
    # Validate each URL
    results = []
    start_time = time.time()
    
    print(f"\nValidating {len(df)} URLs...")
    print("This may take a while...\n")
    
    for idx, row in df.iterrows():
        if idx % 50 == 0 and idx > 0:
            elapsed = time.time() - start_time
            rate = idx / elapsed
            remaining = (len(df) - idx) / rate if rate > 0 else 0
            print(f"Progress: {idx}/{len(df)} ({idx/len(df)*100:.1f}%) | "
                  f"Elapsed: {elapsed:.0f}s | ETA: {remaining:.0f}s")
        
        result = validate_single_url(row['url'], row['label'], verbose=False)
        results.append(result)
    
    # Create results DataFrame
    results_df = pd.DataFrame(results)
    
    # Summary statistics
    total = len(results_df)
    correct = results_df['is_correct'].sum()
    incorrect = total - correct
    accuracy = correct / total * 100 if total > 0 else 0
    
    print("\n" + "="*80)
    print("  VALIDATION RESULTS")
    print("="*80 + "\n")
    
    print(f"Total URLs validated: {total:,}")
    print(f"Correctly labeled:    {correct:,} ({accuracy:.2f}%)")
    print(f"Incorrectly labeled:  {incorrect:,} ({100-accuracy:.2f}%)")
    
    # Show mislabeled URLs
    if incorrect > 0:
        print(f"\n⚠ Found {incorrect} potentially mislabeled URLs:")
        print("-" * 80)
        
        mislabeled = results_df[~results_df['is_correct']]
        for idx, row in mislabeled.head(20).iterrows():
            exp_name = "LEGITIMATE" if row['expected_label'] == 0 else "PHISHING"
            pred_name = "LEGITIMATE" if row['predicted_label'] == 0 else "PHISHING"
            print(f"\n{row['url']}")
            print(f"  Expected: {exp_name} | Predicted: {pred_name} (score={row['pattern_score']})")
            print(f"  Accessible: {row['is_accessible']} | DNS: {row['has_dns']}")
            if row['reasons']:
                print(f"  Reasons: {', '.join(row['reasons'][:3])}")
        
        if len(mislabeled) > 20:
            print(f"\n... and {len(mislabeled) - 20} more mislabeled URLs")
    
    # Save results
    if output_file:
        results_df.to_csv(output_file, index=False)
        print(f"\n💾 Detailed results saved to: {output_file}")
    
    print("\n" + "="*80 + "\n")
    
    return results_df

def main():
    if len(sys.argv) < 2:
        print("\nUsage: python validate_dataset_labels.py <csv_file> [sample_size]")
        print("\nExample:")
        print("  python validate_dataset_labels.py data/urls.csv")
        print("  python validate_dataset_labels.py data/urls.csv 500")
        print("\n")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    sample_size = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    output_file = csv_file.replace('.csv', '_validation_results.csv')
    
    try:
        validate_dataset(csv_file, sample_size=sample_size, output_file=output_file)
    except KeyboardInterrupt:
        print("\n\n⚠ Validation interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
