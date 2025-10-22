
import pandas as pd
import requests
import os
import time
from datetime import datetime

def download_phishtank_urls(limit=10000):
    """
    Download phishing URLs from PhishTank
    
    Returns:
        list of phishing URLs
    """
    print("Downloading phishing URLs from PhishTank...")
    
    phishing_urls = []
    
    try:
        # PhishTank public feed (JSON format)
        url = "http://data.phishtank.com/data/online-valid.json"
        
        print(f"  Fetching from {url}...")
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for entry in data[:limit]:
                phishing_url = entry.get('url', '')
                if phishing_url:
                    phishing_urls.append(phishing_url)
            
            print(f"  ✓ Downloaded {len(phishing_urls)} phishing URLs from PhishTank")
        else:
            print(f"  ✗ Failed to download from PhishTank: {response.status_code}")
    
    except Exception as e:
        print(f"  ✗ Error downloading from PhishTank: {e}")
    
    return phishing_urls

def download_openphish_urls(limit=10000):
    """
    Download phishing URLs from OpenPhish
    
    Returns:
        list of phishing URLs
    """
    print("Downloading phishing URLs from OpenPhish...")
    
    phishing_urls = []
    
    try:
        # OpenPhish public feed
        url = "https://openphish.com/feed.txt"
        
        print(f"  Fetching from {url}...")
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            phishing_urls = [line.strip() for line in lines if line.strip()][:limit]
            
            print(f"  ✓ Downloaded {len(phishing_urls)} phishing URLs from OpenPhish")
        else:
            print(f"  ✗ Failed to download from OpenPhish: {response.status_code}")
    
    except Exception as e:
        print(f"  ✗ Error downloading from OpenPhish: {e}")
    
    return phishing_urls

def download_tranco_legitimate_urls(limit=10000):
    """
    Download legitimate URLs from Tranco Top 1M list
    
    Returns:
        list of legitimate URLs
    """
    print("Downloading legitimate URLs from Tranco...")
    
    legitimate_urls = []
    
    try:
        # Tranco Top 1M list
        url = "https://tranco-list.eu/top-1m.csv.zip"
        
        print(f"  Fetching from {url}...")
        response = requests.get(url, timeout=60)
        
        if response.status_code == 200:
            # Save zip file temporarily
            zip_path = "data/tranco_top1m.zip"
            os.makedirs("data", exist_ok=True)
            
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            # Extract and read CSV
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("data")
            
            # Read the CSV
            csv_path = "data/top-1m.csv"
            df = pd.read_csv(csv_path, names=['rank', 'domain'])
            
            # Convert domains to full URLs
            for domain in df['domain'].head(limit):
                legitimate_urls.append(f"https://{domain}")
            
            # Clean up
            os.remove(zip_path)
            os.remove(csv_path)
            
            print(f"  ✓ Downloaded {len(legitimate_urls)} legitimate URLs from Tranco")
        else:
            print(f"  ✗ Failed to download from Tranco: {response.status_code}")
    
    except Exception as e:
        print(f"  ✗ Error downloading from Tranco: {e}")
    
    return legitimate_urls

def get_curated_legitimate_urls():
    """
    Get curated list of well-known legitimate websites
    
    Returns:
        list of legitimate URLs
    """
    return [
        # Search engines and portals
        'https://www.google.com', 'https://www.bing.com', 'https://www.yahoo.com',
        'https://www.baidu.com', 'https://www.yandex.com', 'https://duckduckgo.com',
        
        # Social media
        'https://www.facebook.com', 'https://www.twitter.com', 'https://www.instagram.com',
        'https://www.linkedin.com', 'https://www.reddit.com', 'https://www.pinterest.com',
        'https://www.snapchat.com', 'https://www.tiktok.com', 'https://www.tumblr.com',
        
        # Video platforms
        'https://www.youtube.com', 'https://www.netflix.com', 'https://www.twitch.tv',
        'https://www.vimeo.com', 'https://www.dailymotion.com', 'https://www.hulu.com',
        
        # E-commerce
        'https://www.amazon.com', 'https://www.ebay.com', 'https://www.alibaba.com',
        'https://www.walmart.com', 'https://www.target.com', 'https://www.bestbuy.com',
        'https://www.etsy.com', 'https://www.shopify.com', 'https://www.aliexpress.com',
        
        # Technology companies
        'https://www.microsoft.com', 'https://www.apple.com', 'https://www.ibm.com',
        'https://www.oracle.com', 'https://www.intel.com', 'https://www.cisco.com',
        'https://www.dell.com', 'https://www.hp.com', 'https://www.adobe.com',
        
        # Cloud and developer tools
        'https://www.github.com', 'https://www.gitlab.com', 'https://www.bitbucket.org',
        'https://www.stackoverflow.com', 'https://www.aws.amazon.com', 'https://cloud.google.com',
        'https://azure.microsoft.com', 'https://www.docker.com', 'https://www.kubernetes.io',
        
        # News and media
        'https://www.cnn.com', 'https://www.bbc.com', 'https://www.nytimes.com',
        'https://www.theguardian.com', 'https://www.washingtonpost.com', 'https://www.reuters.com',
        'https://www.bloomberg.com', 'https://www.forbes.com', 'https://www.techcrunch.com',
        
        # Education
        'https://www.wikipedia.org', 'https://www.coursera.org', 'https://www.udemy.com',
        'https://www.edx.org', 'https://www.khanacademy.org', 'https://www.mit.edu',
        'https://www.stanford.edu', 'https://www.harvard.edu', 'https://www.oxford.ac.uk',
        
        # Financial services
        'https://www.paypal.com', 'https://www.stripe.com', 'https://www.square.com',
        'https://www.chase.com', 'https://www.bankofamerica.com', 'https://www.wellsfargo.com',
        'https://www.citibank.com', 'https://www.capitalone.com', 'https://www.americanexpress.com',
        
        # Communication
        'https://www.zoom.us', 'https://www.slack.com', 'https://www.discord.com',
        'https://www.skype.com', 'https://www.telegram.org', 'https://www.whatsapp.com',
        
        # Entertainment
        'https://www.spotify.com', 'https://www.soundcloud.com', 'https://www.pandora.com',
        'https://www.imdb.com', 'https://www.rottentomatoes.com', 'https://www.metacritic.com',
        
        # Travel
        'https://www.booking.com', 'https://www.airbnb.com', 'https://www.expedia.com',
        'https://www.tripadvisor.com', 'https://www.kayak.com', 'https://www.hotels.com',
        
        # Government
        'https://www.usa.gov', 'https://www.irs.gov', 'https://www.nih.gov',
        'https://www.cdc.gov', 'https://www.nasa.gov', 'https://www.whitehouse.gov'
    ]

def get_curated_phishing_urls():
    """
    Get curated list of phishing URL patterns
    These are pattern-based examples, not real active phishing sites
    
    Returns:
        list of phishing URLs (patterns)
    """
    brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook',
              'netflix', 'instagram', 'linkedin', 'twitter', 'ebay', 'chase',
              'bankofamerica', 'wellsfargo', 'ups', 'fedex', 'dhl', 'irs']
    
    tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.click', '.link', '.pw', '.cc', '.info', '.biz']
    
    patterns = []
    
    for brand in brands:
        for tld in tlds[:3]:  # Use first 3 TLDs for each brand
            patterns.append(f"http://{brand}-secure{tld}/verify")
            patterns.append(f"http://{brand}-login{tld}/account")
            patterns.append(f"http://secure-{brand}{tld}/update")
            patterns.append(f"http://{brand}-verify{tld}/confirm")
            patterns.append(f"http://www.{brand}-alert{tld}/suspended")
    
    return patterns[:5000]  # Return first 5000 patterns

def create_large_dataset(output_file='data/urls_large.csv', target_size=20000):
    """
    Create large balanced dataset with 10K legitimate + 10K malicious URLs
    
    Args:
        output_file: Path to save dataset
        target_size: Total URLs (split 50/50)
    """
    print("\n" + "="*80)
    print("  LARGE DATASET GENERATOR")
    print("  Creating dataset with 20,000 URLs (10K legitimate + 10K malicious)")
    print("="*80 + "\n")
    
    per_class = target_size // 2
    
    # Collect legitimate URLs
    print("[1/4] Collecting legitimate URLs...")
    legitimate_urls = []
    
    # Add curated URLs
    curated_legit = get_curated_legitimate_urls()
    legitimate_urls.extend(curated_legit)
    print(f"  ✓ Added {len(curated_legit)} curated legitimate URLs")
    
    # Download from Tranco if needed
    remaining_legit = per_class - len(legitimate_urls)
    if remaining_legit > 0:
        tranco_urls = download_tranco_legitimate_urls(limit=remaining_legit)
        legitimate_urls.extend(tranco_urls)
    
    print(f"  Total legitimate URLs: {len(legitimate_urls)}")
    
    # Collect phishing URLs
    print("\n[2/4] Collecting phishing/malicious URLs...")
    phishing_urls = []
    
    # Add curated phishing patterns
    curated_phish = get_curated_phishing_urls()
    phishing_urls.extend(curated_phish)
    print(f"  ✓ Added {len(curated_phish)} curated phishing URL patterns")
    
    # Download from PhishTank
    remaining_phish = per_class - len(phishing_urls)
    if remaining_phish > 0:
        phishtank_urls = download_phishtank_urls(limit=remaining_phish)
        phishing_urls.extend(phishtank_urls)
        
        # Download from OpenPhish if still need more
        remaining_phish = per_class - len(phishing_urls)
        if remaining_phish > 0:
            openphish_urls = download_openphish_urls(limit=remaining_phish)
            phishing_urls.extend(openphish_urls)
    
    print(f"  Total phishing URLs: {len(phishing_urls)}")
    
    # Balance datasets
    print("\n[3/4] Balancing dataset...")
    legitimate_urls = legitimate_urls[:per_class]
    phishing_urls = phishing_urls[:per_class]
    
    print(f"  Legitimate URLs: {len(legitimate_urls)}")
    print(f"  Phishing URLs:   {len(phishing_urls)}")
    
    # Create DataFrame
    print("\n[4/4] Creating balanced dataset...")
    
    legit_df = pd.DataFrame({
        'url': legitimate_urls,
        'label': 0
    })
    
    phish_df = pd.DataFrame({
        'url': phishing_urls,
        'label': 1
    })
    
    # Combine and shuffle
    combined_df = pd.concat([legit_df, phish_df], ignore_index=True)
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Remove duplicates
    original_len = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
    removed = original_len - len(combined_df)
    
    if removed > 0:
        print(f"  Removed {removed} duplicate URLs")
    
    # Save dataset
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    combined_df.to_csv(output_file, index=False)
    
    # Final statistics
    final_total = len(combined_df)
    final_legit = len(combined_df[combined_df['label'] == 0])
    final_phish = len(combined_df[combined_df['label'] == 1])
    
    print("\n" + "="*80)
    print("  ✅ LARGE DATASET CREATED!")
    print("="*80)
    print(f"\nDataset Statistics:")
    print(f"  Total URLs:      {final_total:,}")
    print(f"  Legitimate (0):  {final_legit:,} ({final_legit/final_total*100:.2f}%)")
    print(f"  Phishing (1):    {final_phish:,} ({final_phish/final_total*100:.2f}%)")
    print(f"\nSaved to: {output_file}")
    print(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n" + "="*80)
    print("Next Steps:")
    print("  1. Validate dataset: python validate_dataset_labels.py data/urls_large.csv 500")
    print("  2. Train models: python -m src.main")
    print("="*80 + "\n")
    
    return combined_df

if __name__ == "__main__":
    create_large_dataset()
