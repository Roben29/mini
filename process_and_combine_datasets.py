"""
Process and Combine Datasets
============================
Processes legitimate.csv and malicious.csv to create a balanced urls.csv dataset.

Key Features:
- Handles legitimate URLs without https:// prefix (e.g., google.com)
- Extracts URLs from malicious.csv (with full https://)
- Creates balanced dataset in batches of 10,000
- Ensures proper URL formatting and labeling

Usage:
    python process_and_combine_datasets.py
"""

import pandas as pd
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
import re

def extract_domain_from_url(url):
    """
    Extract clean domain from full URL or return as-is if already a domain.
    
    Args:
        url: Full URL or domain name
        
    Returns:
        Clean domain name
    """
    url = str(url).strip()
    
    # If it's already a simple domain (no protocol), return as-is
    if not url.startswith(('http://', 'https://', 'ftp://', '//')):
        # Clean up any leading numbers and commas (from CSV format like "1,google.com")
        url = re.sub(r'^\d+,\s*', '', url)
        return url.strip()
    
    # Parse full URL to extract domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port if present
        domain = domain.split(':')[0]
        return domain.strip()
    except:
        # If parsing fails, try to extract domain using regex
        match = re.search(r'(?:https?://)?(?:www\.)?([^/:\s]+)', url)
        if match:
            return match.group(1).strip()
        return url.strip()

def normalize_url(url):
    """
    Normalize URL to standard format: https://domain
    
    Args:
        url: URL or domain to normalize
        
    Returns:
        Normalized URL with https:// prefix
    """
    url = str(url).strip()
    
    # Remove any leading numbers and commas from CSV format
    url = re.sub(r'^\d+,\s*', '', url)
    url = url.strip()
    
    # If already has protocol, return as-is
    if url.startswith(('http://', 'https://')):
        return url
    
    # If starts with //, add https:
    if url.startswith('//'):
        return 'https:' + url
    
    # Otherwise, add https://
    return 'https://' + url

def load_legitimate_urls(filepath, max_urls=None):
    """
    Load legitimate URLs from CSV file.
    Format: number,domain.com (no https://)
    
    Args:
        filepath: Path to legitimate.csv
        max_urls: Maximum number of URLs to load (None for all)
        
    Returns:
        List of normalized URLs
    """
    print(f"\n📂 Loading legitimate URLs from: {filepath}")
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Read CSV - handle different formats
    try:
        # Try reading with header
        df = pd.read_csv(filepath, header=0)
        
        # If only one column or first column looks like numbers, assume no header
        if len(df.columns) == 1 or df.columns[0].isdigit():
            df = pd.read_csv(filepath, header=None, names=['index', 'url'])
        
    except Exception as e:
        # Try reading without header
        try:
            df = pd.read_csv(filepath, header=None)
            # Assume format: number,domain
            if len(df.columns) >= 2:
                df.columns = ['index', 'url']
            else:
                df.columns = ['url']
        except Exception as e2:
            raise Exception(f"Failed to read CSV: {e2}")
    
    # Get URL column
    if 'url' in df.columns:
        urls = df['url']
    elif len(df.columns) >= 2:
        # Assume second column is URL
        urls = df.iloc[:, 1]
    else:
        # Use first column
        urls = df.iloc[:, 0]
    
    # Clean and normalize URLs
    urls = urls.dropna().astype(str).str.strip()
    
    # Remove empty URLs
    urls = urls[urls != '']
    
    # Remove any URLs that are just numbers
    urls = urls[~urls.str.match(r'^\d+$')]
    
    # Extract domains and normalize
    print(f"   🔧 Processing {len(urls):,} legitimate URLs...")
    normalized_urls = []
    
    for url in urls:
        try:
            # Extract domain from format like "1,google.com"
            domain = extract_domain_from_url(url)
            
            # Skip invalid domains
            if not domain or len(domain) < 3 or domain.isdigit():
                continue
            
            # Normalize to https:// format
            normalized = normalize_url(domain)
            normalized_urls.append(normalized)
            
        except Exception as e:
            continue
    
    # Remove duplicates
    original_count = len(normalized_urls)
    normalized_urls = list(set(normalized_urls))
    duplicates_removed = original_count - len(normalized_urls)
    
    if duplicates_removed > 0:
        print(f"   🧹 Removed {duplicates_removed:,} duplicate URLs")
    
    # Limit if requested
    if max_urls and len(normalized_urls) > max_urls:
        print(f"   ✂️  Limiting to {max_urls:,} URLs")
        normalized_urls = normalized_urls[:max_urls]
    
    print(f"   ✓ Loaded {len(normalized_urls):,} unique legitimate URLs")
    
    return normalized_urls

def load_malicious_urls(filepath, max_urls=None):
    """
    Load malicious URLs from CSV file.
    Format: phish_id,url,phish_detail_url,... (has https://)
    
    Args:
        filepath: Path to malicious.csv
        max_urls: Maximum number of URLs to load (None for all)
        
    Returns:
        List of URLs
    """
    print(f"\n📂 Loading malicious URLs from: {filepath}")
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        raise Exception(f"Failed to read CSV: {e}")
    
    # Find URL column
    url_col = None
    for col in df.columns:
        col_lower = col.lower().strip()
        if col_lower in ['url', 'urls', 'link']:
            url_col = col
            break
    
    if url_col is None:
        # Try to find column with http/https URLs
        for col in df.columns:
            sample = df[col].astype(str).str.strip().iloc[0] if len(df) > 0 else ""
            if sample.startswith(('http://', 'https://')):
                url_col = col
                print(f"   ⚠ No 'url' column found, using: '{col}'")
                break
    
    if url_col is None:
        raise Exception("Could not find URL column in malicious.csv")
    
    print(f"   ✓ Found URL column: '{url_col}'")
    
    # Extract URLs
    urls = df[url_col].dropna().astype(str).str.strip()
    
    # Remove empty URLs
    urls = urls[urls != '']
    
    # Filter only valid URLs (must start with http:// or https://)
    urls = urls[urls.str.startswith(('http://', 'https://'))]
    
    # Remove duplicates
    original_count = len(urls)
    urls = urls.drop_duplicates()
    duplicates_removed = original_count - len(urls)
    
    if duplicates_removed > 0:
        print(f"   🧹 Removed {duplicates_removed:,} duplicate URLs")
    
    urls_list = urls.tolist()
    
    # Limit if requested
    if max_urls and len(urls_list) > max_urls:
        print(f"   ✂️  Limiting to {max_urls:,} URLs")
        urls_list = urls_list[:max_urls]
    
    print(f"   ✓ Loaded {len(urls_list):,} unique malicious URLs")
    
    return urls_list

def create_balanced_batches(legitimate_urls, malicious_urls, batch_size=10000, output_file='data/urls.csv'):
    """
    Create balanced dataset with URLs in batches.
    
    Args:
        legitimate_urls: List of legitimate URLs
        malicious_urls: List of malicious URLs
        batch_size: Number of URLs per batch (will be split 50/50)
        output_file: Output CSV file path
    """
    print("\n" + "="*70)
    print("  CREATING BALANCED DATASET")
    print("="*70)
    
    legit_count = len(legitimate_urls)
    mal_count = len(malicious_urls)
    
    print(f"\n📊 Available URLs:")
    print(f"   Legitimate: {legit_count:,}")
    print(f"   Malicious:  {mal_count:,}")
    
    # Determine how many URLs we can use (balanced 50/50)
    max_per_class = min(legit_count, mal_count)
    print(f"\n   Maximum balanced dataset: {max_per_class:,} per class")
    print(f"   Total possible:          {max_per_class * 2:,} URLs")
    
    # Calculate batch configuration
    urls_per_class = batch_size // 2
    total_batches = max_per_class // urls_per_class
    
    print(f"\n📦 Batch Configuration:")
    print(f"   Batch size:    {batch_size:,} URLs ({urls_per_class:,} per class)")
    print(f"   Total batches: {total_batches:,}")
    print(f"   Total URLs:    {total_batches * batch_size:,}")
    
    # Limit URLs to what we'll actually use
    legitimate_urls = legitimate_urls[:total_batches * urls_per_class]
    malicious_urls = malicious_urls[:total_batches * urls_per_class]
    
    # Create batches
    print(f"\n📝 Creating balanced dataset...")
    all_data = []
    
    for batch_num in range(total_batches):
        start_idx = batch_num * urls_per_class
        end_idx = start_idx + urls_per_class
        
        # Get batch URLs
        batch_legit = legitimate_urls[start_idx:end_idx]
        batch_mal = malicious_urls[start_idx:end_idx]
        
        # Add legitimate URLs (label=0)
        for url in batch_legit:
            all_data.append({'url': url, 'label': 0})
        
        # Add malicious URLs (label=1)
        for url in batch_mal:
            all_data.append({'url': url, 'label': 1})
        
        if (batch_num + 1) % 10 == 0 or batch_num == total_batches - 1:
            print(f"   ✓ Processed batch {batch_num + 1}/{total_batches} ({len(all_data):,} URLs so far)")
    
    # Create DataFrame
    df = pd.DataFrame(all_data)
    
    # Shuffle to mix legitimate and malicious
    print(f"\n🔀 Shuffling {len(df):,} URLs...")
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Remove any duplicates
    original_len = len(df)
    df = df.drop_duplicates(subset=['url'], keep='first')
    removed = original_len - len(df)
    
    if removed > 0:
        print(f"🧹 Removed {removed:,} duplicate URLs")
    
    # Save to file
    print(f"\n💾 Saving to: {output_file}")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    
    # Final statistics
    final_legit = len(df[df['label'] == 0])
    final_mal = len(df[df['label'] == 1])
    total = len(df)
    
    print("\n" + "="*70)
    print("  ✅ DATASET CREATED SUCCESSFULLY!")
    print("="*70)
    print(f"\n📊 Final Statistics:")
    print(f"   Total URLs:     {total:,}")
    print(f"   Legitimate (0): {final_legit:,} ({final_legit/total*100:.2f}%)")
    print(f"   Malicious (1):  {final_mal:,} ({final_mal/total*100:.2f}%)")
    
    if final_legit > 0 and final_mal > 0:
        ratio = final_mal / final_legit
        print(f"   Balance:        1:{ratio:.3f}")
        
        # Visual representation
        legit_bar = '█' * int(final_legit / total * 50)
        mal_bar = '█' * int(final_mal / total * 50)
        print(f"\n   Legitimate: {legit_bar}")
        print(f"   Malicious:  {mal_bar}")
        
        if abs(ratio - 1.0) < 0.01:
            print(f"\n   🎯 PERFECT BALANCE ACHIEVED!")
    
    print(f"\n💾 Output file: {output_file}")
    print(f"🕒 Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    return df

def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("  DATASET PROCESSOR")
    print("  Process and Combine Legitimate + Malicious URLs")
    print("="*70)
    
    # File paths
    legit_file = 'data/legimate.csv'  # Note: typo in original filename
    mal_file = 'data/malicious.csv'
    output_file = 'data/urls.csv'
    
    try:
        # Load URLs
        print("\n[Step 1/3] Loading URLs from CSV files...")
        
        # Load legitimate URLs (limit to match malicious count for balance)
        legitimate_urls = load_legitimate_urls(legit_file, max_urls=None)
        
        # Load malicious URLs
        malicious_urls = load_malicious_urls(mal_file, max_urls=None)
        
        # Create balanced dataset
        print("\n[Step 2/3] Creating balanced dataset...")
        df = create_balanced_batches(
            legitimate_urls,
            malicious_urls,
            batch_size=10000,  # 10k URLs per batch (5k legitimate + 5k malicious)
            output_file=output_file
        )
        
        # Verify output
        print("\n[Step 3/3] Verifying output...")
        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file) / (1024 * 1024)  # MB
            print(f"   ✓ File created: {output_file}")
            print(f"   ✓ File size: {file_size:.2f} MB")
            print(f"   ✓ Total URLs: {len(df):,}")
        
        print("\n" + "="*70)
        print("  🚀 NEXT STEPS")
        print("="*70)
        print("  1. Train models:")
        print("     python -m src.main")
        print("\n  2. Or use batch file:")
        print("     TRAIN_MODELS.bat")
        print("\n  3. After training, run GUI:")
        print("     python -m src.gui")
        print("="*70 + "\n")
        
        return True
        
    except FileNotFoundError as e:
        print(f"\n❌ ERROR: {e}")
        print("\n📁 Required files:")
        print(f"   • {legit_file}")
        print(f"   • {mal_file}")
        print("\nPlease ensure these files exist in the data/ folder.")
        return False
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
