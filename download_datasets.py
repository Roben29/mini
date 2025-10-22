"""
Dataset Downloader
==================
Downloads legitimate and phishing URL datasets from trusted sources.

Downloads:
- 10,000 legitimate URLs from Tranco
- 10,000 phishing URLs from PhishTank + OpenPhish
"""

import requests
import pandas as pd
import zipfile
import os
from datetime import datetime

def download_tranco_legitimate(num_urls=10000, output_file='data/legitimate_urls.csv'):
    """
    Download legitimate URLs from Tranco Top 1M list
    
    Args:
        num_urls: Number of URLs to download (default 10,000)
        output_file: Where to save the CSV
    """
    print("\n" + "="*70)
    print(f"  DOWNLOADING {num_urls:,} LEGITIMATE URLs FROM TRANCO")
    print("="*70 + "\n")
    
    url = "https://tranco-list.eu/top-1m.csv.zip"
    
    try:
        print(f"Downloading from: {url}")
        print("This may take a few minutes...\n")
        
        # Download zip file
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        
        # Save temporarily
        zip_path = "data/tranco_temp.zip"
        os.makedirs("data", exist_ok=True)
        
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        print("✓ Downloaded successfully")
        print("Extracting...\n")
        
        # Extract zip
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("data")
        
        # Read CSV
        csv_path = "data/top-1m.csv"
        df = pd.read_csv(csv_path, names=['rank', 'domain'], nrows=num_urls)
        
        # Format as URLs with https
        df['url'] = 'https://' + df['domain']
        df['label'] = 0  # Legitimate
        
        # Save
        result_df = df[['url', 'label']]
        result_df.to_csv(output_file, index=False)
        
        # Cleanup
        os.remove(zip_path)
        os.remove(csv_path)
        
        print("="*70)
        print(f"  ✅ SUCCESS!")
        print("="*70)
        print(f"Downloaded: {len(result_df):,} legitimate URLs")
        print(f"Saved to: {output_file}")
        print("="*70 + "\n")
        
        return result_df
        
    except Exception as e:
        print(f"\n❌ ERROR: Failed to download Tranco data")
        print(f"   {str(e)}\n")
        return None

def download_phishtank_phishing(num_urls=5000, output_file='data/phishing_urls_phishtank.csv'):
    """
    Download phishing URLs from PhishTank
    
    Args:
        num_urls: Number of URLs to download (default 5,000)
        output_file: Where to save the CSV
    """
    print("\n" + "="*70)
    print(f"  DOWNLOADING PHISHING URLs FROM PHISHTANK")
    print("="*70 + "\n")
    
    url = "http://data.phishtank.com/data/online-valid.json"
    
    try:
        print(f"Downloading from: {url}")
        print("This may take a minute...\n")
        
        # Download JSON
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        
        print("✓ Downloaded successfully")
        print("Processing...\n")
        
        # Parse JSON
        data = response.json()
        
        # Extract URLs
        urls = []
        for entry in data[:num_urls]:
            phish_url = entry.get('url', '')
            if phish_url:
                urls.append(phish_url)
        
        # Create DataFrame
        df = pd.DataFrame({
            'url': urls,
            'label': 1  # Phishing
        })
        
        # Save
        os.makedirs("data", exist_ok=True)
        df.to_csv(output_file, index=False)
        
        print("="*70)
        print(f"  ✅ SUCCESS!")
        print("="*70)
        print(f"Downloaded: {len(df):,} phishing URLs")
        print(f"Saved to: {output_file}")
        print("="*70 + "\n")
        
        return df
        
    except Exception as e:
        print(f"\n❌ ERROR: Failed to download PhishTank data")
        print(f"   {str(e)}\n")
        return None

def download_openphish_phishing(num_urls=5000, output_file='data/phishing_urls_openphish.csv'):
    """
    Download phishing URLs from OpenPhish
    
    Args:
        num_urls: Number of URLs to download (default 5,000)
        output_file: Where to save the CSV
    """
    print("\n" + "="*70)
    print(f"  DOWNLOADING PHISHING URLs FROM OPENPHISH")
    print("="*70 + "\n")
    
    url = "https://openphish.com/feed.txt"
    
    try:
        print(f"Downloading from: {url}")
        print("This may take a minute...\n")
        
        # Download feed
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        
        print("✓ Downloaded successfully")
        print("Processing...\n")
        
        # Parse text file
        lines = response.text.strip().split('\n')
        urls = [line.strip() for line in lines if line.strip()][:num_urls]
        
        # Create DataFrame
        df = pd.DataFrame({
            'url': urls,
            'label': 1  # Phishing
        })
        
        # Save
        os.makedirs("data", exist_ok=True)
        df.to_csv(output_file, index=False)
        
        print("="*70)
        print(f"  ✅ SUCCESS!")
        print("="*70)
        print(f"Downloaded: {len(df):,} phishing URLs")
        print(f"Saved to: {output_file}")
        print("="*70 + "\n")
        
        return df
        
    except Exception as e:
        print(f"\n❌ ERROR: Failed to download OpenPhish data")
        print(f"   {str(e)}\n")
        return None

def combine_datasets(legit_file, phish_files, output_file='data/urls.csv'):
    """
    Combine legitimate and phishing datasets into one balanced file
    
    Args:
        legit_file: Path to legitimate URLs CSV
        phish_files: List of phishing URLs CSV files
        output_file: Final combined output file
    """
    print("\n" + "="*70)
    print("  COMBINING DATASETS")
    print("="*70 + "\n")
    
    try:
        # Load legitimate URLs
        print(f"Loading: {legit_file}")
        legit_df = pd.read_csv(legit_file)
        print(f"  ✓ Loaded {len(legit_df):,} legitimate URLs")
        
        # Load phishing URLs
        phish_dfs = []
        for phish_file in phish_files:
            if os.path.exists(phish_file):
                print(f"Loading: {phish_file}")
                df = pd.read_csv(phish_file)
                phish_dfs.append(df)
                print(f"  ✓ Loaded {len(df):,} phishing URLs")
        
        # Combine phishing datasets
        phish_df = pd.concat(phish_dfs, ignore_index=True)
        
        # Balance datasets (take minimum of both)
        min_size = min(len(legit_df), len(phish_df))
        
        print(f"\nBalancing datasets to {min_size:,} URLs each...")
        
        legit_df = legit_df.sample(n=min_size, random_state=42)
        phish_df = phish_df.sample(n=min_size, random_state=42)
        
        # Combine
        combined_df = pd.concat([legit_df, phish_df], ignore_index=True)
        
        # Shuffle
        combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Remove duplicates
        original_len = len(combined_df)
        combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
        duplicates = original_len - len(combined_df)
        
        if duplicates > 0:
            print(f"Removed {duplicates:,} duplicate URLs")
        
        # Save
        combined_df.to_csv(output_file, index=False)
        
        print("\n" + "="*70)
        print("  ✅ FINAL DATASET CREATED!")
        print("="*70)
        print(f"\nTotal URLs: {len(combined_df):,}")
        print(f"  Legitimate (0): {len(combined_df[combined_df['label']==0]):,}")
        print(f"  Phishing (1):   {len(combined_df[combined_df['label']==1]):,}")
        print(f"\nSaved to: {output_file}")
        print(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
        return combined_df
        
    except Exception as e:
        print(f"\n❌ ERROR: Failed to combine datasets")
        print(f"   {str(e)}\n")
        return None

def main():
    """Main download workflow"""
    print("\n" + "="*80)
    print("  AUTOMATED DATASET DOWNLOADER")
    print("  Downloads 10K Legitimate + 10K Phishing URLs")
    print("="*80)
    
    # Download legitimate URLs
    legit_df = download_tranco_legitimate(num_urls=10000)
    
    if legit_df is None:
        print("❌ Failed to download legitimate URLs")
        return
    
    # Download phishing URLs from PhishTank
    phishtank_df = download_phishtank_phishing(num_urls=5000)
    
    # Download phishing URLs from OpenPhish
    openphish_df = download_openphish_phishing(num_urls=5000)
    
    # Check if we got phishing URLs
    phish_files = []
    if phishtank_df is not None:
        phish_files.append('data/phishing_urls_phishtank.csv')
    if openphish_df is not None:
        phish_files.append('data/phishing_urls_openphish.csv')
    
    if not phish_files:
        print("❌ Failed to download any phishing URLs")
        return
    
    # Combine datasets
    final_df = combine_datasets(
        'data/legitimate_urls.csv',
        phish_files,
        'data/urls.csv'
    )
    
    if final_df is not None:
        print("\n✅ ALL DONE!")
        print("\nNext steps:")
        print("  1. Validate dataset: python validate_dataset_labels.py data/urls.csv 500")
        print("  2. Train models: python -m src.main")
        print("  3. Launch GUI: python -m src.gui")
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Download interrupted by user\n")
    except Exception as e:
        print(f"\n\n❌ Download failed: {e}\n")
        import traceback
        traceback.print_exc()
