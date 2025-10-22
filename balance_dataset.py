"""
Balance Dataset Script
Creates a balanced dataset with 10k legitimate and 10k phishing URLs
"""
import csv
import random
from pathlib import Path

def balance_dataset():
    """Create balanced dataset with 10k legitimate and 10k phishing URLs"""
    
    # Set paths
    base_dir = Path(__file__).parent
    data_dir = base_dir / "data"
    
    legitimate_file = data_dir / "legimate.csv"
    malicious_file = data_dir / "malicious.csv"
    output_file = data_dir / "balanced_dataset.csv"
    
    print("=" * 60)
    print("BALANCING DATASET TO 10K LEGITIMATE + 10K PHISHING")
    print("=" * 60)
    
    # Read legitimate URLs
    print("\n[1/4] Reading legitimate URLs...")
    legitimate_urls = []
    with open(legitimate_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                legitimate_urls.append(row[1])  # Get URL from second column
    
    print(f"   ✓ Found {len(legitimate_urls):,} legitimate URLs")
    
    # Read malicious URLs
    print("\n[2/4] Reading malicious/phishing URLs...")
    malicious_urls = []
    with open(malicious_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if len(row) >= 2:
                malicious_urls.append(row[1])  # Get URL from second column
    
    print(f"   ✓ Found {len(malicious_urls):,} malicious/phishing URLs")
    
    # Sample 10k from each
    print("\n[3/4] Sampling 10,000 URLs from each category...")
    
    # Randomly sample 10k legitimate URLs
    if len(legitimate_urls) >= 10000:
        sampled_legitimate = random.sample(legitimate_urls, 10000)
    else:
        print(f"   ⚠ Warning: Only {len(legitimate_urls)} legitimate URLs available")
        sampled_legitimate = legitimate_urls
    
    # Randomly sample 10k malicious URLs
    if len(malicious_urls) >= 10000:
        sampled_malicious = random.sample(malicious_urls, 10000)
    else:
        print(f"   ⚠ Warning: Only {len(malicious_urls)} malicious URLs available")
        sampled_malicious = malicious_urls
    
    print(f"   ✓ Sampled {len(sampled_legitimate):,} legitimate URLs")
    print(f"   ✓ Sampled {len(sampled_malicious):,} malicious URLs")
    
    # Create balanced dataset
    print("\n[4/4] Creating balanced dataset...")
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        
        # Write legitimate URLs with label 0
        for url in sampled_legitimate:
            writer.writerow([url, 0])
        
        # Write malicious URLs with label 1
        for url in sampled_malicious:
            writer.writerow([url, 1])
    
    print(f"   ✓ Created balanced dataset: {output_file}")
    
    # Summary
    print("\n" + "=" * 60)
    print("DATASET BALANCING COMPLETE!")
    print("=" * 60)
    print(f"Output file: {output_file}")
    print(f"Total URLs: {len(sampled_legitimate) + len(sampled_malicious):,}")
    print(f"  - Legitimate (label=0): {len(sampled_legitimate):,}")
    print(f"  - Phishing (label=1): {len(sampled_malicious):,}")
    print("=" * 60)
    
    return output_file

if __name__ == "__main__":
    try:
        balance_dataset()
        print("\n✓ Success! Balanced dataset is ready for training.")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
