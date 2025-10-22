import random
import csv

def balance_datasets():
    """Balance datasets to 10k legitimate and 10k phishing URLs"""
    
    print("Reading legitimate URLs...")
    # Read legitimate URLs (simple format: id,url)
    with open('data/legimate.csv', 'r', encoding='utf-8', errors='ignore') as f:
        legitimate_urls = f.readlines()
    
    print(f"Found {len(legitimate_urls)} legitimate URLs")
    
    print("Reading malicious URLs...")
    # Read malicious URLs (CSV format with header)
    with open('data/malicious.csv', 'r', encoding='utf-8', errors='ignore') as f:
        malicious_lines = f.readlines()
    
    print(f"Found {len(malicious_lines)} malicious lines (including header)")
    
    # Set random seed for reproducibility
    random.seed(42)
    
    # Sample 10k legitimate URLs
    if len(legitimate_urls) > 10000:
        sampled_legitimate = random.sample(legitimate_urls, 10000)
    else:
        sampled_legitimate = legitimate_urls
        print(f"Warning: Only {len(legitimate_urls)} legitimate URLs available")
    
    # Sample 10k malicious URLs (keep header)
    header = malicious_lines[0]
    malicious_data = malicious_lines[1:]
    
    if len(malicious_data) > 10000:
        sampled_malicious = random.sample(malicious_data, 10000)
    else:
        sampled_malicious = malicious_data
        print(f"Warning: Only {len(malicious_data)} malicious URLs available")
    
    # Write balanced legitimate dataset
    print("Writing balanced legitimate dataset...")
    with open('data/legimate.csv', 'w', encoding='utf-8') as f:
        f.writelines(sampled_legitimate)
    
    # Write balanced malicious dataset
    print("Writing balanced malicious dataset...")
    with open('data/malicious.csv', 'w', encoding='utf-8') as f:
        f.write(header)
        f.writelines(sampled_malicious)
    
    print(f"\n✓ Balanced dataset created successfully!")
    print(f"  - Legitimate URLs: {len(sampled_legitimate)}")
    print(f"  - Malicious URLs: {len(sampled_malicious)}")
    print(f"  - Total: {len(sampled_legitimate) + len(sampled_malicious)}")

if __name__ == "__main__":
    balance_datasets()
