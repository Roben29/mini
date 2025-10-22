"""
Balanced Dataset Creator
========================
Combines malicious and legitimate URL datasets with perfect 50/50 balance.

Usage:
    python create_balanced_dataset.py malicious.csv legit.csv

Input Format:
    CSV files with 'url' column (label column optional)
    
Output:
    data/urls.csv with columns: url, label
    - label=0 for legitimate URLs
    - label=1 for phishing/malicious URLs
"""

import pandas as pd
import sys
import os
from datetime import datetime

def load_urls_from_csv(filepath, expected_label):
    """
    Load URLs from CSV file.
    
    Args:
        filepath: Path to CSV file
        expected_label: 0 for legitimate, 1 for malicious
        
    Returns:
        DataFrame with 'url' and 'label' columns
    """
    print(f"\n📂 Loading: {filepath}")
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Try to read CSV
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        raise Exception(f"Failed to read CSV: {e}")
    
    # Find URL column (flexible column names)
    url_col = None
    for col in df.columns:
        col_lower = col.lower().strip()
        if col_lower in ['url', 'urls', 'link', 'links', 'domain', 'website']:
            url_col = col
            break
    
    if url_col is None:
        # If no named column, assume first column is URLs
        url_col = df.columns[0]
        print(f"   ⚠ No 'url' column found, using first column: '{url_col}'")
    else:
        print(f"   ✓ Found URL column: '{url_col}'")
    
    # Extract URLs
    urls = df[url_col].dropna().astype(str).str.strip()
    
    # Remove empty URLs
    urls = urls[urls != '']
    
    # Remove duplicates
    original_count = len(urls)
    urls = urls.drop_duplicates()
    duplicates = original_count - len(urls)
    
    if duplicates > 0:
        print(f"   🧹 Removed {duplicates:,} duplicate URLs")
    
    # Create DataFrame with label
    result = pd.DataFrame({
        'url': urls.values,
        'label': expected_label
    })
    
    print(f"   ✓ Loaded {len(result):,} unique URLs (label={expected_label})")
    
    return result

def create_balanced_dataset(malicious_file, legit_file, output_file='data/urls.csv', balance_ratio=1.0):
    """
    Create perfectly balanced dataset from malicious and legitimate URL files.
    
    Args:
        malicious_file: Path to malicious URLs CSV
        legit_file: Path to legitimate URLs CSV
        output_file: Output path for balanced dataset
        balance_ratio: Ratio of malicious:legitimate (default 1.0 for 50/50)
    """
    print("\n" + "="*70)
    print("  BALANCED DATASET CREATOR")
    print("="*70)
    
    # Load malicious URLs (label=1)
    print("\n[Step 1/5] Loading malicious/phishing URLs...")
    malicious_df = load_urls_from_csv(malicious_file, expected_label=1)
    malicious_count = len(malicious_df)
    
    # Load legitimate URLs (label=0)
    print("\n[Step 2/5] Loading legitimate URLs...")
    legit_df = load_urls_from_csv(legit_file, expected_label=0)
    legit_count = len(legit_df)
    
    # Display initial counts
    print(f"\n📊 Initial Dataset Counts:")
    print(f"   Malicious/Phishing: {malicious_count:,}")
    print(f"   Legitimate/Safe:    {legit_count:,}")
    print(f"   Total:              {malicious_count + legit_count:,}")
    
    # Balance datasets - USE MAXIMUM POSSIBLE URLS
    print(f"\n[Step 3/5] Balancing datasets to {balance_ratio}:1 ratio...")
    print(f"   Strategy: Taking MAXIMUM URLs while maintaining perfect balance")
    
    if balance_ratio == 1.0:
        # Perfect 50/50 balance - USE THE SMALLER COUNT AS TARGET
        target_size = min(malicious_count, legit_count)
        print(f"   Target size per class: {target_size:,} URLs (MAXIMUM possible)")
        print(f"   Total dataset will be: {target_size * 2:,} URLs")
        
        # Sample to equal sizes
        if malicious_count > target_size:
            malicious_df = malicious_df.sample(n=target_size, random_state=42)
            print(f"   ✂ Sampled {target_size:,} from {malicious_count:,} malicious URLs")
        else:
            print(f"   ✓ Using all {malicious_count:,} malicious URLs")
        
        if legit_count > target_size:
            legit_df = legit_df.sample(n=target_size, random_state=42)
            print(f"   ✂ Sampled {target_size:,} from {legit_count:,} legitimate URLs")
        else:
            print(f"   ✓ Using all {legit_count:,} legitimate URLs")
    else:
        # Custom ratio
        malicious_target = int(min(malicious_count, legit_count * balance_ratio))
        legit_target = int(malicious_target / balance_ratio)
        
        malicious_df = malicious_df.sample(n=malicious_target, random_state=42)
        legit_df = legit_df.sample(n=legit_target, random_state=42)
        
        print(f"   ✂ Sampled {malicious_target:,} malicious, {legit_target:,} legitimate")
    
    # Combine datasets
    print(f"\n[Step 4/5] Combining datasets...")
    combined_df = pd.concat([malicious_df, legit_df], ignore_index=True)
    
    # Shuffle to mix malicious and legitimate
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"   🔀 Shuffled {len(combined_df):,} URLs")
    
    # Remove any cross-duplicates
    original_len = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
    removed = original_len - len(combined_df)
    
    if removed > 0:
        print(f"   🧹 Removed {removed:,} duplicate URLs between datasets")
    
    # Save to file
    print(f"\n[Step 5/5] Saving balanced dataset...")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    combined_df.to_csv(output_file, index=False)
    
    # Final statistics
    final_total = len(combined_df)
    final_malicious = len(combined_df[combined_df['label'] == 1])
    final_legit = len(combined_df[combined_df['label'] == 0])
    
    print("\n" + "="*70)
    print("  ✅ BALANCED DATASET CREATED!")
    print("="*70)
    print(f"\n📊 Final Dataset Statistics:")
    print(f"   Total URLs:         {final_total:,}")
    print(f"   Legitimate (0):     {final_legit:,} ({final_legit/final_total*100:.2f}%)")
    print(f"   Malicious (1):      {final_malicious:,} ({final_malicious/final_total*100:.2f}%)")
    
    if final_legit > 0 and final_malicious > 0:
        ratio = final_malicious / final_legit
        print(f"   Balance Ratio:      1:{ratio:.3f}")
        
        # Visual balance indicator
        legit_bar = '█' * int(final_legit / final_total * 50)
        mal_bar = '█' * int(final_malicious / final_total * 50)
        print(f"\n   Legitimate: {legit_bar}")
        print(f"   Malicious:  {mal_bar}")
        
        if abs(ratio - 1.0) < 0.05:
            print(f"\n   🎯 PERFECT BALANCE ACHIEVED!")
        elif abs(ratio - 1.0) < 0.1:
            print(f"\n   ✅ Excellent balance!")
    
    print(f"\n💾 Saved to: {output_file}")
    print(f"🕒 Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n" + "="*70)
    print("\n🚀 Next Steps:")
    print("   1. Train models: python -m src.main")
    print("   2. Or run: TRAIN_MODELS.bat")
    print("="*70 + "\n")

def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  BALANCED DATASET CREATOR")
    print("  Combines malicious + legitimate URLs with perfect 50/50 balance")
    print("="*70)
    
    # Check command line arguments
    if len(sys.argv) < 3:
        print("\n❌ ERROR: Missing required arguments\n")
        print("Usage:")
        print("   python create_balanced_dataset.py <malicious.csv> <legit.csv>")
        print("\nExample:")
        print("   python create_balanced_dataset.py phishing_urls.csv legitimate_urls.csv")
        print("\nInput CSV Format:")
        print("   - Must have a column named 'url' (or 'link', 'domain', etc.)")
        print("   - Each row should contain one URL")
        print("   - Optional: 'label' column (will be overwritten)")
        print("\nOutput:")
        print("   - Creates: data/urls.csv")
        print("   - Format: url,label")
        print("   - Labels: 0=legitimate, 1=malicious/phishing")
        print("\n" + "="*70 + "\n")
        sys.exit(1)
    
    malicious_file = sys.argv[1]
    legit_file = sys.argv[2]
    
    # Check if files exist
    if not os.path.exists(malicious_file):
        print(f"\n❌ ERROR: Malicious file not found: {malicious_file}\n")
        sys.exit(1)
    
    if not os.path.exists(legit_file):
        print(f"\n❌ ERROR: Legitimate file not found: {legit_file}\n")
        sys.exit(1)
    
    try:
        create_balanced_dataset(malicious_file, legit_file)
    except KeyboardInterrupt:
        print("\n\n⚠ Process interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
