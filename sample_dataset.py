"""
Sample Dataset for Production Training
=======================================
Reduces large dataset to manageable size for real security checks.

Takes balanced sample from full dataset for realistic training times.
"""

import pandas as pd
import os

def sample_dataset(input_file='data/urls.csv', output_file='data/urls_sampled.csv', sample_size=5000):
    """
    Sample balanced subset from large dataset
    
    Args:
        input_file: Path to full dataset
        output_file: Path to save sampled dataset
        sample_size: Total URLs to sample (will be split 50/50 between classes)
    """
    print("\n" + "="*70)
    print("  DATASET SAMPLING FOR PRODUCTION TRAINING")
    print("="*70 + "\n")
    
    # Load full dataset
    print(f"Loading full dataset from: {input_file}")
    df = pd.read_csv(input_file)
    
    total_urls = len(df)
    legit_count = len(df[df['label'] == 0])
    phish_count = len(df[df['label'] == 1])
    
    print(f"✓ Loaded {total_urls:,} URLs")
    print(f"  Legitimate: {legit_count:,}")
    print(f"  Phishing:   {phish_count:,}\n")
    
    # Calculate sample size per class
    per_class = sample_size // 2
    
    print(f"Sampling strategy:")
    print(f"  Target total: {sample_size:,} URLs")
    print(f"  Per class:    {per_class:,} URLs")
    print(f"  Balance:      50/50\n")
    
    # Sample from each class
    legit_sample = df[df['label'] == 0].sample(n=min(per_class, legit_count), random_state=42)
    phish_sample = df[df['label'] == 1].sample(n=min(per_class, phish_count), random_state=42)
    
    # Combine and shuffle
    sampled_df = pd.concat([legit_sample, phish_sample], ignore_index=True)
    sampled_df = sampled_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    sampled_df.to_csv(output_file, index=False)
    
    final_legit = len(sampled_df[sampled_df['label'] == 0])
    final_phish = len(sampled_df[sampled_df['label'] == 1])
    
    print("="*70)
    print("  ✅ SAMPLING COMPLETE")
    print("="*70)
    print(f"\nFinal sampled dataset:")
    print(f"  Total:        {len(sampled_df):,} URLs")
    print(f"  Legitimate:   {final_legit:,} ({final_legit/len(sampled_df)*100:.1f}%)")
    print(f"  Phishing:     {final_phish:,} ({final_phish/len(sampled_df)*100:.1f}%)")
    print(f"\nSaved to: {output_file}")
    
    # Estimate training time
    print(f"\n⏱️  Estimated feature extraction time:")
    print(f"  @ 2 seconds per URL = {len(sampled_df) * 2 / 60:.0f} minutes")
    print(f"  @ 3 seconds per URL = {len(sampled_df) * 3 / 60:.0f} minutes")
    print(f"  @ 5 seconds per URL = {len(sampled_df) * 5 / 60:.0f} minutes")
    
    print(f"\n{'='*70}")
    print(f"Reduction: {total_urls:,} → {len(sampled_df):,} URLs ({len(sampled_df)/total_urls*100:.1f}%)")
    print(f"{'='*70}\n")
    
    print("Next steps:")
    print("  1. Clean cache: python clean_project.py")
    print("  2. Train models: TRAIN_MODELS.bat")
    print(f"  3. The training will use: {output_file}\n")

if __name__ == "__main__":
    sample_dataset(
        input_file='data/urls.csv',
        output_file='data/urls_sampled.csv',
        sample_size=5000  # 2,500 legitimate + 2,500 phishing
    )
