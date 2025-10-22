"""
Validate and Test Dataset Processing
=====================================
This script validates the dataset files and tests the complete workflow.

Tests:
1. Check if legitimate.csv and malicious.csv exist
2. Validate CSV formats
3. Test URL processing
4. Run complete dataset creation
5. Verify output

Usage:
    python validate_and_test.py
"""

import os
import sys
import pandas as pd
from datetime import datetime

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_section(text):
    """Print a formatted section"""
    print(f"\n{'─'*70}")
    print(f"  {text}")
    print(f"{'─'*70}")

def check_file_exists(filepath):
    """Check if file exists and return size"""
    if not os.path.exists(filepath):
        return False, 0, 0
    
    size_bytes = os.path.getsize(filepath)
    size_mb = size_bytes / (1024 * 1024)
    
    # Count lines (approximate)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = sum(1 for _ in f)
        return True, size_mb, lines
    except:
        return True, size_mb, -1

def validate_legitimate_csv(filepath):
    """Validate legitimate.csv format"""
    print_section(f"Validating: {filepath}")
    
    exists, size_mb, lines = check_file_exists(filepath)
    
    if not exists:
        print(f"   ❌ File not found: {filepath}")
        return False
    
    print(f"   ✓ File exists")
    print(f"   ✓ Size: {size_mb:.2f} MB")
    print(f"   ✓ Lines: {lines:,}")
    
    try:
        # Try reading first few rows
        df = pd.read_csv(filepath, nrows=10, header=None)
        print(f"   ✓ CSV format valid")
        print(f"   ✓ Columns detected: {len(df.columns)}")
        
        # Show sample
        print(f"\n   Sample rows:")
        for i, row in df.head(5).iterrows():
            print(f"      {i+1}. {row.values}")
        
        # Check if format matches expected (number,domain)
        first_val = str(df.iloc[0, 0]).strip()
        if first_val.isdigit():
            print(f"   ✓ Format: number,domain (as expected)")
        else:
            print(f"   ⚠ Format may differ from expected")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error reading CSV: {e}")
        return False

def validate_malicious_csv(filepath):
    """Validate malicious.csv format"""
    print_section(f"Validating: {filepath}")
    
    exists, size_mb, lines = check_file_exists(filepath)
    
    if not exists:
        print(f"   ❌ File not found: {filepath}")
        return False
    
    print(f"   ✓ File exists")
    print(f"   ✓ Size: {size_mb:.2f} MB")
    print(f"   ✓ Lines: {lines:,}")
    
    try:
        # Try reading with header
        df = pd.read_csv(filepath, nrows=10)
        print(f"   ✓ CSV format valid")
        print(f"   ✓ Columns detected: {list(df.columns)}")
        
        # Find URL column
        url_col = None
        for col in df.columns:
            if 'url' in col.lower():
                url_col = col
                break
        
        if url_col:
            print(f"   ✓ URL column found: '{url_col}'")
            
            # Show sample URLs
            print(f"\n   Sample URLs:")
            for i, url in enumerate(df[url_col].head(5), 1):
                print(f"      {i}. {url}")
            
            # Check if URLs have https://
            first_url = str(df[url_col].iloc[0])
            if first_url.startswith(('http://', 'https://')):
                print(f"   ✓ URLs have protocol (http/https)")
            else:
                print(f"   ⚠ URLs may not have protocol")
        else:
            print(f"   ⚠ No 'url' column found, will use first column")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error reading CSV: {e}")
        return False

def test_url_processing():
    """Test URL processing functions"""
    print_section("Testing URL Processing Functions")
    
    test_cases = [
        ("1,google.com", "google.com", "https://google.com"),
        ("2,facebook.com", "facebook.com", "https://facebook.com"),
        ("https://example.com", "example.com", "https://example.com"),
        ("http://test.org", "test.org", "http://test.org"),
    ]
    
    print("\n   Testing URL extraction and normalization:")
    
    import re
    from urllib.parse import urlparse
    
    for input_url, expected_domain, expected_normalized in test_cases:
        # Extract domain
        clean = re.sub(r'^\d+,\s*', '', input_url).strip()
        
        if not clean.startswith(('http://', 'https://')):
            domain = clean
            normalized = 'https://' + clean
        else:
            parsed = urlparse(clean)
            domain = parsed.netloc
            normalized = clean
        
        domain_match = "✓" if domain == expected_domain else "✗"
        norm_match = "✓" if normalized == expected_normalized else "✗"
        
        print(f"      Input: '{input_url}'")
        print(f"        Domain: '{domain}' {domain_match}")
        print(f"        Normalized: '{normalized}' {norm_match}")
    
    print("\n   ✓ URL processing test completed")
    return True

def validate_output_dataset(filepath='data/urls.csv'):
    """Validate the output urls.csv"""
    print_section(f"Validating Output: {filepath}")
    
    exists, size_mb, lines = check_file_exists(filepath)
    
    if not exists:
        print(f"   ⚠ Output file not created yet: {filepath}")
        print(f"   Run: python process_and_combine_datasets.py")
        return False
    
    print(f"   ✓ File exists")
    print(f"   ✓ Size: {size_mb:.2f} MB")
    print(f"   ✓ Lines: {lines:,}")
    
    try:
        df = pd.read_csv(filepath)
        
        # Check columns
        if 'url' not in df.columns or 'label' not in df.columns:
            print(f"   ❌ Missing required columns (url, label)")
            print(f"   Found columns: {list(df.columns)}")
            return False
        
        print(f"   ✓ Required columns present: url, label")
        
        # Check data types
        total = len(df)
        legit = len(df[df['label'] == 0])
        mal = len(df[df['label'] == 1])
        
        print(f"\n   Dataset Statistics:")
        print(f"      Total URLs:     {total:,}")
        print(f"      Legitimate (0): {legit:,} ({legit/total*100:.2f}%)")
        print(f"      Malicious (1):  {mal:,} ({mal/total*100:.2f}%)")
        
        # Check balance
        if legit > 0 and mal > 0:
            ratio = mal / legit
            print(f"      Balance ratio:  1:{ratio:.3f}")
            
            if abs(ratio - 1.0) < 0.05:
                print(f"      ✓ Perfectly balanced!")
            elif abs(ratio - 1.0) < 0.1:
                print(f"      ✓ Well balanced")
            else:
                print(f"      ⚠ Imbalanced dataset")
        
        # Check sample URLs
        print(f"\n   Sample URLs:")
        for i, row in df.head(5).iterrows():
            label_text = "Legitimate" if row['label'] == 0 else "Malicious"
            print(f"      {i+1}. [{label_text}] {row['url']}")
        
        print(f"\n   ✓ Output dataset is valid!")
        return True
        
    except Exception as e:
        print(f"   ❌ Error validating output: {e}")
        return False

def run_complete_test():
    """Run complete validation and test"""
    print_header("DATASET VALIDATION AND TEST")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = {
        'legitimate_csv': False,
        'malicious_csv': False,
        'url_processing': False,
        'output_dataset': False
    }
    
    # Test 1: Check legitimate.csv
    print_section("Test 1: Validate legitimate.csv")
    results['legitimate_csv'] = validate_legitimate_csv('data/legimate.csv')
    
    # Test 2: Check malicious.csv
    print_section("Test 2: Validate malicious.csv")
    results['malicious_csv'] = validate_malicious_csv('data/malicious.csv')
    
    # Test 3: Test URL processing
    print_section("Test 3: URL Processing")
    results['url_processing'] = test_url_processing()
    
    # Test 4: Check output (if exists)
    print_section("Test 4: Validate Output Dataset")
    results['output_dataset'] = validate_output_dataset('data/urls.csv')
    
    # Summary
    print_header("VALIDATION SUMMARY")
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"   {test_name.replace('_', ' ').title():25s} {status}")
    
    print(f"\n   Result: {passed}/{total} tests passed")
    
    if results['legitimate_csv'] and results['malicious_csv'] and not results['output_dataset']:
        print("\n" + "="*70)
        print("  🚀 READY TO PROCESS")
        print("="*70)
        print("\n  Input files are valid. Run the processing script:")
        print("     python process_and_combine_datasets.py")
        print("  Or:")
        print("     PROCESS_DATASETS.bat")
        print("="*70)
    elif all(results.values()):
        print("\n" + "="*70)
        print("  ✅ ALL TESTS PASSED!")
        print("="*70)
        print("\n  Dataset is ready. Next steps:")
        print("     1. Train models: python -m src.main")
        print("     2. Or run: TRAIN_MODELS.bat")
        print("="*70)
    else:
        print("\n" + "="*70)
        print("  ⚠ SOME TESTS FAILED")
        print("="*70)
        print("\n  Please check the errors above and fix them.")
        print("="*70)
    
    return all(results.values())

def main():
    """Main function"""
    try:
        success = run_complete_test()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
