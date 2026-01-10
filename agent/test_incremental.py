#!/usr/bin/env python3
"""
Test script to verify incremental mode is working correctly
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cve_fetcher import CVEFetcher

def test_incremental_mode():
    """
    Test that incremental mode only fetches new CVEs
    """
    print("="*70)
    print("TESTING INCREMENTAL MODE")
    print("="*70 + "\n")
    
    fetcher = CVEFetcher(api_key="c7f98472-d0ae-40cd-a9f7-3ef3c6917fe8")
    
    # Test 1: First run (should fetch from last 24 hours)
    print("TEST 1: First Run (No tracking data)")
    print("-" * 70)
    cves_run1 = fetcher.fetch_latest_cves(hours_back=24, max_results=50, incremental=True)
    print(f"✓ Fetched {len(cves_run1)} CVEs on first run\n")
    
    if cves_run1:
        # Save fetch time
        fetcher.save_output(cves_run1)
        
        # Mark as processed
        cve_ids = [cve['cve_id'] for cve in cves_run1]
        fetcher.mark_as_processed(cve_ids)
        print(f"✓ Marked {len(cve_ids)} CVEs as processed\n")
    
    # Wait 2 seconds
    print("⏳ Waiting 2 seconds before second run...\n")
    time.sleep(2)
    
    # Test 2: Immediate second run (should find 0 or very few new CVEs)
    print("TEST 2: Second Run (Should skip already-processed CVEs)")
    print("-" * 70)
    cves_run2 = fetcher.fetch_latest_cves(hours_back=24, max_results=50, incremental=True)
    print(f"✓ Fetched {len(cves_run2)} NEW CVEs on second run\n")
    
    # Results
    print("="*70)
    print("TEST RESULTS")
    print("="*70)
    
    if len(cves_run2) < len(cves_run1):
        print("✅ PASS: Incremental mode is working!")
        print(f"   • First run:  {len(cves_run1)} CVEs analyzed")
        print(f"   • Second run: {len(cves_run2)} CVEs analyzed (only new ones)")
        print(f"   • Saved time: {len(cves_run1) - len(cves_run2)} CVEs not re-analyzed")
    elif len(cves_run2) == 0:
        print("✅ PERFECT: No new CVEs found (as expected)")
        print(f"   • First run:  {len(cves_run1)} CVEs analyzed")
        print(f"   • Second run: 0 CVEs (all already processed)")
    else:
        print("⚠️  WARNING: Unexpected result")
        print(f"   • First run:  {len(cves_run1)} CVEs")
        print(f"   • Second run: {len(cves_run2)} CVEs")
        print("   This might indicate new CVEs were published between runs")
    
    print("\n" + "="*70)
    print("How to reset for testing:")
    print("  rm data/processed_cves.json data/last_run.json")
    print("="*70 + "\n")


if __name__ == "__main__":
    test_incremental_mode()