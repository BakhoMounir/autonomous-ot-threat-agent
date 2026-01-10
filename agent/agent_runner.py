"""
Autonomous OT Threat Intelligence Agent - Main Runner
Orchestrates the entire CVE fetching, filtering, and analysis pipeline
"""

import os
import sys
import time
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cve_fetcher import CVEFetcher
from ot_filter import OTFilter
from config import OUTPUT_FILE, FETCH_HOURS_BACK, MAX_CVES_PER_FETCH


class AutonomousOTAgent:
    """
    Main orchestrator for the OT threat intelligence agent.
    Coordinates CVE fetching, filtering, and report generation.
    """
    
    def __init__(self):
        """Initialize the agent components"""
        print("\n" + "="*70)
        print("AUTONOMOUS OT THREAT INTELLIGENCE AGENT")
        print("ControlPoint AI Internship Challenge")
        print("="*70 + "\n")
        
        from config import NVD_API_KEY
        self.fetcher = CVEFetcher(api_key=NVD_API_KEY)

        self.filter = OTFilter()
        
    def run_once(self):
        """Execute one complete cycle of the agent"""
        start_time = time.time()
        
        print(f"🚀 Starting agent run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Phase 1: Fetch latest CVEs (INCREMENTAL MODE - only new ones!)
        print("📡 PHASE 1: Fetching CVEs from NVD...")
        print("-" * 70)
        cves = self.fetcher.fetch_latest_cves(
            hours_back=FETCH_HOURS_BACK,
            max_results=MAX_CVES_PER_FETCH,
            incremental=True  # Only fetch NEW CVEs
        )
        
        if not cves:
            print("✅ No NEW CVEs found since last run!")
            print("💤 Everything is up to date.\n")
            return
        
        print(f"✓ Found {len(cves)} NEW CVEs to analyze\n")
        
        # Phase 2: Filter for OT relevance
        print("🧠 PHASE 2: Filtering for OT/ICS relevance...")
        print("-" * 70)
        ot_threats = self.filter.process_cves(cves)
        
        # Phase 3: Generate report
        print("📊 PHASE 3: Generating threat report...")
        print("-" * 70)
        self.filter.save_filtered_output(ot_threats)
        
        # Mark ALL CVEs as processed (even non-OT ones, so we don't re-analyze them)
        all_cve_ids = [cve['cve_id'] for cve in cves]
        self.fetcher.mark_as_processed(all_cve_ids)
        
        # Summary
        elapsed_time = time.time() - start_time
        print("\n" + "="*70)
        print("AGENT RUN COMPLETE")
        print("="*70)
        print(f"⏱️  Time elapsed: {elapsed_time:.2f} seconds")
        print(f"📥 Total CVEs processed: {len(cves)}")
        print(f"🎯 OT threats identified: {len(ot_threats)}")
        print(f"📁 Report saved to: {OUTPUT_FILE}")
        
        if ot_threats:
            print("\n⚠️  CRITICAL OT THREATS DETECTED:")
            for threat in ot_threats[:5]:  # Show first 5
                print(f"   • {threat['cve_id']} (CVSS: {threat['cvss_score']}) - {threat['cvss_severity']}")
        else:
            print("\n✓ No critical OT threats detected in this run")
        
        print("="*70 + "\n")
        
    def run_continuous(self, interval_minutes=10):
        """Run the agent continuously at specified intervals"""
        print(f"🔄 Starting continuous mode (running every {interval_minutes} minutes)")
        print("Press Ctrl+C to stop\n")
        
        run_count = 0
        try:
            while True:
                run_count += 1
                print(f"\n{'='*70}")
                print(f"RUN #{run_count}")
                print(f"{'='*70}\n")
                
                self.run_once()
                
                # Wait for next run
                sleep_seconds = interval_minutes * 60
                print(f"\n⏳ Sleeping for {interval_minutes} minutes until next run...")
                print(f"Next run at: {datetime.fromtimestamp(time.time() + sleep_seconds).strftime('%Y-%m-%d %H:%M:%S')}\n")
                time.sleep(sleep_seconds)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Agent stopped by user")
            print(f"Total runs completed: {run_count}")
            print("Goodbye! 👋\n")


def main():
    """Main entry point with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Autonomous OT Threat Intelligence Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run once and exit
  python agent_runner.py
  
  # Run continuously every 10 minutes
  python agent_runner.py --continuous
  
  # Run continuously every 5 minutes
  python agent_runner.py --continuous --interval 5
        """
    )
    
    parser.add_argument(
        '--continuous', '-c',
        action='store_true',
        help='Run continuously at specified intervals'
    )
    
    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=10,
        help='Interval between runs in minutes (default: 10)'
    )
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = AutonomousOTAgent()
    
    # Run based on mode
    if args.continuous:
        agent.run_continuous(interval_minutes=args.interval)
    else:
        agent.run_once()


if __name__ == "__main__":
    main()