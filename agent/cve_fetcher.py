import requests
import json
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional

# Define data folder relative to this script
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
os.makedirs(DATA_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(DATA_DIR, 'output_sample.json')
LAST_RUN_FILE = os.path.join(DATA_DIR, 'last_run.json')
PROCESSED_CVES_FILE = os.path.join(DATA_DIR, 'processed_cves.json')


class CVEFetcher:
    """
    CVE Fetcher for the Autonomous OT Threat Intelligence Agent.
    Responsible for retrieving recent CVEs from NVD and returning structured data.
    NOW WITH INCREMENTAL FETCHING - Only processes NEW CVEs!
    """

    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers['apiKey'] = api_key

    def get_last_fetch_time(self) -> Optional[datetime]:
        """Get the timestamp of the last successful fetch"""
        try:
            if os.path.exists(LAST_RUN_FILE):
                with open(LAST_RUN_FILE, 'r') as f:
                    data = json.load(f)
                    last_time = datetime.fromisoformat(data['last_fetch_time'].replace('Z', '+00:00'))
                    return last_time
        except Exception as e:
            print(f"Could not read last fetch time: {e}")
        return None

    def get_processed_cve_ids(self) -> set:
        """Get set of CVE IDs that have already been processed"""
        try:
            if os.path.exists(PROCESSED_CVES_FILE):
                with open(PROCESSED_CVES_FILE, 'r') as f:
                    data = json.load(f)
                    return set(data.get('processed_cve_ids', []))
        except Exception as e:
            print(f"Could not read processed CVEs: {e}")
        return set()

    def save_processed_cve_ids(self, cve_ids: set):
        """Save the list of processed CVE IDs"""
        try:
            with open(PROCESSED_CVES_FILE, 'w') as f:
                json.dump({
                    'processed_cve_ids': list(cve_ids),
                    'last_updated': datetime.now(timezone.utc).isoformat()
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving processed CVEs: {e}")

    def fetch_latest_cves(self, hours_back: int = 24, max_results: int = 100, incremental: bool = True) -> List[Dict]:
        """
        Fetch CVEs published in the last 'hours_back' hours.
        If incremental=True, only returns CVEs not previously processed.

        Args:
            hours_back: Lookback window in hours (used only for first run)
            max_results: Maximum number of CVEs to fetch
            incremental: If True, fetch only new CVEs since last run

        Returns:
            List of CVE dictionaries with key details
        """
        try:
            # Determine time window
            end_date = datetime.now(timezone.utc)
            
            if incremental:
                last_fetch = self.get_last_fetch_time()
                if last_fetch:
                    # Fetch CVEs since last run (with 5-minute overlap to avoid missing any)
                    start_date = last_fetch - timedelta(minutes=5)
                    print(f"📅 Incremental mode: Fetching CVEs since last run ({last_fetch.strftime('%Y-%m-%d %H:%M:%S')})")
                else:
                    # First run - fetch last 24 hours
                    start_date = end_date - timedelta(hours=hours_back)
                    print(f"📅 First run: Fetching CVEs from last {hours_back} hours")
            else:
                start_date = end_date - timedelta(hours=hours_back)
                print(f"📅 Full fetch mode: Fetching CVEs from last {hours_back} hours")

            pub_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            pub_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')

            params = {
                'pubStartDate': pub_start_date,
                'pubEndDate': pub_end_date,
                'resultsPerPage': max_results
            }

            print(f"Fetching CVEs from {pub_start_date} to {pub_end_date}...")

            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                print(f"Fetched {len(vulnerabilities)} CVEs from NVD")

                # Parse all CVEs
                parsed_cves = [self._parse_cve(vuln.get('cve', {})) for vuln in vulnerabilities]
                
                # Filter out already processed CVEs if in incremental mode
                if incremental:
                    processed_ids = self.get_processed_cve_ids()
                    new_cves = [cve for cve in parsed_cves if cve['cve_id'] not in processed_ids]
                    
                    if len(new_cves) < len(parsed_cves):
                        skipped = len(parsed_cves) - len(new_cves)
                        print(f"⏭️  Skipped {skipped} already-processed CVEs")
                    
                    print(f"✨ {len(new_cves)} NEW CVEs to analyze")
                    return new_cves
                
                return parsed_cves
            else:
                print(f"Error {response.status_code}: {response.text}")
                return []

        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return []

    def _parse_cve(self, cve_item: Dict) -> Dict:
        """
        Extract key fields from raw CVE data.
        """
        cve_id = cve_item.get('id', 'N/A')

        # English description
        descriptions = cve_item.get('descriptions', [])
        description = next(
            (desc['value'] for desc in descriptions if desc.get('lang') == 'en'),
            'No description provided'
        )

        # CVSS score
        metrics = cve_item.get('metrics', {})
        cvss_score = 'N/A'
        cvss_severity = 'N/A'

        for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if ver in metrics and metrics[ver]:
                cvss_data = metrics[ver][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 'N/A')
                cvss_severity = cvss_data.get('baseSeverity', 'N/A') if ver != 'cvssMetricV2' else 'N/A'
                break

        published = cve_item.get('published', 'N/A')

        references = [ref.get('url') for ref in cve_item.get('references', [])[:3]]

        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'cvss_severity': cvss_severity,
            'published_date': published,
            'references': references
        }

    def mark_as_processed(self, cve_ids: List[str]):
        """Mark CVE IDs as processed (add to tracking)"""
        processed = self.get_processed_cve_ids()
        processed.update(cve_ids)
        self.save_processed_cve_ids(processed)
        print(f"✓ Marked {len(cve_ids)} CVEs as processed")

    def save_output(self, cves: List[Dict]):
        """
        Save CVEs to output_sample.json and update last_run.json with timestamp
        """
        # Save actual CVE output
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    'analysis_time': datetime.now(timezone.utc).isoformat(),  # Changed from fetch_time
                    'total_ot_threats': len(cves),  # Changed from total_cves
                    'ot_vulnerabilities': cves  # Changed from cves
                }, f, indent=2, ensure_ascii=False)          
            print(f"Saved {len(cves)} CVEs to {OUTPUT_FILE}")
        except Exception as e:
            print(f"Error saving output file: {str(e)}")

        # Update last fetch time
        try:
            with open(LAST_RUN_FILE, 'w', encoding='utf-8') as f:
                json.dump({'last_fetch_time': datetime.now(timezone.utc).isoformat()}, f, indent=2)
            print(f"Updated last fetch timestamp in {LAST_RUN_FILE}")
        except Exception as e:
            print(f"Error updating last_run.json: {str(e)}")


def main():
    print("="*60)
    print("CVE Fetcher - Data Pipeline Phase")
    print("="*60)

    # Initialize fetcher (insert API key if you have one)
    from config import NVD_API_KEY
    fetcher = CVEFetcher(api_key=NVD_API_KEY)


    # Fetch with incremental mode (only new CVEs)
    cves = fetcher.fetch_latest_cves(hours_back=24, max_results=100, incremental=True)

    if cves:
        print(f"Total NEW CVEs to process: {len(cves)}")
        print("Sample CVE:")
        print(json.dumps(cves[0], indent=2))

        # Save to project data folder and update timestamp
        fetcher.save_output(cves)
        
        # Mark these CVEs as fetched (they'll be marked as processed after filtering)
        print(f"\n💡 These {len(cves)} CVEs will be analyzed for OT relevance...")
    else:
        print("✅ No new CVEs found since last run!")

    print("\nℹ️  Run agent_runner.py in continuous mode for automatic 10-minute checks.")


if __name__ == "__main__":
    main()