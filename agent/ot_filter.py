import json
from typing import List, Dict
from llm_analyzer import LLMAnalyzer  # fixed import
from config import OT_KEYWORDS, OUTPUT_FILE
from datetime import datetime, timezone


class OTFilter:
    """
    Filters CVEs to identify those relevant to OT/ICS environments.
    Uses a two-stage approach: keyword pre-filtering + LLM analysis.
    """
    
    def __init__(self):
        """Initialize the OT filter with LLM analyzer"""
        self.analyzer = LLMAnalyzer()
        self.ot_keywords = OT_KEYWORDS
    
    def keyword_prefilter(self, cve: Dict) -> bool:
        """
        Fast keyword-based pre-filter to reduce LLM API calls.
        Returns True if CVE description contains OT-related keywords.
        """
        description = cve.get('description', '').lower()
        return any(keyword.lower() in description for keyword in self.ot_keywords)
    
    def process_cves(self, cves: List[Dict]) -> List[Dict]:
        """
        Process a list of CVEs and filter for OT-relevance.
        """
        ot_relevant_cves = []
        print(f"\n{'='*60}")
        print(f"Processing {len(cves)} CVEs for OT relevance...")
        print(f"{'='*60}\n")
        
        for i, cve in enumerate(cves, 1):
            cve_id = cve.get('cve_id', 'Unknown')
            print(f"[{i}/{len(cves)}] Analyzing {cve_id}...")
            
            if not self.keyword_prefilter(cve):
                print(f"  ↳ Skipped (no OT keywords found)")
                continue
            
            print(f"  ↳ Potential OT match - analyzing with LLM...")
            analysis = self.analyzer.analyze_cve(cve)
            
            if analysis.get('is_ot_relevant', False):
                enhanced_cve = {
                    **cve,
                    'ai_insight': analysis.get('factory_impact', ''),
                    'analysis_reasoning': analysis.get('reasoning', '')
                }
                ot_relevant_cves.append(enhanced_cve)
                print(f"  ✓ OT relevant - added to report")
            else:
                print(f"  ✗ Not OT relevant")
        
        print(f"\n{'='*60}")
        print(f"Filtering complete: {len(ot_relevant_cves)}/{len(cves)} CVEs are OT-relevant")
        print(f"{'='*60}\n")
        return ot_relevant_cves
    
    def save_filtered_output(self, ot_cves: List[Dict]):
        """
        Save filtered OT CVEs to output file.
        """
        output = {
            'analysis_time': datetime.now(timezone.utc).isoformat(),
            'total_ot_threats': len(ot_cves),
            'ot_vulnerabilities': ot_cves
        }
        
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            print(f"✓ Saved {len(ot_cves)} OT threats to {OUTPUT_FILE}")
        except Exception as e:
            print(f"Error saving output: {e}")


def test_filter():
    """Test the OT filter with sample CVEs"""
    print("="*60)
    print("Testing OT Filter")
    print("="*60)
    
    test_cves = [
        {
            "cve_id": "CVE-2023-OT-001",
            "description": "Critical vulnerability in Siemens SIMATIC S7-1500 PLC allows remote attackers to execute arbitrary code via crafted Modbus TCP packets",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "published_date": "2023-12-01",
            "references": []
        },
        {
            "cve_id": "CVE-2023-IT-001",
            "description": "WordPress plugin XYZ version 1.2.3 has a SQL injection vulnerability allowing authentication bypass",
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "published_date": "2023-12-01",
            "references": []
        },
        {
            "cve_id": "CVE-2023-OT-002",
            "description": "Rockwell Automation FactoryTalk View HMI vulnerable to buffer overflow in DNP3 protocol handler",
            "cvss_score": 8.1,
            "cvss_severity": "HIGH",
            "published_date": "2023-12-01",
            "references": []
        }
    ]
    
    filter_engine = OTFilter()
    ot_results = filter_engine.process_cves(test_cves)
    
    print(f"\nResults: {len(ot_results)}/3 CVEs identified as OT-relevant")
    for cve in ot_results:
        print(f"\n{cve['cve_id']}:")
        print(f"  Impact: {cve.get('ai_insight', 'N/A')}")
    
    print("\n✓ Filter test completed!")


if __name__ == "__main__":
    test_filter()
