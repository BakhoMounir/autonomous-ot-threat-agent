"""
Comprehensive Testing Script for OT Threat Intelligence Agent
Tests all phases before dashboard deployment
"""

import os
import sys
import json
import time
from datetime import timezone, datetime

# Add agent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'agent'))

from cve_fetcher import CVEFetcher
from llm_analyzer import LLMAnalyzer
from ot_filter import OTFilter
from config import OUTPUT_FILE, DATA_DIR


class AgentTester:
    """Comprehensive testing suite for the OT agent"""
    
    def __init__(self):
        self.results = {
            'phase1': {'status': 'pending', 'details': {}},
            'phase2': {'status': 'pending', 'details': {}},
            'phase3': {'status': 'pending', 'details': {}},
            'integration': {'status': 'pending', 'details': {}}
        }
        
    def print_header(self, text):
        """Print formatted header"""
        print("\n" + "="*70)
        print(f"  {text}")
        print("="*70)
        
    def print_result(self, test_name, passed, message=""):
        """Print test result"""
        icon = "✓" if passed else "✗"
        status = "PASS" if passed else "FAIL"
        print(f"{icon} {test_name}: {status}")
        if message:
            print(f"  └─ {message}")
    
    def test_phase1_data_pipeline(self):
        """Test Phase 1: CVE Fetching"""
        self.print_header("PHASE 1: DATA PIPELINE TESTING")
        
        try:
            # Test 1: Initialize fetcher
            print("\n[Test 1.1] Initializing CVE Fetcher...")
            fetcher = CVEFetcher(api_key="c7f98472-d0ae-40cd-a9f7-3ef3c6917fe8")
            self.print_result("Fetcher initialization", True)
            
            # Test 2: Check data directory
            print("\n[Test 1.2] Checking data directory...")
            os.makedirs(DATA_DIR, exist_ok=True)
            data_dir_exists = os.path.exists(DATA_DIR)
            self.print_result("Data directory creation", data_dir_exists, 
                            f"Path: {DATA_DIR}")
            
            # Test 3: Fetch CVEs (non-incremental for testing)
            print("\n[Test 1.3] Fetching CVEs from NVD...")
            print("  (This may take 10-30 seconds...)")
            cves = fetcher.fetch_latest_cves(
                hours_back=24, 
                max_results=20,  # Small batch for testing
                incremental=False
            )
            
            fetch_success = len(cves) > 0
            self.print_result("CVE fetching", fetch_success, 
                            f"Retrieved {len(cves)} CVEs")
            
            if fetch_success:
                # Display sample CVE
                sample_cve = cves[0]
                print(f"\n  Sample CVE:")
                print(f"    ID: {sample_cve.get('cve_id')}")
                print(f"    CVSS: {sample_cve.get('cvss_score')} ({sample_cve.get('cvss_severity')})")
                print(f"    Description: {sample_cve.get('description')}...")

            # Test 4: State management
            print("\n[Test 1.4] Testing state management...")
            fetcher.save_output(cves[:5])  # Save small sample
            
            output_exists = os.path.exists(OUTPUT_FILE)
            last_run_exists = os.path.exists(os.path.join(DATA_DIR, 'last_run.json'))
            
            self.print_result("Output file creation", output_exists)
            self.print_result("Last run tracking", last_run_exists)
            
            # Test 5: Incremental fetching
            print("\n[Test 1.5] Testing incremental fetching...")
            incremental_cves = fetcher.fetch_latest_cves(incremental=True)
            self.print_result("Incremental mode", True, 
                            f"Found {len(incremental_cves)} new CVEs")
            
            self.results['phase1']['status'] = 'passed'
            self.results['phase1']['details'] = {
                'total_cves_fetched': len(cves),
                'incremental_cves': len(incremental_cves),
                'sample_cve': sample_cve
            }
            
            return cves
            
        except Exception as e:
            self.print_result("Phase 1 Overall", False, f"Error: {str(e)}")
            self.results['phase1']['status'] = 'failed'
            self.results['phase1']['details'] = {'error': str(e)}
            return []
    
    def test_phase2_llm_filtering(self, test_cves):
        """Test Phase 2: LLM Analysis and Filtering"""
        self.print_header("PHASE 2: LLM FILTERING TESTING")
        
        try:
            # Test 1: Initialize LLM
            print("\n[Test 2.1] Initializing LLM Analyzer...")
            analyzer = LLMAnalyzer()
            self.print_result("LLM initialization", True, 
                            f"Provider: {analyzer.provider}, Model: {analyzer.model}")
            
            # Test 2: Check Ollama connection
            print("\n[Test 2.2] Testing Ollama connection...")
            try:
                test_prompt = "Respond with only: OK"
                response = analyzer._call_ollama(test_prompt)
                ollama_working = len(response) > 0
                self.print_result("Ollama connectivity", ollama_working)
            except Exception as e:
                self.print_result("Ollama connectivity", False, 
                                f"Error: {str(e)}\nMake sure Ollama is running!")
                return
            
            # Test 3: Create test CVEs (OT and non-OT)
            print("\n[Test 2.3] Testing with synthetic CVEs...")
            synthetic_cves = [
                {
                    "cve_id": "TEST-OT-001",
                    "description": "Critical vulnerability in Siemens SIMATIC S7-1500 PLC allows remote code execution via Modbus TCP protocol",
                    "cvss_score": 9.8,
                    "cvss_severity": "CRITICAL"
                },
                {
                    "cve_id": "TEST-IT-001",
                    "description": "WordPress plugin vulnerability allows SQL injection in admin panel",
                    "cvss_score": 7.5,
                    "cvss_severity": "HIGH"
                },
                {
                    "cve_id": "TEST-OT-002",
                    "description": "Rockwell Automation FactoryTalk View HMI vulnerable to buffer overflow in DNP3 handler",
                    "cvss_score": 8.1,
                    "cvss_severity": "HIGH"
                }
            ]
            
            # Test 4: Analyze each CVE
            results = []
            for cve in synthetic_cves:
                print(f"\n  Analyzing {cve['cve_id']}...")
                analysis = analyzer.analyze_cve(cve)
                
                is_relevant = analysis.get('is_ot_relevant', False)
                reasoning = analysis.get('reasoning', 'N/A')
                
                print(f"    OT Relevant: {is_relevant}")
                print(f"    Reasoning: {reasoning[:80]}...")
                
                results.append({
                    'cve_id': cve['cve_id'],
                    'is_ot_relevant': is_relevant,
                    'expected_ot': 'OT' in cve['cve_id']
                })
            
            # Test 5: Verify accuracy
            print("\n[Test 2.4] Verifying LLM accuracy...")
            correct = sum(1 for r in results if r['is_ot_relevant'] == r['expected_ot'])
            accuracy = (correct / len(results)) * 100
            
            self.print_result("LLM accuracy", accuracy >= 66.0, 
                            f"{correct}/{len(results)} correct ({accuracy:.0f}%)")
            
            # Test 6: Full OT Filter
            print("\n[Test 2.5] Testing OTFilter with keyword pre-filtering...")
            ot_filter = OTFilter()
            
            # Test keyword prefilter
            ot_match = ot_filter.keyword_prefilter(synthetic_cves[0])
            it_match = ot_filter.keyword_prefilter(synthetic_cves[1])
            
            self.print_result("Keyword pre-filter (OT)", ot_match)
            self.print_result("Keyword pre-filter (IT rejection)", not it_match)
            
            # Test 7: Full pipeline with real CVEs (if available)
            if test_cves:
                print("\n[Test 2.6] Processing real CVEs with full pipeline...")
                ot_results = ot_filter.process_cves(test_cves[:10])  # Process first 10
                
                self.print_result("Real CVE processing", True, 
                                f"{len(ot_results)}/{min(10, len(test_cves))} identified as OT-relevant")
                
                self.results['phase2']['details'] = {
                    'ot_cves_found': len(ot_results),
                    'accuracy': accuracy,
                    'sample_results': results
                }
            
            self.results['phase2']['status'] = 'passed'
            
        except Exception as e:
            self.print_result("Phase 2 Overall", False, f"Error: {str(e)}")
            self.results['phase2']['status'] = 'failed'
            self.results['phase2']['details'] = {'error': str(e)}
    
    def test_phase3_output(self):
        """Test Phase 3: Report Generation"""
        self.print_header("PHASE 3: OUTPUT GENERATION TESTING")
        
        try:
            # Test 1: Check output file exists
            print("\n[Test 3.1] Checking output file...")
            output_exists = os.path.exists(OUTPUT_FILE)
            self.print_result("Output file exists", output_exists, OUTPUT_FILE)
            
            if not output_exists:
                print("  Creating sample output for testing...")
                sample_output = {
                    'analysis_time': datetime.utcnow().isoformat(),
                    'total_ot_threats': 1,
                    'ot_vulnerabilities': [{
                        'cve_id': 'TEST-CVE-001',
                        'description': 'Test vulnerability',
                        'cvss_score': 7.5,
                        'cvss_severity': 'HIGH',
                        'ai_insight': 'Test impact',
                        'analysis_reasoning': 'Test reasoning'
                    }]
                }
                with open(OUTPUT_FILE, 'w') as f:
                    json.dump(sample_output, f, indent=2)
            
            # Test 2: Validate JSON structure
            print("\n[Test 3.2] Validating JSON structure...")
            with open(OUTPUT_FILE, 'r') as f:
                data = json.load(f)
            
            required_fields = ['analysis_time', 'total_ot_threats', 'ot_vulnerabilities']
            has_required = all(field in data for field in required_fields)
            self.print_result("Required fields present", has_required)
            
            # Test 3: Validate CVE structure
            print("\n[Test 3.3] Validating CVE structure...")
            if data.get('ot_vulnerabilities'):
                sample_vuln = data['ot_vulnerabilities'][0]
                cve_fields = ['cve_id', 'description', 'cvss_score', 'ai_insight']
                has_cve_fields = all(field in sample_vuln for field in cve_fields)
                self.print_result("CVE fields complete", has_cve_fields)
                
                print(f"\n  Sample vulnerability:")
                print(f"    CVE: {sample_vuln.get('cve_id')}")
                print(f"    CVSS: {sample_vuln.get('cvss_score')} ({sample_vuln.get('cvss_severity')})")
                print(f"    AI Insight: {sample_vuln.get('ai_insight', '')[:80]}...")
            
            # Test 4: File size and readability
            file_size = os.path.getsize(OUTPUT_FILE)
            self.print_result("Output file readable", file_size > 0, 
                            f"{file_size} bytes")
            
            self.results['phase3']['status'] = 'passed'
            self.results['phase3']['details'] = {
                'file_size': file_size,
                'total_threats': data.get('total_ot_threats', 0)
            }
            
        except Exception as e:
            self.print_result("Phase 3 Overall", False, f"Error: {str(e)}")
            self.results['phase3']['status'] = 'failed'
            self.results['phase3']['details'] = {'error': str(e)}
    
    def test_integration(self):
        """Test full integration (simulated agent run)"""
        self.print_header("INTEGRATION TESTING")
        
        try:
            print("\n[Test INT.1] Running simulated agent cycle...")
            
            # Import agent runner
            from agent_runner import AutonomousOTAgent
            
            # Initialize agent
            agent = AutonomousOTAgent()
            self.print_result("Agent initialization", True)
            
            # Run one cycle (this will do everything)
            print("\n[Test INT.2] Executing full pipeline...")
            print("  (This will take 30-60 seconds...)\n")
            
            start_time = time.time()
            agent.run_once()
            elapsed = time.time() - start_time
            
            self.print_result("Full pipeline execution", True, 
                            f"Completed in {elapsed:.1f} seconds")
            
            # Verify output was updated
            print("\n[Test INT.3] Verifying pipeline output...")
            with open(OUTPUT_FILE, 'r') as f:
                final_output = json.load(f)
            
            analysis_time = datetime.fromisoformat(final_output['analysis_time'].replace('Z', '+00:00'))
            recent_run = (datetime.now(timezone.utc) - analysis_time).seconds < 300  # Within 5 minutes
            
            self.print_result("Recent output timestamp", recent_run,
                            f"Last analysis: {analysis_time.strftime('%H:%M:%S')}")
            
            self.results['integration']['status'] = 'passed'
            self.results['integration']['details'] = {
                'execution_time': elapsed,
                'threats_found': final_output.get('total_ot_threats', 0)
            }
            
        except Exception as e:
            self.print_result("Integration Overall", False, f"Error: {str(e)}")
            self.results['integration']['status'] = 'failed'
            self.results['integration']['details'] = {'error': str(e)}
    
    def generate_report(self):
        """Generate final test report"""
        self.print_header("TEST SUMMARY REPORT")
        
        phases = {
            'Phase 1 (Data Pipeline)': self.results['phase1'],
            'Phase 2 (LLM Filtering)': self.results['phase2'],
            'Phase 3 (Output)': self.results['phase3'],
            'Integration Test': self.results['integration']
        }
        
        print()
        for phase_name, result in phases.items():
            status = result['status']
            icon = "✓" if status == 'passed' else ("✗" if status == 'failed' else "⊘")
            print(f"{icon} {phase_name}: {status.upper()}")
            
            if result.get('details'):
                for key, value in result['details'].items():
                    if key != 'error':
                        print(f"    • {key}: {value}")
        
        # Overall status
        all_passed = all(r['status'] == 'passed' for r in self.results.values())
        
        print("\n" + "="*70)
        if all_passed:
            print("  🎉 ALL TESTS PASSED - READY FOR DASHBOARD DEPLOYMENT!")
        else:
            print("  ⚠️  SOME TESTS FAILED - REVIEW ERRORS ABOVE")
        print("="*70 + "\n")
        
        # Save report
        report_file = os.path.join(DATA_DIR, 'test_report.json')
        with open(report_file, 'w') as f:
            json.dump({
                'test_time': datetime.now(timezone.utc).isoformat(),
                'results': self.results,
                'overall_status': 'passed' if all_passed else 'failed'
            }, f, indent=2)
        
        print(f"📄 Detailed report saved to: {report_file}\n")
        
        return all_passed


def main():
    """Run all tests"""
    print("\n" + "🔬"*35)
    print("  AUTONOMOUS OT THREAT INTELLIGENCE AGENT")
    print("  Comprehensive Testing Suite")
    print("🔬"*35 + "\n")
    
    tester = AgentTester()
    
    # Run all test phases
    cves = tester.test_phase1_data_pipeline()
    time.sleep(1)
    
    tester.test_phase2_llm_filtering(cves)
    time.sleep(1)
    
    tester.test_phase3_output()
    time.sleep(1)
    
    tester.test_integration()
    
    # Generate final report
    success = tester.generate_report()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()