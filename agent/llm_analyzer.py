import json
import requests
from typing import Dict
from config import LLM_MODELS, OT_FILTER_PROMPT

class LLMAnalyzer:
    """
    LLM-based analyzer for determining if a CVE is OT/ICS-relevant.
    Uses Ollama local API only.
    """
    
    def __init__(self):
        """
        Initialize the LLM analyzer using Ollama local API.
        """
        self.provider = 'ollama'
        self.model = LLM_MODELS.get(self.provider)
        self.ollama_url = "http://localhost:11434/api/generate"
        print(f"LLM Analyzer initialized with {self.provider} ({self.model})")
        print("Ensure Ollama is running locally!")
    
    def analyze_cve(self, cve: Dict) -> Dict:
        """
        Analyze a CVE to determine if it's OT/ICS-relevant.
        """
        # Prepare the prompt
        prompt = OT_FILTER_PROMPT.format(
            cve_id=cve.get('cve_id', 'N/A'),
            description=cve.get('description', 'No description'),
            cvss_score=cve.get('cvss_score', 'N/A'),
            cvss_severity=cve.get('cvss_severity', 'N/A')
        )
        
        try:
            response_text = self._call_ollama(prompt)
            
            # Clean the response - remove markdown code blocks if present
            cleaned_response = response_text.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            
            # Parse JSON
            analysis = json.loads(cleaned_response)
            
            # Normalize the is_ot_relevant field to boolean
            if isinstance(analysis.get('is_ot_relevant'), str):
                analysis['is_ot_relevant'] = analysis['is_ot_relevant'].upper() in ['YES', 'TRUE', '1']
            
            return analysis
            
        except json.JSONDecodeError as e:
            cve_id = cve.get('cve_id', 'Unknown')
            print(f"JSON parsing error for {cve_id}: {e}")
            print(f"Raw response: {response_text[:200]}...")
            
            # Attempt manual parsing as fallback
            return self._manual_parse_response(response_text, cve_id)
            
        except Exception as e:
            cve_id = cve.get('cve_id', 'Unknown')
            print(f"Error analyzing {cve_id}: {e}")
            return self._default_response()
    
    def _manual_parse_response(self, text: str, cve_id: str) -> Dict:
        """
        Manually parse LLM response when JSON parsing fails.
        """
        try:
            # Safety check
            if not text or text is None:
                print(f"⚠️  Empty response for {cve_id}")
                return self._default_response()
            
            # Look for is_ot_relevant
            is_relevant = False
            if '"is_ot_relevant": YES' in text or '"is_ot_relevant": true' in text:
                is_relevant = True
            elif '"is_ot_relevant": NO' in text or '"is_ot_relevant": false' in text:
                is_relevant = False
            
            # Extract reasoning (between quotes after "reasoning":)
            reasoning = ""
            if '"reasoning":' in text:
                start = text.find('"reasoning":') + len('"reasoning":')
                text_after = text[start:].strip()
                if text_after.startswith('"'):
                    end = text_after.find('"', 1)
                    if end != -1:
                        reasoning = text_after[1:end]
            
            # Extract factory_impact
            factory_impact = ""
            if '"factory_impact":' in text:
                start = text.find('"factory_impact":') + len('"factory_impact":')
                text_after = text[start:].strip()
                if text_after.startswith('"'):
                    end = text_after.find('"', 1)
                    if end != -1:
                        factory_impact = text_after[1:end]
            
            print(f"✓ Manual parsing successful for {cve_id}")
            return {
                "is_ot_relevant": is_relevant,
                "reasoning": reasoning or "Could not extract reasoning",
                "factory_impact": factory_impact or ""
            }
        except Exception as e:
            print(f"Manual parsing also failed: {e}")
            return self._default_response()
        
    def _call_ollama(self, prompt: str) -> str:
        """
        Call local Ollama API to generate response.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.3,
            "format": "json"  # Request JSON format explicitly
        }
        response = requests.post(self.ollama_url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()['response']
    
    def _default_response(self) -> Dict:
        """Return default response when analysis fails"""
        return {
            "is_ot_relevant": False,
            "reasoning": "Analysis failed - could not determine relevance",
            "factory_impact": ""
        }


def test_analyzer():
    """Test function to verify LLM analyzer is working"""
    print("="*60)
    print("Testing LLM Analyzer with Ollama")
    print("="*60)
    
    test_cve = {
        "cve_id": "CVE-2023-TEST",
        "description": "A critical vulnerability in Siemens SIMATIC PLC allows remote code execution via Modbus protocol",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL"
    }
    
    try:
        analyzer = LLMAnalyzer()
        result = analyzer.analyze_cve(test_cve)
        
        print(f"\nTest CVE: {test_cve['cve_id']}")
        print(f"OT Relevant: {result['is_ot_relevant']}")
        print(f"Reasoning: {result['reasoning']}")
        print(f"Factory Impact: {result['factory_impact']}")
        print("\n✓ LLM Analyzer test passed!")
        
    except Exception as e:
        print(f"\n✗ LLM Analyzer test failed: {e}")
        print("Make sure Ollama is running locally and your model is available.")


if __name__ == "__main__":
    test_analyzer()