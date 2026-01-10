import os

# API KEY
# NVD API Key 
NVD_API_KEY = os.getenv('NVD_API_KEY', 'c7f98472-d0ae-40cd-a9f7-3ef3c6917fe8')

# LLM CONFIGURATION

# We use Ollama for local LLM inference (no cloud, fully private)
LLM_PROVIDER = 'ollama'
LLM_MODELS = {
    'ollama': 'llama3.1'  
}

 
# OT/ICS KEYWORDS - Critical for pre-filtering
OT_KEYWORDS = [
    # Control Systems
    'SCADA', 'scada', 'Scada',
    'PLC', 'plc', 'Programmable Logic Controller',
    'HMI', 'hmi', 'Human Machine Interface',
    'DCS', 'dcs', 'Distributed Control System',
    'RTU', 'rtu', 'Remote Terminal Unit',
    'ICS', 'ics', 'Industrial Control System',
    
    # Major OT Vendors
    'Siemens', 'siemens', 'SIMATIC',
    'Rockwell', 'rockwell', 'Allen-Bradley', 'FactoryTalk',
    'Schneider', 'schneider', 'Modicon', 'Schneider Electric',
    'ABB', 'abb',
    'Honeywell', 'honeywell',
    'Emerson', 'emerson',
    'Yokogawa', 'yokogawa',
    'GE', 'General Electric', 'Proficy',
    'Mitsubishi', 'mitsubishi',
    'Omron', 'omron',
    
    # Industrial Protocols
    'Modbus', 'modbus', 'MODBUS',
    'DNP3', 'dnp3',
    'OPC', 'opc', 'OPC-UA', 'OPC UA',
    'BACnet', 'bacnet',
    'Profinet', 'profinet', 'PROFINET',
    'EtherNet/IP', 'ethernet/ip',
    'CIP', 'Common Industrial Protocol',
    
    # Industrial Terms
    'industrial', 'Industrial',
    'manufacturing', 'Manufacturing',
    'factory', 'Factory',
    'plant', 'Plant',
    'operational technology', 'Operational Technology',
    'critical infrastructure', 'Critical Infrastructure',
    'power grid', 'Power Grid',
    'water treatment', 'Water Treatment',
    'oil and gas', 'Oil and Gas',
    'energy sector', 'Energy Sector',
    'automation', 'Automation'
]

 
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
OUTPUT_FILE = os.path.join(DATA_DIR, 'output_sample.json')
LAST_RUN_FILE = os.path.join(DATA_DIR, 'last_run.json')

 
# FETCHER SETTINGS
FETCH_HOURS_BACK = 24  # Look back 24 hours for new CVEs
MAX_CVES_PER_FETCH = 100  # Maximum CVEs to process per run

 
# PROMPT TEMPLATE FOR LLM (Improved for better JSON responses)
OT_FILTER_PROMPT = """You are a cybersecurity expert specializing in Operational Technology (OT) and Industrial Control Systems (ICS).

Your task is to analyze the following CVE (Common Vulnerabilities and Exposures) and determine if it is relevant to OT/ICS environments.

**CVE Details:**
- CVE ID: {cve_id}
- Description: {description}
- CVSS Score: {cvss_score}
- Severity: {cvss_severity}

**OT/ICS Context:**
OT/ICS systems include:
- Control systems: SCADA, PLCs, HMIs, DCS, RTUs
- Industrial protocols: Modbus, DNP3, OPC-UA, Profinet, BACnet, EtherNet/IP
- Vendors: Siemens, Rockwell, Schneider Electric, ABB, Honeywell, Emerson, GE
- Critical infrastructure: power plants, water treatment, manufacturing, oil & gas, transportation

**Instructions:**
1. Determine if this CVE affects OT/ICS systems (true or false)
2. Provide a brief explanation (2-3 sentences) of your reasoning
3. If relevant, explain why this is dangerous for a factory or industrial plant (2-3 sentences)

**IMPORTANT:** You MUST respond with ONLY valid JSON. Use boolean values (true/false), not strings ("YES"/"NO").

**Response Format:**
{{
  "is_ot_relevant": true,
  "reasoning": "This CVE affects a Siemens SIMATIC PLC which is widely used in industrial automation...",
  "factory_impact": "An attacker could exploit this to disrupt production lines, cause equipment damage..."
}}

Remember:
- Use true/false (not "YES"/"NO")
- Keep reasoning concise (2-3 sentences)
- If not OT-relevant, set factory_impact to empty string ""
- Respond ONLY with valid JSON, no additional text or markdown"""

print("Configuration loaded successfully!")
print(f"LLM Provider: {LLM_PROVIDER}")
print(f"Model: {LLM_MODELS.get(LLM_PROVIDER, 'Not configured')}")
