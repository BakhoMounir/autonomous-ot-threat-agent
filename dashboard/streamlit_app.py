"""
Autonomous OT Threat Intelligence Agent - Streamlit Dashboard
Complete control panel for managing and monitoring the agent
"""

import streamlit as st
import json
import os
import sys
import time
from datetime import datetime, timezone
import pandas as pd
from pathlib import Path
# Fix import paths - Add agent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
agent_dir = os.path.join(parent_dir, 'agent')

# Add both parent and agent directories
for path in [parent_dir, agent_dir]:
    if path not in sys.path:
        sys.path.insert(0, path)
# Now import from agent
try:
    from agent.config import OUTPUT_FILE
except ImportError:
    # Fallback if running from different location
    OUTPUT_FILE = os.path.join(parent_dir, 'data', 'output_sample.json')

from agent.cve_fetcher import CVEFetcher
from agent.ot_filter import OTFilter
from agent.config import OUTPUT_FILE, DATA_DIR, FETCH_HOURS_BACK, MAX_CVES_PER_FETCH

# Page configuration
st.set_page_config(
    page_title="OT Threat Intelligence Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .threat-card {
        background-color: #f0f2f6;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
        margin: 1rem 0;
    }
    .stat-box {
        background-color: #e8f4f8;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
    }
    .critical { border-left-color: #ff0000; }
    .high { border-left-color: #ff4b4b; }
    .medium { border-left-color: #ffa500; }
    .low { border-left-color: #90ee90; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'agent_running' not in st.session_state:
    st.session_state.agent_running = False
if 'last_run_time' not in st.session_state:
    st.session_state.last_run_time = None
if 'run_history' not in st.session_state:
    st.session_state.run_history = []

# Helper Functions
def load_threats():
    """Load threats from output file"""
    try:
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r') as f:
                data = json.load(f)
                return data.get('ot_vulnerabilities', []), data.get('analysis_time', 'Unknown')
        return [], None
    except Exception as e:
        st.error(f"Error loading threats: {e}")
        return [], None

def get_severity_color(severity):
    """Get color based on severity"""
    severity_map = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'N/A': '⚪'
    }
    return severity_map.get(str(severity).upper(), '⚪')

def run_agent_once():
    """Run the agent pipeline once"""
    try:
        with st.spinner('🔄 Running threat intelligence agent...'):
            # Initialize components
            from agent.config import NVD_API_KEY
            fetcher = CVEFetcher(api_key=NVD_API_KEY)
            ot_filter = OTFilter()
            
            # Phase 1: Fetch CVEs
            st.info("📡 Phase 1: Fetching CVEs from NVD...")
            cves = fetcher.fetch_latest_cves(
                hours_back=FETCH_HOURS_BACK,
                max_results=MAX_CVES_PER_FETCH,
                incremental=True
            )
            
            if not cves:
                st.success("✅ No new CVEs found since last run!")
                return 0, 0
            
            st.info(f"Found {len(cves)} new CVEs")
            
            # Phase 2: Filter for OT relevance
            st.info("🧠 Phase 2: Analyzing for OT/ICS relevance...")
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            ot_threats = []
            for i, cve in enumerate(cves):
                status_text.text(f"Analyzing {cve['cve_id']} ({i+1}/{len(cves)})")
                progress_bar.progress((i + 1) / len(cves))
                
                # Check if OT-relevant
                if ot_filter.keyword_prefilter(cve):
                    analysis = ot_filter.analyzer.analyze_cve(cve)
                    if analysis.get('is_ot_relevant', False):
                        enhanced_cve = {
                            **cve,
                            'ai_insight': analysis.get('factory_impact', ''),
                            'analysis_reasoning': analysis.get('reasoning', '')
                        }
                        ot_threats.append(enhanced_cve)
            
            progress_bar.empty()
            status_text.empty()
            
            # Phase 3: Save results
            st.info("💾 Phase 3: Saving results...")
            ot_filter.save_filtered_output(ot_threats)
            
            # Mark as processed
            all_cve_ids = [cve['cve_id'] for cve in cves]
            fetcher.mark_as_processed(all_cve_ids)
            
            st.success(f"✅ Analysis complete! Found {len(ot_threats)} OT threats out of {len(cves)} CVEs")
            
            # Update session state
            st.session_state.last_run_time = datetime.now(timezone.utc)
            st.session_state.run_history.append({
                'time': st.session_state.last_run_time.isoformat(),
                'total_cves': len(cves),
                'ot_threats': len(ot_threats)
            })
            
            return len(cves), len(ot_threats)
            
    except Exception as e:
        st.error(f"❌ Error running agent: {e}")
        import traceback
        st.code(traceback.format_exc())
        return 0, 0

# Sidebar Navigation
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/000000/security-shield-green.png", width=100)
    st.title("🛡️ OT Threat Agent")
    
    page = st.radio(
        "Navigation",
        ["🏠 Dashboard", "🔍 Test Single CVE", "📊 All Results", "⚙️ Agent Control", "📈 Statistics"]
    )
    
    st.divider()
    
    # Quick stats
    threats, last_update = load_threats()
    st.metric("Active Threats", len(threats))
    if last_update:
        try:
            update_time = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
            st.caption(f"Last updated: {update_time.strftime('%Y-%m-%d %H:%M')}")
        except:
            st.caption(f"Last updated: {last_update}")
    
    st.divider()
    st.caption("ControlPoint AI Internship")
    st.caption("Autonomous OT Threat Intelligence")

# Main Content
if page == "🏠 Dashboard":
    st.markdown('<div class="main-header">🛡️ OT Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
    
    # Control buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔄 Run Agent Now", type="primary", use_container_width=True):
            total, ot = run_agent_once()
            st.rerun()
    
    with col2:
        if st.button("♻️ Refresh Data", use_container_width=True):
            st.rerun()
    
    with col3:
        auto_refresh = st.checkbox("Auto-refresh (30s)")
    
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    st.divider()
    
    # Load and display threats
    threats, last_update = load_threats()
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="stat-box">', unsafe_allow_html=True)
        st.metric("Total Threats", len(threats))
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        critical_count = sum(1 for t in threats if str(t.get('cvss_severity', '')).upper() == 'CRITICAL')
        st.markdown('<div class="stat-box">', unsafe_allow_html=True)
        st.metric("Critical", critical_count)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        high_count = sum(1 for t in threats if str(t.get('cvss_severity', '')).upper() == 'HIGH')
        st.markdown('<div class="stat-box">', unsafe_allow_html=True)
        st.metric("High", high_count)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        if last_update:
            try:
                update_time = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                time_ago = datetime.now(timezone.utc) - update_time
                st.markdown('<div class="stat-box">', unsafe_allow_html=True)
                st.metric("Last Update", f"{time_ago.seconds // 60}m ago")
                st.markdown('</div>', unsafe_allow_html=True)
            except:
                st.markdown('<div class="stat-box">', unsafe_allow_html=True)
                st.metric("Last Update", "Unknown")
                st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Display threats
    if threats:
        st.subheader("🚨 Active OT/ICS Threats")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH"]
            )
        
        with col2:
            search_term = st.text_input("🔍 Search CVE ID or description")
        
        # Filter threats
        filtered_threats = threats
        if severity_filter:
            filtered_threats = [t for t in filtered_threats if str(t.get('cvss_severity', '')).upper() in severity_filter]
        if search_term:
            filtered_threats = [t for t in filtered_threats 
                              if search_term.lower() in str(t.get('cve_id', '')).lower() 
                              or search_term.lower() in str(t.get('description', '')).lower()]
        
        st.caption(f"Showing {len(filtered_threats)} of {len(threats)} threats")
        
        # Display each threat
        for threat in filtered_threats:
            severity = str(threat.get('cvss_severity', 'N/A')).upper()
            severity_class = severity.lower()
            
            st.markdown(f'<div class="threat-card {severity_class}">', unsafe_allow_html=True)
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"### {get_severity_color(severity)} {threat.get('cve_id', 'Unknown')}")
            with col2:
                cvss = threat.get('cvss_score', 'N/A')
                st.markdown(f"**CVSS:** {cvss} ({severity})")
            
            st.markdown(f"**Description:** {threat.get('description', 'No description available')[:300]}...")
            
            if threat.get('ai_insight'):
                with st.expander("🤖 AI Analysis - Factory Impact"):
                    st.write(threat['ai_insight'])
            
            if threat.get('analysis_reasoning'):
                with st.expander("💡 Reasoning"):
                    st.write(threat['analysis_reasoning'])
            
            if threat.get('references'):
                with st.expander("🔗 References"):
                    for ref in threat['references'][:3]:
                        st.markdown(f"- [{ref}]({ref})")
            
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("✅ No active threats detected. Run the agent to scan for new vulnerabilities.")

elif page == "🔍 Test Single CVE":
    st.markdown('<div class="main-header">🔍 Test Single CVE</div>', unsafe_allow_html=True)
    st.write("Test the OT filtering logic with a custom CVE")
    
    with st.form("test_cve_form"):
        st.subheader("Enter CVE Details")
        
        cve_id = st.text_input("CVE ID", placeholder="CVE-2023-XXXXX")
        description = st.text_area(
            "Description",
            placeholder="Enter the vulnerability description...",
            height=150
        )
        
        col1, col2 = st.columns(2)
        with col1:
            cvss_score = st.number_input("CVSS Score", min_value=0.0, max_value=10.0, value=7.5, step=0.1)
        with col2:
            cvss_severity = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
        submitted = st.form_submit_button("🧪 Analyze CVE", type="primary", use_container_width=True)
    
    if submitted:
        if not cve_id or not description:
            st.error("Please fill in CVE ID and Description")
        else:
            test_cve = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cvss_severity': cvss_severity
            }
            
            with st.spinner("🔄 Analyzing CVE..."):
                try:
                    ot_filter = OTFilter()
                    
                    # Step 1: Keyword pre-filter
                    st.info("Step 1: Checking for OT keywords...")
                    keyword_match = ot_filter.keyword_prefilter(test_cve)
                    
                    if keyword_match:
                        st.success("✅ CVE contains OT-related keywords")
                        
                        # Step 2: LLM Analysis
                        st.info("Step 2: Running LLM analysis...")
                        analysis = ot_filter.analyzer.analyze_cve(test_cve)
                        
                        # Display results
                        st.divider()
                        st.subheader("📊 Analysis Results")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            is_ot = analysis.get('is_ot_relevant', False)
                            if is_ot:
                                st.success("✅ OT/ICS Relevant")
                            else:
                                st.warning("❌ Not OT/ICS Relevant")
                        
                        with col2:
                            st.metric("CVSS Score", f"{cvss_score} ({cvss_severity})")
                        
                        st.markdown("**Reasoning:**")
                        st.info(analysis.get('reasoning', 'No reasoning provided'))
                        
                        if analysis.get('factory_impact'):
                            st.markdown("**Factory Impact:**")
                            st.warning(analysis['factory_impact'])
                        
                    else:
                        st.warning("❌ No OT keywords found - CVE likely not relevant to industrial systems")
                        
                except Exception as e:
                    st.error(f"Analysis failed: {e}")
                    import traceback
                    st.code(traceback.format_exc())

elif page == "📊 All Results":
    st.markdown('<div class="main-header">📊 All Scan Results</div>', unsafe_allow_html=True)
    
    threats, last_update = load_threats()
    
    if threats:
        # Export options
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            if st.button("📥 Export to CSV"):
                df = pd.DataFrame(threats)
                csv = df.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    csv,
                    "ot_threats.csv",
                    "text/csv",
                    key='download-csv'
                )
        
        with col2:
            if st.button("📄 Export to JSON"):
                json_str = json.dumps(threats, indent=2)
                st.download_button(
                    "Download JSON",
                    json_str,
                    "ot_threats.json",
                    "application/json",
                    key='download-json'
                )
        
        st.divider()
        
        # Create DataFrame
        df_data = []
        for threat in threats:
            df_data.append({
                'CVE ID': threat.get('cve_id', 'N/A'),
                'CVSS': threat.get('cvss_score', 'N/A'),
                'Severity': threat.get('cvss_severity', 'N/A'),
                'Description': threat.get('description', '')[:100] + '...',
                'Published': threat.get('published_date', 'N/A')
            })
        
        df = pd.DataFrame(df_data)
        
        # Display table
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
                "CVSS": st.column_config.NumberColumn("CVSS", width="small"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Description": st.column_config.TextColumn("Description", width="large"),
            }
        )
        
        # Detailed view
        st.divider()
        st.subheader("Detailed View")
        selected_cve = st.selectbox("Select CVE for details", [t['cve_id'] for t in threats])
        
        if selected_cve:
            threat = next(t for t in threats if t['cve_id'] == selected_cve)
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**CVE ID:** {threat.get('cve_id')}")
                st.markdown(f"**CVSS Score:** {threat.get('cvss_score')}")
                st.markdown(f"**Severity:** {threat.get('cvss_severity')}")
            with col2:
                st.markdown(f"**Published:** {threat.get('published_date')}")
            
            st.markdown("**Description:**")
            st.write(threat.get('description', 'No description'))
            
            if threat.get('ai_insight'):
                st.markdown("**AI Factory Impact Analysis:**")
                st.info(threat['ai_insight'])
            
            if threat.get('analysis_reasoning'):
                st.markdown("**Analysis Reasoning:**")
                st.write(threat['analysis_reasoning'])
            
            if threat.get('references'):
                st.markdown("**References:**")
                for ref in threat['references']:
                    st.markdown(f"- [{ref}]({ref})")
    else:
        st.info("No threats found. Run the agent to scan for vulnerabilities.")

elif page == "⚙️ Agent Control":
    st.markdown('<div class="main-header">⚙️ Agent Control Panel</div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["▶️ Run Agent", "📜 Run History", "🗑️ Data Management"])
    
    with tab1:
        st.subheader("Manual Agent Execution")
        
        col1, col2 = st.columns(2)
        with col1:
            hours_back = st.number_input("Hours to look back", min_value=1, max_value=168, value=24)
        with col2:
            max_results = st.number_input("Max CVEs to fetch", min_value=10, max_value=500, value=100)
        
        incremental = st.checkbox("Incremental mode (skip processed CVEs)", value=True)
        
        if st.button("🚀 Run Agent", type="primary", use_container_width=True):
            total, ot = run_agent_once()
            st.success(f"Completed! Processed {total} CVEs, found {ot} OT threats")
    
    with tab2:
        st.subheader("Run History")
        if st.session_state.run_history:
            history_df = pd.DataFrame(st.session_state.run_history)
            st.dataframe(history_df, use_container_width=True)
        else:
            st.info("No run history yet")
    
    with tab3:
        st.subheader("Data Management")
        st.warning("⚠️ These actions will delete data permanently!")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗑️ Clear Processed CVEs", type="secondary"):
                processed_file = os.path.join(DATA_DIR, 'processed_cves.json')
                if os.path.exists(processed_file):
                    os.remove(processed_file)
                    st.success("Cleared processed CVEs list")
                    st.rerun()
        
        with col2:
            if st.button("🗑️ Clear All Results", type="secondary"):
                if os.path.exists(OUTPUT_FILE):
                    os.remove(OUTPUT_FILE)
                    st.success("Cleared all results")
                    st.rerun()

elif page == "📈 Statistics":
    st.markdown('<div class="main-header">📈 Threat Statistics</div>', unsafe_allow_html=True)
    
    threats, _ = load_threats()
    
    if threats:
        # Severity distribution
        st.subheader("Severity Distribution")
        severity_counts = {}
        for threat in threats:
            sev = str(threat.get('cvss_severity', 'Unknown')).upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔴 Critical", severity_counts.get('CRITICAL', 0))
        with col2:
            st.metric("🟠 High", severity_counts.get('HIGH', 0))
        with col3:
            st.metric("🟡 Medium", severity_counts.get('MEDIUM', 0))
        with col4:
            st.metric("🟢 Low", severity_counts.get('LOW', 0))
        
        # CVSS Score distribution
        st.divider()
        st.subheader("CVSS Score Distribution")
        
        cvss_scores = [t.get('cvss_score') for t in threats if isinstance(t.get('cvss_score'), (int, float))]
        if cvss_scores:
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots()
            ax.hist(cvss_scores, bins=10, color='#1f77b4', alpha=0.7)
            ax.set_xlabel('CVSS Score')
            ax.set_ylabel('Frequency')
            ax.set_title('CVSS Score Distribution')
            st.pyplot(fig)
        
        # Timeline
        st.divider()
        st.subheader("📅 Published Timeline")
        
        timeline_data = []
        for threat in threats:
            pub_date = threat.get('published_date', '')
            if pub_date:
                try:
                    date = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).date()
                    timeline_data.append(date)
                except:
                    pass
        
        if timeline_data:
            from collections import Counter
            date_counts = Counter(timeline_data)
            timeline_df = pd.DataFrame(list(date_counts.items()), columns=['Date', 'Count'])
            timeline_df = timeline_df.sort_values('Date')
            st.line_chart(timeline_df.set_index('Date'))
    else:
        st.info("No data available for statistics")

# Footer
st.divider()
st.caption("🛡️ Autonomous OT Threat Intelligence Agent | ControlPoint AI Internship Challenge | 2026")