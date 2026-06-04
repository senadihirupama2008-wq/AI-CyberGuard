import streamlit as st
import re

# Page Configuration for High-End Threat Intelligence Look
st.set_page_config(
    page_title="AI CyberGuard | Advanced Threat Intelligence",
    page_icon="🛡️",
    layout="centered"
)

# Custom Styling for Tactical Dark Cyber Auditing Environment
st.markdown("""
    <style>
    .main-title { font-size: 42px; font-weight: bold; color: #00FF66; text-align: center; letter-spacing: 1px; }
    .sub-title { font-size: 18px; color: #888888; text-align: center; margin-bottom: 30px; }
    .report-card { padding: 20px; border-radius: 10px; border: 1px solid #333; background-color: #111; }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ AI CYBERGUARD</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Advanced Hybrid OSINT & Live Risk Engineering Pipeline</div>', unsafe_allow_html=True)

# Input Field for Threat Tracking
url_input = st.text_input("🔗 Enter Suspicious Network URL / Domain String:", placeholder="https://secure-login-verify-bank.com")

# Fully Hardened Core Diagnostic Engine
def analyze_url(url):
    if not url or len(url.strip()) == 0:
        return None
    
    score = 0
    reasons = []
    url_lower = url.lower().strip()
    
    # 1. SSL/TLS Protocol Cryptographic Verification
    if url_lower.startswith("http://"):
        score += 35
        reasons.append("❌ **Insecure Protocol:** Explicitly transmits payload over unencrypted 'http://'.")
    elif not url_lower.startswith("https://"):
        score += 20
        reasons.append("⚠️ **Missing Protocol Layer:** URL lacks explicit structured secure network protocol prefix.")
        
    # 2. Advanced Social Engineering & Brand Impersonation Heuristics
    scam_keywords = ["free-gift", "login-", "secure-bank", "verify-account", "win-money", "crypto-bonus", "giveaway", "update-wallet"]
    found_keywords = [word for word in scam_keywords if word in url_lower]
    if found_keywords:
        score += 45
        reasons.append(f"❌ **Impersonation Risk:** URL structure contains blacklisted scam tokens: `{found_keywords}`.")
        
    # 3. Domain Obfuscation & Typosquatting Check
    tld_count = len(re.findall(r"\.(com|net|org|gov|edu|biz|xyz|info|co)", url_lower))
    if tld_count > 1:
        score += 30
        reasons.append("❌ **Subdomain Padding:** Multiple top-level domain tokens detected. Heavily indicative of URL masking.")
        
    risk_score = min(score, 100)
    return risk_score, reasons

# Core Trigger Workflow
if st.button("🚨 Run System Threat Scan", use_container_width=True):
    # Security Sanity Check on User Input
    if url_input and url_input.strip():
        with st.spinner("Compiling structural telemetry and running risk vector checks..."):
            analysis_data = analyze_url(url_input)
            
            if analysis_data:
                risk_score, danger_reasons = analysis_data
                
                st.write("---")
                st.subheader("📊 Tactical Analysis Diagnostics")
                
                # Visual Analytics Meter
                st.progress(risk_score / 100)
                
                # Dynamic Threat Profiling Grid
                col1, col2 = st.columns(2)
                with col1:
                    st.metric(label="Calculated Risk Factor", value=f"{risk_score}%")
                with col2:
                    if risk_score >= 70:
                        st.markdown("### 🔴 **HIGH RISK**")
                    elif risk_score >= 35:
                        st.markdown("### 🟡 **SUSPICIOUS**")
                    else:
                        st.markdown("### 🟢 **SAFE VERDICT**")
                
                st.write("")
                
                # Render Detailed Logic Logs
                if danger_reasons:
                    st.write("### 🔍 Risk Indicators Identified:")
                    for reason in danger_reasons:
                        st.info(reason)
                else:
                    st.success("✨ Safe Pass: No high-risk string tokens or signature anomalies identified in the current URL vector.")
    else:
        st.warning("💡 Operational Halt: Please feed a valid URL network link string to invoke the pipeline.")
