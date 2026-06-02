import streamlit as st
import re

# Page Configuration for High-End UX
st.set_page_config(
    page_title="AI CyberGuard | Advanced Threat Intelligence",
    page_icon="🛡️",
    layout="centered"
)

# Custom Styling to look like a Professional Cyber Security Tool
st.markdown("""
    <style>
    .main-title { font-size: 40px; font-weight: bold; color: #00FF66; text-align: center; }
    .sub-title { font-size: 18px; color: #CCCCCC; text-align: center; margin-bottom: 30px; }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ AI CyberGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Advanced Hybrid OSINT & Risk Analysis Tool</div>', unsafe_allow_html=True)

# Input Field for the User
url_input = st.text_input("🔗 Enter the suspicious URL / Link below to analyze:", placeholder="https://example-scam-site.com")

# Core Diagnostic Logic (Hybrid Rules Analysis)
def analyze_url(url):
    if not url:
        return None
    
    score = 0
    reasons = []
    
    # 1. Protocol Verification
    if url.startswith("http://"):
        score += 30
        reasons.append("❌ Insecure Protocol: Uses 'http://' instead of encrypted 'https://'.")
    elif not url.startswith("https://"):
        score += 15
        reasons.append("⚠️ Missing Protocol: The URL structure does not explicitly state a secure connection.")
        
    # 2. Deceptive Keywords Detection (Social Engineering Heuristics)
    scam_keywords = ["free-gift", "login-", "secure-bank", "verify-account", "win-money", "crypto-bonus", "giveaway"]
    found_keywords = [word for word in scam_keywords if word in url.lower()]
    if found_keywords:
        score += 40
        reasons.append(f"❌ Social Engineering Trigger: Detected high-risk deceptive phrases {found_keywords}.")
        
    # 3. Domain Manipulation Check (Typosquatting)
    if len(re.findall(r"\.(com|net|org|gov|edu)", url.lower())) > 1:
        score += 25
        reasons.append("❌ Subdomain Padding: URL contains multiple top-level domain extensions (common in masking fraud sites).")
        
    # Cap score at 100
    risk_score = min(score, 100)
    return risk_score, reasons

# Execution Trigger
if st.button("🚨 Run Security Scan", use_container_width=True):
    if url_input:
        with st.spinner("Analyzing URL architecture and matching threat signatures..."):
            result = analyze_url(url_input)
            
            if result:
                risk_score, danger_reasons = result
                
                st.subheader("📊 Diagnostic Summary")
                
                # Visual Dashboard output based on Severity Level
                if risk_score >= 70:
                    st.error(f"🔴 HIGH RISK VERDICT: {risk_score}% Phishing Probability")
                elif risk_score >= 30:
                    st.warning(f"🟡 SUSPICIOUS VERDICT: {risk_score}% Risk Level Detected")
                else:
                    st.success(f"🟢 LOW RISK VERDICT: {risk_score}% Risk Level (Appears Standard)")
                
                # Output dynamic insights
                if danger_reasons:
                    st.write("### 🔍 Risk Indicators Identified:")
                    for reason in danger_reasons:
                        st.write(reason)
                else:
                    st.write("✨ No immediate structural vulnerabilities or blacklisted keywords found in the URL token array.")
    else:
        st.info("💡 Please enter a valid URL network link string to execute the diagnostic pipeline.")