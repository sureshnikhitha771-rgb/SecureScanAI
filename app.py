import streamlit as st
from scanner import scan_code
from ai_explainer import explain_findings

st.set_page_config(page_title="SecureScan AI", page_icon="🛡️", layout="wide")
st.title("🛡️ SecureScan AI")
st.subheader("LLM-Based Source Code Vulnerability Scanner")
st.write("Analyze C and Java source code for security issues and receive defensive explanations.")

# Add an API key field in the sidebar for the AI generation feature
api_key = st.sidebar.text_input("Enter Gemini API Key (Optional)", type="password", value="YOUR_API_KEY")

# Language support configuration panel
language = st.selectbox("Select programming language", ["C", "Java"])
source_option = st.radio("Choose input method:", ["Type/Paste Code", "Upload File"])

code = ""
if source_option == "Upload File":
    uploaded_file = st.file_uploader("Upload source code", type=["c", "java"])
    if uploaded_file is not None:
        code = uploaded_file.read().decode("utf-8")
else:
    # Setup interactive initial code templates
    if language == "C":
        default_text = """#include <stdio.h>
#include <string.h>

int main() {
    char username[30];
    printf("Enter username: ");
    gets(username);
    printf("Logged in as: %s\\n", username);
    return 0;
}"""
    else:
        default_text = """import java.sql.*;

public class UserAuth {
    public void login(Connection conn, String inputPass) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE pass = '" + inputPass + "'";
        ResultSet rs = stmt.executeQuery(sql);
    }
}"""
    code = st.text_area("Paste code here:", value=default_text, height=220)

if code:
    st.subheader("Source Code View")
    st.code(code, language=language.lower())

    if st.button("🔍 Scan Code", type="primary"):
        with st.spinner("Analyzing code safety features..."):
            # 1. Run the local static scanner rules
            findings = scan_code(code, language)
            
            if findings:
                st.error(f"⚠️ Detected {len(findings)} Potential Vulnerability Patterns")
                for item in findings:
                    st.markdown(f"*[{item['severity']}] {item['title']}*")
                    st.write(item['recommendation'])
                
                st.markdown("---")
                st.subheader("🤖 AI Remediation Report")
                
                # 2. Trigger the AVR explanation workflow
                report = explain_findings(code, language, findings, api_key)
                st.markdown(report)
            else:
                st.success("✅ Clean Check: No simple vulnerability signatures discovered.")