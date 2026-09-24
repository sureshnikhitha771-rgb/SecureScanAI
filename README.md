# 🛡️ SecureScan AI (VRpilot Architecture Engine)

An *Agentic AI & Automated Vulnerability Repair (AVR)* framework designed to statically scan source code for structural hazards and execute an *Iterative Automated Patch Verification Loop* with compilers and memory safety sanitizers.

---

## 🚀 Key Innovation Highlights
* *Chain-of-Thought (CoT) Repair:* Avoids hasty single-pass generation by forcing the underlying Large Language Model to document vulnerability impacts and memory bounds before writing patches.
* *Autonomous Feedback System:* Bridges the gap between static analysis and operational execution by actively testing proposed code modifications against local sandbox compiler verification environments (gcc / javac).
* *Self-Correcting Execution Loops:* Automatically routes crash reports, compiler errors, and sanitizer exception outputs back into the context thread window to programmatically self-heal up to 3 diagnostic cycles.

---

## 📂 Repository Breakdown
* app.py: Streamlit-driven interactive visualization interface dashboard.
* scanner.py: Local multi-language static signature scanner optimization layers.
* ai_explainer.py: Core iterative repair feedback control pipeline running system validation.
* test_cases/: Contains vulnerable target code sequences (C Stack Overflows & Java Database Injections).

---

## 🛠️ Operational Setup & Execution

### 1. Prerequisite Installations
Ensure your local platform environment contains valid system installations of gcc and javac.

bash
pip install -r requirements.txt


### 2. Launching the Interface Dashboard
bash
streamlit run app.py
