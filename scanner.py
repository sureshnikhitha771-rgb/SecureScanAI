import re
def scan_code(code, language):
    """
    Statically analyzes C and Java code templates for simple signature matches.
    Returns a list of finding dictionaries if issues are detected.
    """
    findings = []   
    if not code:
        return findings
    # --- RULE SET FOR C LANGUAGES ---
    if language == "C":
        if "gets(" in code:
            findings.append({
                "title": "Use of Obsolete and Dangerous Function 'gets()'",
                "severity": "CRITICAL",
                "recommendation": "Replace gets() with fgets() to prevent severe stack buffer overflows (CWE-120)."
            })          
    # --- RULE SET FOR JAVA LANGUAGES ---
    elif language == "Java":
        if "createStatement" in code and ("+" in code or "concat" in code):
            findings.append({
                "title": "SQL Injection via Dynamic String Concatenation",
                "severity": "HIGH",
                "recommendation": "Use PreparedStatement parameter bindings instead of concatenating variables into raw SQL (CWE-89)."
            })
            
        if "Runtime.getRuntime().exec(" in code or "ProcessBuilder" in code:
            # Simple heuristic check to see if an unvalidated variable might be passed
            findings.append({
                "title": "Potential OS Command Injection",
                "severity": "HIGH",
                "recommendation": "Ensure system process parameters are heavily whitelisted, strictly array-mapped, and isolated from shell interpretations (CWE-78)."
            })

    return findings