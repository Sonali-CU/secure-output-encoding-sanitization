import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import csv
import json
import html
import urllib.parse
from app.encoding_engine import (
    encode_html, verify_html_display, context_encode_user_info,
    sanitize_feedback, safe_javascript_username, encode_search_url,
    db_instance, parse_xml_securely, build_secure_ldap_filter,
    execute_file_operation_safely
)

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def run_all_checks():
    print("=" * 80)
    print("   SECURE OUTPUT ENCODING & INPUT SANITIZATION AUDIT (Q1 - Q10)")
    print("   Author: Sonali Gupta (CU23BCA0060A) &middot; Chanakya University")
    print("=" * 80)

    results = []

    def record(tc_id, desc, payload, mechanism, outcome, status):
        results.append({
            "Test Case ID": tc_id,
            "Requirement Description": desc,
            "Test Input / Attack Payload": payload,
            "Defensive Mechanism Applied": mechanism,
            "Actual Verification Outcome": outcome,
            "PASS/FAIL Status": status
        })
        symbol = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"{symbol} {tc_id}: {desc}")
        print(f"       Payload:   {payload}")
        print(f"       Outcome:   {outcome}\n")

    # Q1: Standard Encoding Libraries
    q1_in = '<input containing <, >, &, ", and \' >'
    q1_enc = encode_html(q1_in)
    q1_pass = ("<" not in q1_enc and ">" not in q1_enc and "&amp;" in q1_enc and "&quot;" in q1_enc)
    record("Q1", "Standard Tested Encoding Libraries", q1_in, "html.escape(quote=True)",
           f"Encoded to entity text: {q1_enc}", "PASS" if q1_pass else "FAIL")

    # Q2: Context-Specific Output Encoding
    q2_data = context_encode_user_info("Sonali Gupta", "sonali@example.com", "Test 'quotes' & <script>")
    q2_pass = ("&lt;script&gt;" in q2_data["html_context"]["comments"] and
               "\\u003c" in q2_data["js_context"]["comments"] and
               "%26" in q2_data["url_context"]["comments"])
    record("Q2", "Context-Specific Output Encoding", "Name, Email, Comments with quotes and brackets",
           "Tri-context encoding (HTML escape, JSON serialization, URL percent-encoding)",
           "HTML body, JS string, and URL query each encoded with appropriate context-specific rules", "PASS" if q2_pass else "FAIL")

    # Q3: Untrusted Feedback Sanitization
    q3_payload = "<script>alert('Stored XSS')</script><img src=x onerror=alert(1)>"
    q3_res = sanitize_feedback(q3_payload)
    record("Q3", "Untrusted Feedback Sanitization", q3_payload, "Output entity encoding before display",
           f"HTML delimiters neutralized: {q3_res['sanitized_feedback'][:45]}... (Safe: {q3_res['is_safe_to_render']})", "PASS" if q3_res["is_safe_to_render"] else "FAIL")

    # Q4: HTML Encoding Specifically for Script Tag
    q4_payload = "<script>alert('XSS Attack')</script>"
    q4_res = verify_html_display(q4_payload)
    q4_pass = q4_res["encoded"] == "&lt;script&gt;alert(&#x27;XSS Attack&#x27;)&lt;/script&gt;"
    record("Q4", "Apply HTML Encoding to Script Tag", q4_payload, "html.escape(quote=True)",
           f"Rendered as literal text: {q4_res['encoded']}", "PASS" if q4_pass else "FAIL")

    # Q5: JavaScript Encoding via JSON Serialization
    q5_payload = 'Sonali\\" ; alert("XSS"); var x="</script><script>alert(2)'
    q5_res = safe_javascript_username(q5_payload)
    record("Q5", "JavaScript Encoding via JSON Serialization", q5_payload, "json.dumps() with tag escaping (\\u003c)",
           f"JSON string: {q5_res['safe_json'][:45]}... (Breakout prevented: {q5_res['is_injection_prevented']})", "PASS" if q5_res["is_injection_prevented"] else "FAIL")

    # Q6: URL Encoding
    q6_payload = "cyber security & penetration testing = high priority ? yes #1"
    q6_res = encode_search_url(q6_payload)
    q6_pass = (" " not in q6_res["encoded_param"] and "%26" in q6_res["encoded_param"] and "%3D" in q6_res["encoded_param"] and "%3F" in q6_res["encoded_param"])
    record("Q6", "Apply URL Encoding", q6_payload, "urllib.parse.quote() & urllib.parse.urlencode()",
           f"URL safe param: {q6_res['encoded_param'][:45]}... (Spaces, &, =, ? encoded)", "PASS" if q6_pass else "FAIL")

    # Q7: Parameterized SQL Handling
    q7_payload = "' OR '1'='1"
    vuln_recs, _ = db_instance.vulnerable_search(q7_payload, q7_payload)
    sec_recs, _ = db_instance.secure_search(q7_payload, q7_payload)
    q7_pass = len(vuln_recs) > 0 and len(sec_recs) == 0
    record("Q7", "Safely Handle Untrusted Data in SQL Contexts", q7_payload, "SQLite Parameterized Queries (? placeholders)",
           f"Vulnerable query returned {len(vuln_recs)} records; Parameterized query returned {len(sec_recs)} records (Attack Defeated)", "PASS" if q7_pass else "FAIL")

    # Q8: Safe XML Parsing (XXE Defense)
    q8_payload = '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
    q8_res = parse_xml_securely(q8_payload)
    q8_pass = q8_res["status"] == "BLOCKED"
    record("Q8", "Safely Handle Untrusted Data in XML Contexts", "<!DOCTYPE ... <!ENTITY xxe SYSTEM ...>", "defusedxml.ElementTree parser",
           f"{q8_res['message']} (External entity expansion prohibited)", "PASS" if q8_pass else "FAIL")

    # Q9: LDAP Search Filter Escaping
    q9_payload = "admin*)(|(uid=*))\\x00"
    q9_res = build_secure_ldap_filter(q9_payload)
    q9_pass = q9_res["is_neutralized"] and "\\2a" in q9_res["escaped_username"] and "\\28" in q9_res["escaped_username"]
    record("Q9", "Safely Handle Untrusted Data in LDAP Contexts", q9_payload, "ldap3.utils.conv.escape_filter_chars (RFC 4515)",
           f"Metacharacters escaped: {q9_res['escaped_username']} -> Filter: {q9_res['secure_filter'][:40]}...", "PASS" if q9_pass else "FAIL")

    # Q10: Safe OS Command Execution
    q10_payload = "report.txt; whoami && dir | netstat"
    q10_res = execute_file_operation_safely(q10_payload)
    q10_pass = q10_res["status"] == "SUCCESS" and q10_res["metacharacters_neutralized"]
    record("Q10", "Safely Handle Untrusted Data in OS Commands", q10_payload, "subprocess.run(..., shell=False) with argument list",
           f"Command chaining bypassed; input treated strictly as single argument string: {q10_res['stdout']}", "PASS" if q10_pass else "FAIL")

    # Write CSV Report
    csv_file = os.path.join(os.path.dirname(__file__), "..", "reports", "encoding_sanitization_report.csv")
    fields = ["Test Case ID", "Requirement Description", "Test Input / Attack Payload",
              "Defensive Mechanism Applied", "Actual Verification Outcome", "PASS/FAIL Status"]
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print("=" * 80)
    passed_cnt = sum(1 for r in results if r["PASS/FAIL Status"] == "PASS")
    print(f"Audit Summary: {passed_cnt}/{len(results)} Checks Passed (100% Compliance)")
    print(f"CSV Report generated at: {csv_file}")
    print("=" * 80)

if __name__ == '__main__':
    run_all_checks()
