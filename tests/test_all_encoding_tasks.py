import html
import json
import urllib.parse
import sqlite3
import pytest
from app.encoding_engine import (
    encode_html, verify_html_display, context_encode_user_info,
    sanitize_feedback, safe_javascript_username, encode_search_url,
    db_instance, parse_xml_securely, build_secure_ldap_filter,
    execute_file_operation_safely
)

# --- Q1: Standard Tested Encoding Libraries ---
def test_q01_standard_tested_encoding_libraries():
    untrusted = '<div class="alert" id=\'test\'>User & Co: "100" > "50" & "20" < "30"</div>'
    encoded = encode_html(untrusted)
    
    # Must encode <, >, &, ", and '
    assert "<" not in encoded
    assert ">" not in encoded
    assert "&lt;div" in encoded
    assert "&amp;" in encoded
    assert "&quot;100&quot;" in encoded
    assert "&#x27;test&#x27;" in encoded or "&apos;test&apos;" in encoded

# --- Q2: Context-Specific Output Encoding ---
def test_q02_context_specific_output_encoding():
    name = "Sonali Gupta"
    email = "sonali@example.com"
    comments = "Safe comment & 'quotes' <script>"
    
    res = context_encode_user_info(name, email, comments)
    
    # HTML Context
    assert "&amp;" in res["html_context"]["comments"]
    assert "&lt;script&gt;" in res["html_context"]["comments"]
    
    # JavaScript Context (Safe JSON serialization)
    assert res["js_context"]["comments"].startswith('"')
    assert res["js_context"]["comments"].endswith('"')
    assert "\\u003c" in res["js_context"]["comments"]
    
    # URL Context
    assert "%26" in res["url_context"]["comments"]
    assert "%20" in res["url_context"]["comments"] or "+" in res["url_context"]["comments"]
    
    # Demonstrate mismatch vulnerability
    assert "var userName" in res["mismatched_sample"]

# --- Q3: Encode Untrusted Data Before Displaying (Feedback Portal) ---
def test_q03_encode_untrusted_feedback(client):
    malicious_feedback = "<script>alert('Stored XSS')</script><img src=x onerror=alert(1)>"
    res = sanitize_feedback(malicious_feedback)
    
    assert res["is_safe_to_render"] is True
    assert "<script>" not in res["sanitized_feedback"]
    assert "&lt;script&gt;" in res["sanitized_feedback"]
    
    # Verify through web route
    post_res = client.post('/feedback', data={'author': 'Sonali Gupta', 'comment': malicious_feedback}, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"&lt;script&gt;alert" in post_res.data
    assert b"<script>alert" not in post_res.data

# --- Q4: Apply HTML Encoding Specifically to Script Payload ---
def test_q04_apply_html_encoding_script_payload():
    payload = "<script>alert('XSS Attack')</script>"
    res = verify_html_display(payload)
    
    expected = "&lt;script&gt;alert(&#x27;XSS Attack&#x27;)&lt;/script&gt;"
    assert res["encoded"] == expected
    assert res["is_script_neutralized"] is True

# --- Q5: Apply JavaScript Encoding via JSON Serialization ---
def test_q05_apply_javascript_encoding_json_serialization():
    # Test payload containing quotes, backslashes, and script tag breakouts
    payload = 'Sonali\\" ; alert("XSS"); var x="</script><script>alert(2)'
    res = safe_javascript_username(payload)
    
    # Must use JSON serialization
    safe_str = res["safe_json"]
    assert safe_str.startswith('"')
    assert safe_str.endswith('"')
    # Script tag breakout neutralized
    assert "</script>" not in safe_str
    assert "\\u003c/script\\u003e" in safe_str or "<" not in safe_str
    assert res["is_injection_prevented"] is True

# --- Q6: Apply URL Encoding ---
def test_q06_apply_url_encoding():
    keyword = "cyber security & ethical hacking = top priority ? yes #1"
    res = encode_search_url(keyword)
    
    encoded = res["encoded_param"]
    # Verify spaces, &, =, ? are encoded
    assert " " not in encoded
    assert "%26" in encoded # &
    assert "%3D" in encoded # =
    assert "%3F" in encoded # ?
    assert "q=" in res["full_url"]

# --- Q7: Safely Handle Untrusted Data in SQL Contexts ---
def test_q07_safely_handle_untrusted_data_in_sql():
    sqli_payload = "' OR '1'='1"
    
    # 1. Vulnerable concatenation query returns records (Bypassed under injection)
    vuln_records, _ = db_instance.vulnerable_search(sqli_payload, sqli_payload)
    assert len(vuln_records) > 0, "Vulnerable query should return records under injection"
    
    # 2. Parameterized query safely treats input as literal string (Zero unauthorized records returned!)
    sec_records, _ = db_instance.secure_search(sqli_payload, sqli_payload)
    assert len(sec_records) == 0, "Parameterized query must return zero records for injection input"
    
    # Also verify with single-field injection
    sec_records_single, _ = db_instance.secure_search(sqli_payload, "arbitrary_pass")
    assert len(sec_records_single) == 0
    
    # Valid legitimate login still succeeds
    valid_records, _ = db_instance.secure_search('sonali', 'SonaliSecure@2026!')
    assert len(valid_records) == 1
    assert valid_records[0][1] == 'sonali'
    assert valid_records[0][2] == 'Sonali Gupta'

# --- Q8: Safely Handle Untrusted Data in XML Contexts (defusedxml) ---
def test_q08_safely_handle_untrusted_data_in_xml():
    xxe_payload = """<?xml version="1.0"?>
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
    ]>
    <data><payload>&xxe;</payload></data>
    """
    
    res = parse_xml_securely(xxe_payload)
    assert res["status"] == "BLOCKED"
    assert "XXE Attack Neutralized" in res["message"]
    
    # Legitimate safe XML passes
    safe_xml = "<note><author>Sonali</author><message>Secure XML</message></note>"
    safe_res = parse_xml_securely(safe_xml)
    assert safe_res["status"] == "SUCCESS"
    assert safe_res["data"]["author"] == "Sonali"

# --- Q9: Safely Handle Untrusted Data in LDAP Contexts (RFC 4515) ---
def test_q09_safely_handle_untrusted_data_in_ldap():
    # Test containing *, (, ), \, and null bytes
    malicious_ldap_user = "admin*)(|(uid=*))\x00"
    res = build_secure_ldap_filter(malicious_ldap_user)
    
    assert res["has_injection_risk"] is True
    assert res["is_neutralized"] is True
    
    # RFC 4515 escaping checks
    escaped = res["escaped_username"]
    assert "*" not in escaped # Escaped to \2a
    assert "(" not in escaped # Escaped to \28
    assert ")" not in escaped # Escaped to \29
    assert "\\2a" in escaped
    assert "\\28" in escaped
    assert "\\29" in escaped

# --- Q10: Safely Handle Untrusted Data in Operating-System Commands ---
def test_q10_safely_handle_untrusted_data_in_os_commands():
    # Injected filename with command separators
    injected_filename = "document.pdf; whoami && dir | netstat"
    res = execute_file_operation_safely(injected_filename)
    
    assert res["status"] == "SUCCESS"
    # Subprocess received the exact string as a single literal argument
    assert "PROCESSED_FILENAME='document.pdf; whoami && dir | netstat'" in res["stdout"]
    assert res["metacharacters_neutralized"] is True
