import html
import json
import urllib.parse
import sqlite3
import subprocess
import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException, EntitiesForbidden
from ldap3.utils.conv import escape_filter_chars

# -----------------------------------------------------------------------------
# Q1 & Q4: Standard HTML Encoding (html.escape)
# -----------------------------------------------------------------------------
def encode_html(text: str) -> str:
    """
    Encodes <, >, &, ", and ' using Python's standard html.escape library.
    Ensures quotes are escaped (quote=True) to protect both element bodies
    and quoted HTML attributes.
    """
    if text is None:
        return ""
    return html.escape(text, quote=True)

def verify_html_display(malicious_payload: str) -> dict:
    encoded = encode_html(malicious_payload)
    return {
        "input": malicious_payload,
        "encoded": encoded,
        "is_script_neutralized": ("<script>" not in encoded and "</script>" not in encoded),
        "safe_html_sample": f"<p>{encoded}</p>"
    }

# -----------------------------------------------------------------------------
# Q2: Context-Specific Output Encoding
# -----------------------------------------------------------------------------
def context_encode_user_info(name: str, email: str, comments: str) -> dict:
    """
    Demonstrates why output encoding must be tailored to the specific sink context:
    1. HTML Body Context: Requires HTML entity encoding (html.escape).
    2. JavaScript Context: Requires JSON serialization (json.dumps) to escape quotes/newlines.
    3. URL Context: Requires URL percent-encoding (urllib.parse.quote).
    """
    # HTML Context
    html_name = html.escape(name, quote=True)
    html_email = html.escape(email, quote=True)
    html_comments = html.escape(comments, quote=True)

    # JavaScript Context (Safe JSON serialization)
    js_name = json.dumps(name).replace('<', '\\u003c').replace('>', '\\u003e')
    js_email = json.dumps(email).replace('<', '\\u003c').replace('>', '\\u003e')
    js_comments = json.dumps(comments).replace('<', '\\u003c').replace('>', '\\u003e')

    # URL Context
    url_name = urllib.parse.quote(name, safe='')
    url_email = urllib.parse.quote(email, safe='')
    url_comments = urllib.parse.quote(comments, safe='')

    # Demonstrating vulnerability when using mismatched encoding:
    # E.g., using HTML encoding inside a JavaScript string:
    mismatched_sample = f"var userName = '{html_name}';" # If name contains quotes or </script>, breaks!

    return {
        "raw": {"name": name, "email": email, "comments": comments},
        "html_context": {"name": html_name, "email": html_email, "comments": html_comments},
        "js_context": {"name": js_name, "email": js_email, "comments": js_comments},
        "url_context": {"name": url_name, "email": url_email, "comments": url_comments},
        "mismatched_sample": mismatched_sample
    }

# -----------------------------------------------------------------------------
# Q3: Untrusted Feedback Sanitization (XSS Mitigation)
# -----------------------------------------------------------------------------
def sanitize_feedback(feedback_text: str) -> dict:
    """
    Sanitizes untrusted feedback submitted by users before displaying on webpage.
    """
    clean_text = encode_html(feedback_text)
    # Safe to render because all HTML opening/closing delimiters (<, >) are entity-encoded
    is_safe = ("<" not in clean_text and ">" not in clean_text)
    return {
        "raw_feedback": feedback_text,
        "sanitized_feedback": clean_text,
        "is_safe_to_render": is_safe
    }

# -----------------------------------------------------------------------------
# Q5: JavaScript Encoding via JSON Serialization
# -----------------------------------------------------------------------------
def safe_javascript_username(username: str) -> dict:
    """
    Encodes username safely for embedding inside JavaScript using JSON serialization.
    Replaces '<' and '>' to prevent closing script tags (e.g. </script>).
    """
    safe_json = json.dumps(username).replace('<', '\\u003c').replace('>', '\\u003e')
    script_snippet = f"const currentUsername = {safe_json}; console.log('Welcome ' + currentUsername);"
    
    return {
        "raw_username": username,
        "safe_json": safe_json,
        "script_snippet": script_snippet,
        "is_injection_prevented": ("<script>" not in safe_json and "</script>" not in safe_json)
    }

# -----------------------------------------------------------------------------
# Q6: URL Encoding
# -----------------------------------------------------------------------------
def encode_search_url(keyword: str, base_url: str = "https://example.com/search") -> dict:
    """
    Encodes search parameters using urllib.parse.urlencode and urllib.parse.quote.
    """
    encoded_param = urllib.parse.quote(keyword, safe='')
    full_url = f"{base_url}?q={urllib.parse.quote_plus(keyword)}"
    query_dict = urllib.parse.urlencode({'q': keyword, 'ref': 'secure_search'})
    
    return {
        "raw_keyword": keyword,
        "encoded_param": encoded_param,
        "full_url": full_url,
        "query_string": query_dict
    }

# -----------------------------------------------------------------------------
# Q7: Parameterized SQL Handling (SQLite)
# -----------------------------------------------------------------------------
class SecureDatabase:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                full_name TEXT
            )
        """)
        cursor.execute("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                       ('sonali', 'SonaliSecure@2026!', 'Sonali Gupta'))
        cursor.execute("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                       ('admin', 'AdminSecretKey#999', 'System Administrator'))
        cursor.execute("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                       ('bob', 'BobPassword123', 'Bob Smith'))
        self.conn.commit()

    def vulnerable_search(self, username, password):
        # Vulnerable to SQL injection via string concatenation
        cursor = self.conn.cursor()
        query = f"SELECT id, username, full_name FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(query)
            return cursor.fetchall(), query
        except Exception as e:
            return [], str(e)

    def secure_search(self, username, password):
        # Secure parameterized query using ? placeholders
        cursor = self.conn.cursor()
        query = "SELECT id, username, full_name FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        return cursor.fetchall(), query

db_instance = SecureDatabase()

# -----------------------------------------------------------------------------
# Q8: Safe XML Parsing (XXE Prevention via defusedxml)
# -----------------------------------------------------------------------------
def parse_xml_securely(xml_data: str) -> dict:
    """
    Parses untrusted XML data using defusedxml.ElementTree, rejecting XML External Entities.
    """
    try:
        root = DefusedET.fromstring(xml_data)
        elements = {child.tag: child.text for child in root}
        return {
            "status": "SUCCESS",
            "message": "XML parsed successfully with XXE protections active.",
            "root_tag": root.tag,
            "data": elements
        }
    except (DefusedXmlException, EntitiesForbidden) as e:
        return {
            "status": "BLOCKED",
            "message": f"XXE Attack Neutralized: {type(e).__name__} - External entity expansion blocked.",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": "XML Syntax error or malformed input.",
            "error": str(e)
        }

# -----------------------------------------------------------------------------
# Q9: Safe LDAP Search Filter Escaping (RFC 4515)
# -----------------------------------------------------------------------------
def build_secure_ldap_filter(username: str) -> dict:
    """
    Constructs an LDAP search filter using ldap3.utils.conv.escape_filter_chars,
    escaping *, (, ), \, and null bytes per RFC 4515.
    """
    escaped_user = escape_filter_chars(username)
    secure_filter = f"(&(objectClass=user)(sAMAccountName={escaped_user}))"
    vulnerable_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
    
    # Check if dangerous characters were neutralized
    has_injection_risk = any(char in username for char in ['*', '(', ')', '\\', '\x00'])
    is_neutralized = not any(char in escaped_user for char in ['*', '(', ')'])
    
    return {
        "raw_username": username,
        "escaped_username": escaped_user,
        "secure_filter": secure_filter,
        "vulnerable_filter": vulnerable_filter,
        "has_injection_risk": has_injection_risk,
        "is_neutralized": is_neutralized
    }

# -----------------------------------------------------------------------------
# Q10: Safe OS Command Execution (subprocess.run with shell=False)
# -----------------------------------------------------------------------------
def execute_file_operation_safely(filename: str) -> dict:
    """
    Safely handles user input in OS commands using subprocess.run with an argument list
    and shell=False, preventing command chaining metacharacters (;, |, &, &&).
    """
    # Python script executed with argument list
    cmd = [
        "python", "-c",
        "import sys; print('PROCESSED_FILENAME=' + repr(sys.argv[1]))",
        filename
    ]
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5
        )
        return {
            "status": "SUCCESS",
            "filename_received": filename,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "metacharacters_neutralized": True
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e)
        }
