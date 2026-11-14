from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from .encoding_engine import (
    encode_html, verify_html_display, context_encode_user_info,
    sanitize_feedback, safe_javascript_username, encode_search_url,
    db_instance, parse_xml_securely, build_secure_ldap_filter,
    execute_file_operation_safely
)

main_bp = Blueprint('main', __name__)

# Stored feedback items in memory
feedback_storage = [
    {"author": "Sonali Gupta", "content": "The application architecture enforces strict output encoding.", "clean": True},
    {"author": "Alice", "content": "Great security controls implemented across all endpoints.", "clean": True}
]

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/html-encoding', methods=['GET', 'POST'])
def html_encoding():
    default_payload = "<script>alert('XSS Attack')</script>"
    payload = request.form.get('payload', default_payload) if request.method == 'POST' else default_payload
    result = verify_html_display(payload)
    return render_template('html_encoding.html', result=result)

@main_bp.route('/context-encoding', methods=['GET', 'POST'])
def context_encoding():
    name = request.form.get('name', 'Sonali Gupta')
    email = request.form.get('email', 'sonali@example.com')
    comments = request.form.get('comments', "Testing 'single' and \"double\" quotes and <script>")
    result = context_encode_user_info(name, email, comments)
    return render_template('context_encoding.html', result=result)

@main_bp.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        author = request.form.get('author', 'Anonymous').strip() or 'Anonymous'
        comment = request.form.get('comment', '')
        sanitized = sanitize_feedback(comment)
        feedback_storage.append({
            "author": encode_html(author),
            "content": sanitized["sanitized_feedback"],
            "raw": comment,
            "is_safe": sanitized["is_safe_to_render"]
        })
        return redirect(url_for('main.feedback'))
    return render_template('feedback.html', feedback_items=feedback_storage)

@main_bp.route('/js-welcome', methods=['GET', 'POST'])
def js_welcome():
    default_user = 'Sonali"; alert("Injected!"); var x="'
    username = request.form.get('username', default_user) if request.method == 'POST' else default_user
    result = safe_javascript_username(username)
    return render_template('js_welcome.html', result=result)

@main_bp.route('/search-url', methods=['GET', 'POST'])
def search_url():
    default_query = 'cyber security & penetration testing = high priority?'
    query = request.form.get('query', default_query) if request.method == 'POST' else default_query
    result = encode_search_url(query)
    return render_template('search_url.html', result=result)

@main_bp.route('/sql-auth', methods=['GET', 'POST'])
def sql_auth():
    username = request.form.get('username', "' OR '1'='1")
    password = request.form.get('password', "anything")
    
    # Run secure parameterized query
    sec_records, sec_query = db_instance.secure_search(username, password)
    
    # Run vulnerable concatenation query for demonstration
    vuln_records, vuln_query = db_instance.vulnerable_search(username, password)
    
    return render_template('sql_auth.html',
                           username=username, password=password,
                           sec_records=sec_records, sec_query=sec_query,
                           vuln_records=vuln_records, vuln_query=vuln_query)

@main_bp.route('/xml-parser', methods=['GET', 'POST'])
def xml_parser():
    default_xml = '''<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<note>
  <to>Sonali</to>
  <from>Admin</from>
  <heading>Security Advisory</heading>
  <body>&xxe;</body>
</note>'''
    xml_data = request.form.get('xml_data', default_xml) if request.method == 'POST' else default_xml
    result = parse_xml_securely(xml_data)
    return render_template('xml_parser.html', xml_data=xml_data, result=result)

@main_bp.route('/ldap-filter', methods=['GET', 'POST'])
def ldap_filter():
    default_user = "admin*)(|(uid=*))"
    username = request.form.get('username', default_user) if request.method == 'POST' else default_user
    result = build_secure_ldap_filter(username)
    return render_template('ldap_filter.html', result=result)

@main_bp.route('/cmd-exec', methods=['GET', 'POST'])
def cmd_exec():
    default_file = "report.txt; whoami & dir"
    filename = request.form.get('filename', default_file) if request.method == 'POST' else default_file
    result = execute_file_operation_safely(filename)
    return render_template('cmd_exec.html', result=result)

@main_bp.route('/api/audit-summary')
def api_audit_summary():
    return jsonify({
        "project": "secure-output-encoding-sanitization",
        "author": "Sonali Gupta",
        "student_uid": "CU23BCA0060A",
        "institution": "Chanakya University",
        "modules_implemented": 10,
        "status": "OPERATIONAL"
    })
