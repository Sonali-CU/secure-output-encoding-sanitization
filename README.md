# Secure Output Encoding & Input Sanitization Suite

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/security-OWASP%20ASVS%20v4.0-orange.svg)](https://owasp.org/www-project-application-security-verification-standard/)
[![Tests Status](https://img.shields.io/badge/tests-10%2F10%20passed-brightgreen.svg)]()
[![Code Quality](https://img.shields.io/badge/compliance-100%25-success.svg)]()

> **Project Author:** Sonali Gupta  
> **Roll Number:** CU23BCA0060A  
> **Institution:** Department of Computer Applications, Chanakya University  
> **Course:** Secure Coding Practices (Assignment 3)  
> **Project Scope:** Implementation and Automated Verification of Defense-in-Depth Output Encoding and Context-Specific Sanitization Controls

---

## 1. Executive Summary

Modern web applications constantly process untrusted user input across diverse rendering contexts—such as HTML bodies, tag attributes, JavaScript runtime variables, URL query strings, database queries, XML documents, LDAP directories, and operating system execution shells. Failure to apply context-specific encoding and strict input validation introduces critical injection vulnerabilities, notably Cross-Site Scripting (XSS), SQL Injection (SQLi), XML External Entity (XXE) attacks, LDAP Injection, and Command Injection.

This repository provides an enterprise-grade reference implementation in Python that comprehensively implements, audits, and proves the efficacy of 10 defense-in-depth secure coding controls. The implementation demonstrates both vulnerable baselines and secure countermeasures, accompanied by an interactive Flask administrative dashboard, automated test suites (PyTest), and a compliance verification audit engine.

---

## 2. Architecture & Modules Overview

The framework is organized into modular components adhering to separation of concerns:

```
secure-output-encoding-sanitization/
├── app/
│   ├── __init__.py               # Flask application factory
│   ├── encoding_engine.py        # Core security engine implementing 10 defense controls
│   ├── routes.py                 # Blueprint routes serving demonstration UI & verification endpoints
│   ├── templates/                # Jinja2 presentation templates with secure context rendering
│   └── static/css/style.css      # Executive cybersecurity UI styling
├── tests/
│   └── test_all_encoding_tasks.py # PyTest automated verification suite (10 test modules)
├── scripts/
│   ├── run_audit_report.py       # Programmatic compliance audit script & CSV report generator
│   ├── capture_screenshots.py    # Automated headless browser verification capture script
│   └── build_assignment_pdf.py   # CDP-based PDF report compiler
├── reports/
│   └── encoding_sanitization_report.csv # Comprehensive audit evidence matrix
├── screenshots/                  # High-resolution verification captures
├── run.py                        # Standalone application entry point
└── requirements.txt              # Production and testing dependencies
```

---

## 3. Defense Controls Implemented

### Module 1: HTML Output Encoding (Q1)
- **Function:** `encode_html(user_input)`
- **Mechanism:** Escapes HTML metacharacters (`&`, `<`, `>`, `"`, `'`) using Python's `html.escape(quote=True)`.
- **Defense Target:** Stored and Reflected Cross-Site Scripting (XSS) in HTML body context.
- **Verification:** Converts `<script>alert('XSS')</script>` into inert text `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`.

### Module 2: Context-Aware Output Encoding (Q2)
- **Function:** `context_encode_user_info(name, role, site_url)`
- **Mechanism:** Differentiates encoding rules based on output location:
  - *HTML Body Context:* Standard HTML entity escaping.
  - *Tag Attribute Context:* Escapes quotes and structural characters for attribute injection prevention.
  - *JavaScript Variable Context:* Enforces JSON serialization (`json.dumps`) and cleans tag breakouts.
  - *URI / Link Context:* Strict URL-percent encoding (`urllib.parse.quote`).
- **Defense Target:** Context-breakout attacks where single-layer encoding fails.

### Module 3: Untrusted Feedback Sanitization (Q3)
- **Function:** `sanitize_feedback(feedback_text)`
- **Mechanism:** Strips/escapes HTML tags, sanitizes malicious event handlers (`onerror`, `onload`, `javascript:`), and validates structure.
- **Defense Target:** Persistent stored XSS in user review and feedback portals.

### Module 4: HTML Entity Verification & Safe Rendering (Q4)
- **Function:** `verify_html_display(test_string)`
- **Mechanism:** Validates that entities (`&quot;`, `&amp;`, `&#x27;`, `&lt;`, `&gt;`) render cleanly in the browser DOM as literal typographical marks without triggering script execution.

### Module 5: Safe JavaScript Variable Encoding (Q5)
- **Function:** `safe_javascript_username(username)`
- **Mechanism:** Uses strict JSON serialization (`json.dumps`) combined with proactive mitigation of script tag terminators (`</script>` -> `<\/script>`).
- **Defense Target:** DOM-based XSS and script-block breakout vulnerabilities.

### Module 6: URL Parameter Encoding (Q6)
- **Function:** `encode_search_url(base_url, query_term, category)`
- **Mechanism:** Compliant RFC 3986 parameter encoding via `urllib.parse.urlencode` with `quote_via=urllib.parse.quote`.
- **Defense Target:** Parameter injection, CRLF injection, and query-string truncation attacks.

### Module 7: Parameterized SQL Queries (Q7)
- **Class / Methods:** `DatabaseManager.secure_search(username, password)` vs `vulnerable_search`
- **Mechanism:** Enforces native database driver parameter binding (`?` placeholders) in SQLite.
- **Defense Target:** Authentication bypass via classic SQL Injection payloads (e.g., `' OR '1'='1`).

### Module 8: XML External Entity (XXE) Defense (Q8)
- **Function:** `parse_xml_securely(xml_string)`
- **Mechanism:** Uses `defusedxml.ElementTree` to parse untrusted XML structures, strictly forbidding DTD entity expansions, external network resolutions, and entity bombs.
- **Defense Target:** Local file disclosure (`file:///etc/passwd`, Windows `win.ini`), SSRF, and Billion Laughs DoS.

### Module 9: LDAP Search Filter Escaping (Q9)
- **Function:** `build_secure_ldap_filter(username)`
- **Mechanism:** Applies RFC 4515 character escaping using `ldap3.utils.conv.escape_filter_chars`, sanitizing asterisks, parentheses, backslashes, and null bytes.
- **Defense Target:** LDAP injection, directory enumeration, and authentication bypass (`*(|(objectClass=*))`).

### Module 10: Safe Operating System Command Execution (Q10)
- **Function:** `execute_file_operation_safely(command_name, target_path)`
- **Mechanism:** Whitelists allowed executable commands and passes arguments strictly as discrete array vectors via `subprocess.run(shell=False)`.
- **Defense Target:** Shell metacharacter command chaining (`&`, `|`, `;`, `` ` ``, `$()`).

---

## 4. Verification & Automated Test Results

The platform incorporates automated verification via PyTest and automated audit reporting.

### Automated Test Suite
```bash
python -m pytest -v tests/
```
**Results Summary:**
```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-8.3.4
collected 10 items

tests/test_all_encoding_tasks.py::test_q01_html_encoding_defense PASSED   [ 10%]
tests/test_all_encoding_tasks.py::test_q02_context_aware_encoding PASSED   [ 20%]
tests/test_all_encoding_tasks.py::test_q03_encode_untrusted_feedback PASSED [ 30%]
tests/test_all_encoding_tasks.py::test_q04_html_entity_rendering PASSED   [ 40%]
tests/test_all_encoding_tasks.py::test_q05_javascript_context_encoding PASSED [ 50%]
tests/test_all_encoding_tasks.py::test_q06_url_parameter_encoding PASSED  [ 60%]
tests/test_all_encoding_tasks.py::test_q07_safely_handle_untrusted_data_in_sql PASSED [ 70%]
tests/test_all_encoding_tasks.py::test_q08_xxe_defense_with_defusedxml PASSED [ 80%]
tests/test_all_encoding_tasks.py::test_q09_ldap_filter_escaping PASSED     [ 90%]
tests/test_all_encoding_tasks.py::test_q10_os_command_injection_defense PASSED [100%]

============================== 10 passed in 0.42s ==============================
```

### Audit Matrix (CSV Summary)
The automated audit generator (`scripts/run_audit_report.py`) executes end-to-end attack simulations across all 10 controls and outputs `reports/encoding_sanitization_report.csv`:

| ID | Control / Task Name | Test Payload / Scenario | Compliance Status | Defense Mechanism |
|---|---|---|---|---|
| Q01 | HTML Entity Encoding | `<script>alert('XSS')</script>` | **PASS** | Metacharacter HTML entity conversion |
| Q02 | Context-Aware Encoding | `"><script>alert(1)</script>` | **PASS** | HTML body, attribute, script & URI isolation |
| Q03 | Untrusted Feedback Sanitization | `<img src=x onerror=alert(1)>` | **PASS** | Tag & event-handler neutralization |
| Q04 | Entity Display Verification | `Testing 'single' & "double" quotes` | **PASS** | DOM literal character representation |
| Q05 | JavaScript Context Encoding | `Sonali"; alert('DOM XSS'); //` | **PASS** | Strict JSON serialization with script protection |
| Q06 | URL Query Parameter Encoding | `cyber & security = top priority / 2026` | **PASS** | RFC 3986 percent-encoding (`urllib.parse`) |
| Q07 | Parameterized SQL Queries | `' OR '1'='1' --` | **PASS** | Driver-level SQL placeholder binding (`?`) |
| Q08 | XXE Injection Defense | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM ...>]>` | **PASS** | `defusedxml` DTD expansion blocking |
| Q09 | LDAP Filter Escaping | `Sonali*)(uid=*))(|(uid=*` | **PASS** | RFC 4515 metacharacter escaping (`\2a\28...`) |
| Q10 | Safe OS Command Execution | `test_file.txt && dir` | **PASS** | Argument array execution with `shell=False` |

---

## 5. Security Principles & Standards

The implementation enforces the core recommendations of:
- **OWASP Proactive Controls:** C3 (Encode and Escape Data), C4 (Validate All Inputs), C5 (Parameterized Queries).
- **OWASP ASVS v4.0:** V5 (Validation, Sanitization, and Encoding Verification Requirements).
- **NIST SP 800-53 Rev. 5:** SI-10 (Information Input Validation).

---

## 6. Author Information

- **Student Name:** Sonali Gupta
- **Roll Number:** CU23BCA0060A
- **Degree Program:** Bachelor of Computer Applications (BCA)
- **Department:** Department of Computer Applications
- **University:** Chanakya University
- **Course:** Secure Coding Practices (Assignment 3)
- **Academic Year:** 2025–2026