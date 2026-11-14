import os
import sys
import time
import threading
from werkzeug.serving import make_server
from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions

# Fix path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import create_app

base = r'C:\Users\DELL\Downloads\secure-output-encoding-sanitization'
screenshots_dir = os.path.join(base, 'screenshots')
os.makedirs(screenshots_dir, exist_ok=True)

class ServerThread(threading.Thread):
    def __init__(self, app, port=5058):
        super().__init__()
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.daemon = True

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

def capture_all():
    print("Starting Flask application on port 5058...")
    app = create_app()
    server = ServerThread(app, port=5058)
    server.start()
    time.sleep(1.5)

    base_url = "http://127.0.0.1:5058"

    edge_options = EdgeOptions()
    edge_options.add_argument('--headless=new')
    edge_options.add_argument('--window-size=1280,850')
    edge_options.add_argument('--disable-gpu')

    print("Initializing Edge headless browser...")
    driver = webdriver.Edge(options=edge_options)

    try:
        # 1. Main Dashboard
        print("Capturing 01_main_dashboard.png...")
        driver.get(f"{base_url}/")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '01_main_dashboard.png'))

        # 2. HTML Encoding (Q1 & Q4)
        print("Capturing 02_html_encoding_q1_q4.png...")
        driver.get(f"{base_url}/html-encoding")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '02_html_encoding_q1_q4.png'))

        # 3. Context Encoding (Q2)
        print("Capturing 03_context_encoding_q2.png...")
        driver.get(f"{base_url}/context-encoding")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '03_context_encoding_q2.png'))

        # 4. Untrusted Feedback (Q3)
        print("Capturing 04_feedback_xss_defense_q3.png...")
        driver.get(f"{base_url}/feedback")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '04_feedback_xss_defense_q3.png'))

        # 5. Parameterized SQL Login (Q7)
        print("Capturing 05_sql_parameterization_q7.png...")
        driver.get(f"{base_url}/sql-auth")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '05_sql_parameterization_q7.png'))

        # 6. XXE Defense (Q8)
        print("Capturing 06_xxe_defense_q8.png...")
        driver.get(f"{base_url}/xml-parser")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '06_xxe_defense_q8.png'))

        # 7. LDAP Filter Escaping (Q9)
        print("Capturing 07_ldap_filter_escaping_q9.png...")
        driver.get(f"{base_url}/ldap-filter")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '07_ldap_filter_escaping_q9.png'))

        # 8. OS Command Execution Defense (Q10)
        print("Capturing 08_os_command_injection_defense_q10.png...")
        driver.get(f"{base_url}/cmd-exec")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '08_os_command_injection_defense_q10.png'))

        print("All screenshots successfully captured!")
    finally:
        driver.quit()
        server.shutdown()

if __name__ == '__main__':
    capture_all()
