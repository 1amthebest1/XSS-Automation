import requests
import sys
import asyncio
import base64
import urllib.parse
import html
import re
import warnings
import time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ANSI escape codes for coloring the output
RED = '\033[91m'
RESET = '\033[0m'

# Suppress SSL warnings from the requests library
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global flag for SSL warning
ssl_warning_shown = False

# Function to display SSL warning once
def show_ssl_warning():
    global ssl_warning_shown
    if not ssl_warning_shown:
        print(f"{RED}Warning: SSL certificate verification is disabled. This can expose you to security risks.{RESET}")
        ssl_warning_shown = True

# Function to decode payload based on encoding type
def decode_payload(payload, encoding):
    if encoding == "base64":
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return None
    elif encoding == "url":
        try:
            return urllib.parse.unquote(payload)
        except Exception:
            return None
    elif encoding == "html":
        try:
            return html.unescape(payload)
        except Exception:
            return None
    elif encoding == "none":
        return payload
    else:
        raise ValueError("Unsupported encoding type")

# Function to check if payload is reflected in HTML content
def is_payload_reflected(response_text, payload):
    soup = BeautifulSoup(response_text, 'html.parser')
    text = soup.get_text().lower()
    # Check if payload is reflected directly or as part of HTML attributes
    return payload.lower() in text or any(payload.lower() in tag.get('href', '').lower() for tag in soup.find_all())

# Function to perform additional checks
async def additional_check(url, injection_point, payload, http_method):
    print(f"Running additional checks for {url} with payload: {payload}")
    # Placeholder for additional check logic
    # Implement advanced response analysis or checks here

# Function to use Selenium for advanced XSS testing
def selenium_check(url, payload):
    options = Options()
    options.add_argument('--headless')  # Run in headless mode
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    try:
        driver.get(url)
        # Inject payload to dynamically check for alert box
        script = f"""
        var payload = `{payload}`;
        var scriptTag = document.createElement('script');
        scriptTag.text = `try {{ eval(payload); }} catch (e) {{ console.log("Error:", e); }} `;
        document.body.appendChild(scriptTag);
        """
        driver.execute_script(script)

        # Check for alert box
        alert_triggered = False
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"{RED}Alert box detected with text: {alert_text}{RESET}")
            alert.accept()
            alert_triggered = True
        except Exception as e:
            print(f"No alert detected: {e}")
        
        if alert_triggered:
            print(f"{RED}XSS VULNERABILITY FOUND (Selenium): {url}{RESET}")
        else:
            print(f"No XSS vulnerability found (Selenium) at {url} with payload: {payload}")
    finally:
        driver.quit()

# Function to analyze response for XSS
def analyze_response(response_text, payload):
    # Normalize content
    normalized_content = response_text.lower()

    # XSS detection patterns
    xss_patterns = [
        re.compile(r'<script\b[^>]*>([\s\S]*?)<\/script>', re.IGNORECASE),
        re.compile(r'<iframe\b[^>]*src=["\']?javascript:', re.IGNORECASE),
        re.compile(r'javascript:.*?(alert|prompt|confirm|eval|onerror|onload|innerhtml|document\.write|srcdoc)', re.IGNORECASE),
        re.compile(r'document\.cookie', re.IGNORECASE),
        re.compile(r'window\.location\=', re.IGNORECASE),
        re.compile(r'setTimeout\s*\(', re.IGNORECASE),
        re.compile(r'setInterval\s*\(', re.IGNORECASE),
        re.compile(r'function\s+\w+\s*\(', re.IGNORECASE),
        re.compile(r'\balert\s*\(', re.IGNORECASE),
        re.compile(r'\beval\s*\(', re.IGNORECASE),
        re.compile(r'<img\b[^>]*src=["\']?data:image', re.IGNORECASE),
        re.compile(r'<svg\b[^>]*onload\s*=', re.IGNORECASE),
        re.compile(r'<meta\b[^>]*http-equiv=["\']refresh', re.IGNORECASE),
        re.compile(r'base64,[^\'"<>]*?alert\(', re.IGNORECASE),
        re.compile(r'\bconsole\.log\b', re.IGNORECASE),
        re.compile(r'\beval\s*\(', re.IGNORECASE),
        re.compile(r'(<|%3C)script(>|%3E)', re.IGNORECASE),
        re.compile(r'(<|%3C)iframe(>|%3E)', re.IGNORECASE)
    ]

    # Check if content contains known XSS patterns
    return any(pattern.search(normalized_content) for pattern in xss_patterns)

# Function to test for XSS
async def test_xss(url, injection_point, payload, vuln_type, http_method, encoding):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
        "Custom-Header": "custom value"
    }
    cookies = {
        "session_id": "abcdef123456"
    }

    # Encode payload if needed
    if encoding == "base64":
        payload = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
    elif encoding == "url":
        payload = urllib.parse.quote(payload)
    elif encoding == "html":
        payload = html.escape(payload)

    try:
        # Parse URL and inject payload into the specified parameter
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if injection_point.startswith('?'):
            injection_point = injection_point[1:]
        
        query_params[injection_point] = [payload]
        new_query_string = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query_string))

        # Send request based on the method
        if http_method.lower() == "get":
            show_ssl_warning()
            r = requests.get(new_url, headers=headers, cookies=cookies, auth=("user", "pass"), verify=False)
        elif http_method.lower() == "post":
            show_ssl_warning()
            r = requests.post(new_url, headers=headers, cookies=cookies, auth=("user", "pass"), verify=False)

        # Check for XSS vulnerability, ignoring 403 status codes
        if r is not None:
            if r.status_code == 403:
                print(f"Request to {new_url} resulted in status code 403, skipping.")
                return

            content_type = r.headers.get('Content-Type', '')
            if 'html' in content_type.lower():
                if analyze_response(r.text, payload):
                    decoded_payload = decode_payload(payload, encoding)
                    if decoded_payload and is_payload_reflected(r.text, decoded_payload):
                        print(f"{RED}XSS VULNERABILITY FOUND: {new_url}{RESET}")
                        # Run additional check
                        await additional_check(url, injection_point, payload, http_method)
                    else:
                        print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
                else:
                    print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
            else:
                print(f"Response from {new_url} is not HTML, skipping XSS checks.")
            
        else:
            print(f"Request to {new_url} failed.")

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except Exception as e:
        print(f"General error occurred: {e}")

    # Use Selenium for advanced XSS checking
    selenium_check(url, payload)

    return r

# Asynchronous scanning function
async def scan(url, payloads, vuln_type, injection_point, http_method, encoding):
    tasks = []
    for payload in payloads:
        task = asyncio.ensure_future(test_xss(url, injection_point, payload, vuln_type, http_method, encoding))
        tasks.append(task)
    responses = await asyncio.gather(*tasks)
    return responses

# Main function
def main(url, payloads_file, vuln_type, injection_point, http_method, encoding):
    with open(payloads_file, "r") as f:
        payloads = f.read().splitlines()
    
    loop = asyncio.get_event_loop()
    responses = loop.run_until_complete(scan(url, payloads, vuln_type, injection_point, http_method, encoding))
    return responses

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python xss_test.py <url> <payloads_file> <vuln_type> <injection_point> <http_method> <encoding>")
        sys.exit(1)

    url = sys.argv[1]
    payloads_file = sys.argv[2]
    vuln_type = sys.argv[3]
    injection_point = sys.argv[4]
    http_method = sys.argv[5]
    encoding = sys.argv[6]

    main(url, payloads_file, vuln_type, injection_point, http_method, encoding)
