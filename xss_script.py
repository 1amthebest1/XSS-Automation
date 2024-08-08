import requests
import sys
import asyncio
import base64
import urllib.parse
import html
import re
import warnings
from bs4 import BeautifulSoup

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

# Function to check if payload is reflected in HTML content
def is_payload_reflected(response_text, payload):
    # Use BeautifulSoup for better HTML parsing
    soup = BeautifulSoup(response_text, 'html.parser')
    return payload in soup.get_text()

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

        # Check for XSS vulnerability, ignore 403 status codes
        if r is not None and r.status_code != 403:
            content_type = r.headers.get('Content-Type', '')
            if 'html' in content_type.lower():
                content = r.text.lower()

                # Nuclei-like matchers for XSS
                xss_patterns = [
                    re.compile(r'<script\b[^>]*>([\s\S]*?)</script>', re.IGNORECASE),
                    re.compile(r'<iframe\b[^>]*src=["\']?javascript:', re.IGNORECASE),
                    re.compile(r'javascript:.*?(alert|prompt|confirm)\(', re.IGNORECASE),
                    re.compile(r'<script\b[^>]*>([\s\S]*?)alert\(', re.IGNORECASE),
                    re.compile(r'eval\(', re.IGNORECASE),
                    re.compile(r'onerror\s*=', re.IGNORECASE),
                    re.compile(r'onload\s*=', re.IGNORECASE),
                    re.compile(r'document\.write\(', re.IGNORECASE)
                ]
                
                # Check if content contains known XSS patterns
                if any(pattern.search(content) for pattern in xss_patterns):
                    # Further checks to reduce false positives
                    if is_payload_reflected(r.text, payload):
                        print(f"{RED}XSS VULNERABILITY FOUND: {new_url}{RESET}")
                    else:
                        print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
                else:
                    print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
            else:
                print(f"Response from {new_url} is not HTML, skipping XSS checks.")

        else:
            print(f"Request to {new_url} resulted in status code 403, skipping.")

    except Exception as e:
        print(f"Error occurred: {e}")

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
        print("Usage: python3 xss_scanner.py <url> <payloads_file> <vuln_type> <injection_point> <http_method> <encoding>")
        sys.exit(1)

    url = sys.argv[1]
    payloads_file = sys.argv[2]
    vuln_type = sys.argv[3]
    injection_point = sys.argv[4]
    http_method = sys.argv[5]
    encoding = sys.argv[6]

    main(url, payloads_file, vuln_type, injection_point, http_method, encoding)
