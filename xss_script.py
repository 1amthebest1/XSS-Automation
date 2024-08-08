import requests
import sys
import asyncio
import base64
import urllib.parse
import html
import re

# ANSI escape codes for coloring the output
RED = '\033[91m'
RESET = '\033[0m'

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
            r = requests.get(new_url, headers=headers, cookies=cookies, auth=("user", "pass"))
        elif http_method.lower() == "post":
            r = requests.post(new_url, headers=headers, cookies=cookies, auth=("user", "pass"))

        # Check for XSS vulnerability, ignore 403 status codes
        if r is not None and r.status_code != 403:
            content = r.text.lower()

            # Nuclei-like matchers for XSS
            script_check = re.compile(r'<script\b[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
            iframe_check = re.compile(r'<iframe\b[^>]*src=["\']?javascript:', re.IGNORECASE)
            matcher_check = re.compile(r'javascript:.*?(alert|prompt|confirm)\(', re.IGNORECASE)
            inline_js_check = re.compile(r'<script\b[^>]*>([\s\S]*?)alert\(', re.IGNORECASE)
            eval_check = re.compile(r'eval\(', re.IGNORECASE)
            onerror_check = re.compile(r'onerror\s*=', re.IGNORECASE)
            onload_check = re.compile(r'onload\s*=', re.IGNORECASE)
            document_write_check = re.compile(r'document\.write\(', re.IGNORECASE)
            xss_indicators = [script_check, iframe_check, matcher_check, inline_js_check, eval_check, onerror_check, onload_check, document_write_check]
            
            # Check if content contains known XSS patterns
            if any(regex.search(content) for regex in xss_indicators):
                # Further checks to reduce false positives
                if any(content.find(payload) != -1 for payload in [payload, payload.lower()]):
                    print(f"{RED}XSS VULNERABILITY FOUND: {new_url}{RESET}")
                else:
                    print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
            else:
                print(f"No XSS vulnerability found at {new_url} with payload: {payload}")

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
