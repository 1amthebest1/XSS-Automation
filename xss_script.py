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
async def test_xss(url, injection_point, payload, vuln_type, http_method, encoding, headers=None, cookies=None):
    if headers is None:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "Custom-Header": "custom value"
        }
    if cookies is None:
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
        # Inject payload based on injection point type
        if injection_point.startswith('param:'):
            param_name = injection_point[6:]
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            new_query_string = urllib.parse.urlencode(query_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query_string))
        elif injection_point.startswith('path:'):
            path_segment = injection_point[5:]
            new_url = f"{url}/{payload}"
        elif injection_point.startswith('header:'):
            header_name = injection_point[7:]
            headers[header_name] = payload
            new_url = url  # URL doesn't change for header injection
        elif injection_point.startswith('cookie:'):
            cookie_name = injection_point[7:]
            cookies[cookie_name] = payload
            new_url = url  # URL doesn't change for cookie injection
        elif injection_point.startswith('body:'):
            new_url = url  # URL doesn't change for body payload
            payload = payload  # Use payload as body content
        else:
            raise ValueError("Invalid injection point format")

        # Send request based on the method
        if http_method.lower() == "get":
            r = requests.get(new_url, headers=headers, cookies=cookies, auth=("user", "pass"))
        elif http_method.lower() == "post":
            r = requests.post(new_url, headers=headers, cookies=cookies, auth=("user", "pass"), data=payload)
        else:
            raise ValueError("Unsupported HTTP method")

        # Check for XSS vulnerability, ignore 403 status codes
        if r is not None and r.status_code != 403:
            if vuln_type == "reflected":
                content = r.text.lower()
                
                # Matchers used by Nuclei templates
                script_check = re.compile(r'<script\b[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
                iframe_check = re.compile(r'<iframe\b[^>]*src=["\']?javascript:', re.IGNORECASE)
                matcher_check = re.compile(r'javascript:.*?(alert|prompt|confirm)\(', re.IGNORECASE)
                
                # Additional Nuclei-like matchers without look-behind
                inline_js_check = re.compile(r'<script\b[^>]*>([\s\S]*?)alert\(', re.IGNORECASE)
                eval_check = re.compile(r'eval\(', re.IGNORECASE)
                onerror_check = re.compile(r'onerror\s*=', re.IGNORECASE)
                onload_check = re.compile(r'onload\s*=', re.IGNORECASE)
                document_write_check = re.compile(r'document\.write\(', re.IGNORECASE)
                
                # Combined check for known XSS patterns
                if (script_check.search(content) or
                    iframe_check.search(content) or
                    matcher_check.search(content) or
                    inline_js_check.search(content) or
                    eval_check.search(content) or
                    onerror_check.search(content) or
                    onload_check.search(content) or
                    document_write_check.search(content)):

                    # Further checks to avoid false positives
                    if (r.text.find(payload) == -1):  # Ensure payload isn't just present as part of normal content
                        print(f"{RED}XSS VULNERABILITY FOUND: {new_url}{RESET}")
                    else:
                        print(f"No XSS vulnerability found at {new_url} with payload: {payload}")
                else:
                    print(f"No XSS vulnerability found at {new_url} with payload: {payload}")

            elif vuln_type == "persistent":
                # Implement persistent XSS logic if needed
                pass
            else:
                print(f"Invalid vulnerability type: {vuln_type}")
        else:
            print(f"Request to {new_url} resulted in status code 403, skipping.")

    except Exception as e:
        print(f"Error occurred: {e}")

    return r

# Asynchronous scanning function
async def scan(url, payloads, vuln_type, injection_points, http_method, encoding):
    tasks = []
    for injection_point in injection_points:
        for payload in payloads:
            task = asyncio.ensure_future(test_xss(url, injection_point, payload, vuln_type, http_method, encoding))
            tasks.append(task)
    responses = await asyncio.gather(*tasks)
    return responses

# Main function
def main(url, payloads_file, vuln_type, injection_points_file, http_method, encoding):
    with open(payloads_file, "r") as f:
        payloads = f.read().splitlines()
    
    with open(injection_points_file, "r") as f:
        injection_points = f.read().splitlines()

    loop = asyncio.get_event_loop()
    responses = loop.run_until_complete(scan(url, payloads, vuln_type, injection_points, http_method, encoding))
    return responses

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python3 xss_scanner.py <url> <payloads_file> <vuln_type> <injection_points_file> <http_method> <encoding>")
        sys.exit(1)

    url = sys.argv[1]
    payloads_file = sys.argv[2]
    vuln_type = sys.argv[3]
    injection_points_file = sys.argv[4]
    http_method = sys.argv[5]
    encoding = sys.argv[6]

    main(url, payloads_file, vuln_type, injection_points_file, http_method, encoding)
