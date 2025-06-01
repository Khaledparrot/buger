import os
import sys
import requests
from bs4 import BeautifulSoup
import json
import time

def create_output_directory(domain):
    """
    Creates a directory named after the domain to store results.
    """
    if not os.path.exists(domain):
        os.makedirs(domain)
    return domain

def save_to_file(directory, filename, data):
    """
    Saves a list of data to a file within the specified directory.
    """
    filepath = os.path.join(directory, filename)
    with open(filepath, 'w') as f:
        for item in sorted(set(data)):
            f.write(f"{item}\n")
    print(f"[+] Saved {len(data)} entries to {filepath}")

def fetch_crtsh_subdomains(domain):
    """
    Fetches subdomains from crt.sh Certificate Transparency logs.
    """
    print("[*] Fetching subdomains from crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            entries = response.json()
            subdomains = set()
            for entry in entries:
                name_value = entry.get('name_value')
                if name_value:
                    subdomains.update(name_value.splitlines())
            return list(subdomains)
        else:
            print(f"[!] crt.sh returned status code {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching from crt.sh: {e}")
    return []

def fetch_google_dorks_subdomains(domain):
    """
    Uses Google Dorks to find subdomains via search engine results.
    Note: This method may be limited by Google's rate limiting and requires parsing HTML content.
    """
    print("[*] Fetching subdomains using Google Dorks...")
    subdomains = set()
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    query = f"site:*.{domain} -www"
    url = f"https://www.google.com/search?q={query}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for cite in soup.find_all('cite'):
                href = cite.get_text()
                if domain in href:
                    subdomain = href.split('/')[0]
                    if subdomain.endswith(domain):
                        subdomains.add(subdomain)
        else:
            print(f"[!] Google returned status code {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching from Google: {e}")
    return list(subdomains)

def fetch_wayback_urls(domain):
    """
    Retrieves URLs from the Wayback Machine for the given domain.
    """
    print("[*] Fetching URLs from Wayback Machine...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = [entry[0] for entry in data[1:]]  # Skip header
            return urls
        else:
            print(f"[!] Wayback Machine returned status code {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching from Wayback Machine: {e}")
    return []

def fetch_commoncrawl_urls(domain):
    """
    Retrieves URLs from Common Crawl for the given domain.
    """
    print("[*] Fetching URLs from Common Crawl...")
    index_url = "https://index.commoncrawl.org/collinfo.json"
    urls = set()
    try:
        response = requests.get(index_url, timeout=10)
        if response.status_code == 200:
            indexes = response.json()
            for idx in indexes:
                cc_url = f"{idx['cdx-api']}?url=*.{domain}&output=json"
                try:
                    cc_response = requests.get(cc_url, timeout=10)
                    if cc_response.status_code == 200:
                        for line in cc_response.text.strip().split('\n'):
                            obj = json.loads(line)
                            url = obj.get('url')
                            if url:
                                urls.add(url)
                    time.sleep(1)  # To avoid overwhelming the server
                except Exception as e:
                    print(f"[!] Error fetching from {cc_url}: {e}")
        else:
            print(f"[!] Common Crawl index returned status code {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching Common Crawl indexes: {e}")
    return list(urls)

def main():
    if len(sys.argv) != 2:
        print("Usage: python recon_tool.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    output_dir = create_output_directory(domain)

    # Fetch subdomains from crt.sh
    crtsh_subdomains = fetch_crtsh_subdomains(domain)
    save_to_file(output_dir, "subdomains_crtsh.txt", crtsh_subdomains)

    # Fetch subdomains using Google Dorks
    google_subdomains = fetch_google_dorks_subdomains(domain)
    save_to_file(output_dir, "subdomains_google_dorks.txt", google_subdomains)

    # Fetch URLs from Wayback Machine
    wayback_urls = fetch_wayback_urls(domain)
    save_to_file(output_dir, "urls_wayback.txt", wayback_urls)

    # Fetch URLs from Common Crawl
    commoncrawl_urls = fetch_commoncrawl_urls(domain)
    save_to_file(output_dir, "urls_commoncrawl.txt", commoncrawl_urls)

    print(f"\n[+] Reconnaissance completed for {domain}. Results saved in the '{output_dir}' directory.")

if __name__ == "__main__":
    main()
