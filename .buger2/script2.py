import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

START_URL = "https://ooredoo.dz"  # 🔁 Replace with your starting URL
URL_FILE = "found_urls.txt"
TIMEOUT = 5

visited = set()
to_visit = set([START_URL])

def is_absolute(url):
    return bool(urlparse(url).netloc)

def extract_absolute_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full_url = urljoin(base_url, href)
        if is_absolute(full_url):
            links.add(full_url.split("#")[0])  # remove fragments
    return links

def save_all(urls):
    with open(URL_FILE, "w") as f:
        for url in sorted(urls):
            f.write(url + "\n")

def crawl():
    session = requests.Session()
    round_num = 0

    while to_visit:
        round_num += 1
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        print(f"[{round_num}] Visiting: {current_url}")
        try:
            response = session.get(current_url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
            response.raise_for_status()
            new_links = extract_absolute_links(response.text, current_url)
            for link in new_links:
                if link not in visited:
                    to_visit.add(link)
        except Exception as e:
            print(f"  ⚠️ Failed: {e}")
        visited.add(current_url)
        time.sleep(0.5)  # polite delay (adjust as needed)

    print(f"\n✅ Finished. {len(visited)} unique URLs found.")
    save_all(visited)

if __name__ == "__main__":
    crawl()
