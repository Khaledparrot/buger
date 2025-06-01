import os
import re
from urllib.parse import urlparse, parse_qs
from tqdm import tqdm  # Progress bar library

def load_urls(input_file):
    with open(input_file, 'r') as f:
        return list(set(line.strip() for line in f if line.strip()))

def save_urls(urls, category, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    with open(os.path.join(output_folder, f"{category}.txt"), 'w') as f:
        for url in urls:
            f.write(f"{url}\n")

def filter_urls(urls):
    static_exts = re.compile(r".*\.(css|js|jpg|jpeg|png|gif|svg|woff|ttf|eot|ico)(\?.*)?$", re.IGNORECASE)
    dynamic_exts = re.compile(r".*\.(php|asp|aspx|jsp|cgi)(\?.*)?$", re.IGNORECASE)

    categorized = {
        'dynamic': [],
        'with_params': [],
        'api': [],
        'admin': [],
        'file_handling': [],
        'potentially_sensitive': [],
        'others': []
    }

    print(f"[+] Total URLs to process: {len(urls)}")
    for url in tqdm(urls, desc="Processing URLs", unit="url"):
        if static_exts.match(url):
            continue  # Skip static files
        parsed = urlparse(url)
        path = parsed.path.lower()
        params = parse_qs(parsed.query)

        if dynamic_exts.match(url):
            categorized['dynamic'].append(url)
        elif params:
            categorized['with_params'].append(url)
        elif '/api/' in path or '/v1/' in path or '/graphql' in path:
            categorized['api'].append(url)
        elif any(x in path for x in ['/admin', '/login', '/dashboard', '/user']):
            categorized['admin'].append(url)
        elif any(x in path for x in ['/upload', '/file', '/download', '/export', '/import', '/path']):
            categorized['file_handling'].append(url)
        elif any(x in path for x in ['/config', '/backup', '/debug', '/test', '/internal', '/dev', '/old']):
            categorized['potentially_sensitive'].append(url)
        else:
            categorized['others'].append(url)

    return categorized

def main():
    input_file = 'urls.txt'  # Replace with your URL list
    output_folder = 'prioritized_urls'

    urls = load_urls(input_file)
    categorized_urls = filter_urls(urls)

    for category, url_list in categorized_urls.items():
        save_urls(url_list, category, output_folder)
        print(f"[+] Saved {len(url_list)} URLs to {category}.txt")

if __name__ == "__main__":
    try:
        from tqdm import tqdm
    except ImportError:
        print("[!] tqdm module not found. Installing...")
        os.system('pip install tqdm')
        from tqdm import tqdm

    main()
