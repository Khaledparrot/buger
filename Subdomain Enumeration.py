import dns.resolver
import threading
from queue import Queue
import random
import string
import sys
import signal
import time
from datetime import datetime
from tqdm import tqdm  # Progress bar library

# Global flag to detect when user wants to stop (e.g., Ctrl+C)
stop_scan = False

# Function to handle Ctrl+C (SIGINT)
def signal_handler(sig, frame):
    global stop_scan
    print("\n[!] Exit requested, stopping scan...")
    stop_scan = True

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Detects wildcard DNS (resolves random subdomain to see if DNS wildcarding is in place)
def detect_wildcard(domain, resolver):
    random_subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test_domain = f"{random_subdomain}.{domain}"
    try:
        answers = resolver.resolve(test_domain, 'A')
        ips = [rdata.to_text() for rdata in answers]
        print(f"[!] Wildcard DNS detected! {test_domain} resolves to {ips}")
        return set(ips)
    except:
        print("[+] No wildcard DNS detected")
        return set()

# Worker thread function
def worker(domain, queue, resolver, wildcard_ips, output_file, progress_bar):
    while not queue.empty() and not stop_scan:
        sub = queue.get()
        full_domain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full_domain, 'A')
            resolved_ips = set(rdata.to_text() for rdata in answers)
            if not resolved_ips.intersection(wildcard_ips):
                print(f"[+] Found: {full_domain} -> {resolved_ips}")
                with open(output_file, 'a') as f:
                    f.write(f"{full_domain}\n")  # Save immediately
            else:
                print(f"[-] Wildcard Match: {full_domain} -> {resolved_ips}")
        except:
            pass
        finally:
            queue.task_done()
            progress_bar.update(1)  # Update the progress bar

# Main brute force function with progress bar
def brute_force_subdomains(domain, wordlist, num_threads=10, output_file="found_subdomains.txt"):
    resolver = dns.resolver.Resolver()
    wildcard_ips = detect_wildcard(domain, resolver)
    
    # Prepare queue of subdomains
    q = Queue()
    for sub in wordlist:
        q.put(sub.strip())
    
    total_subdomains = q.qsize()

    # Initialize tqdm progress bar
    with tqdm(total=total_subdomains, desc="Scanning", unit="subdomain") as progress_bar:
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker, args=(domain, q, resolver, wildcard_ips, output_file, progress_bar))
            t.start()
            threads.append(t)
        
        # Wait for threads to finish
        q.join()
        for t in threads:
            t.join()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python subdomain_enum.py <domain> <wordlist_file>")
        sys.exit(1)
    
    domain = sys.argv[1].strip()
    wordlist_file = sys.argv[2].strip()
    
    # Generate a unique output filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"found_subdomains_{domain}_{timestamp}.txt"

    # Load the wordlist
    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file '{wordlist_file}' not found.")
        sys.exit(1)
    
    print(f"[*] Starting subdomain scan for {domain}")
    print(f"[*] Saving live results to '{output_file}'")
    
    # Run the scan with a progress bar
    brute_force_subdomains(domain, wordlist, num_threads=20, output_file=output_file)
    
    print(f"\n[+] Scan completed. Results saved to {output_file}")
