import os

def merge_url_files(input_folder, output_file):
    url_set = set()
    total_files = 0
    total_urls = 0

    # Loop through all .txt files in the folder
    for filename in os.listdir(input_folder):
        if filename.endswith('.txt'):
            total_files += 1
            file_path = os.path.join(input_folder, filename)
            with open(file_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        url_set.add(url)
                        total_urls += 1

    # Write the unique URLs to the output file
    with open(output_file, 'w') as out:
        for url in sorted(url_set):
            out.write(f"{url}\n")

    print(f"[+] Processed {total_files} files.")
    print(f"[+] Collected {total_urls} URLs, reduced to {len(url_set)} unique URLs.")
    print(f"[+] Merged file saved as '{output_file}'.")

if __name__ == "__main__":
    input_folder = "url_files"  # Replace with your folder containing multiple .txt files
    output_file = "urls.txt"
    merge_url_files(input_folder, output_file)
