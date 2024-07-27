import os
import subprocess
import requests
import shutil
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

# Function to run a command and return the output
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e}")
        return ""
    except FileNotFoundError as e:
        print(f"Executable not found: {command}\n{e}")
        return ""

# Function to check if required tools are installed
def check_tools():
    required_tools = ["sublist3r", "subfinder", "assetfinder", "httprobe"]
    for tool in required_tools:
        if not shutil.which(tool):
            print(f"Error: {tool} is not installed or not in PATH.")
            return False
    return True

# Function to gather subdomains from various tools
def gather_subdomains(domain, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    subdomains = set()
    
    # Sublist3r
    print("Running Sublist3r...")
    sublist3r_output_file = os.path.join(output_folder, 'sublist3r_output.txt')
    run_command(f"sublist3r -d {domain} -o {sublist3r_output_file}")
    if os.path.isfile(sublist3r_output_file):
        with open(sublist3r_output_file, 'r') as f:
            subdomains.update(f.read().splitlines())

    # Subfinder
    print("Running Subfinder...")
    subfinder_output_file = os.path.join(output_folder, 'subfinder_output.txt')
    run_command(f"subfinder -d {domain} -o {subfinder_output_file}")
    if os.path.isfile(subfinder_output_file):
        with open(subfinder_output_file, 'r') as f:
            subdomains.update(f.read().splitlines())

    # Assetfinder
    print("Running Assetfinder...")
    assetfinder_output_file = os.path.join(output_folder, 'assetfinder_output.txt')
    run_command(f"assetfinder --subs-only {domain} > {assetfinder_output_file}")
    if os.path.isfile(assetfinder_output_file):
        with open(assetfinder_output_file, 'r') as f:
            subdomains.update(f.read().splitlines())

    # crt.sh
    print("Gathering data from crt.sh...")
    crtsh_output_file = os.path.join(output_folder, 'crtsh_output.txt')
    crtsh_response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if crtsh_response.status_code == 200:
        crtsh_subdomains = {entry["name_value"] for entry in crtsh_response.json()}
        with open(crtsh_output_file, 'w') as f:
            f.writelines(f"{sub}\n" for sub in crtsh_subdomains)
        subdomains.update(crtsh_subdomains)
    else:
        print("Error fetching data from crt.sh")

    # Save all subdomains to a single file
    all_subdomains_file = os.path.join(output_folder, 'all_subdomains.txt')
    with open(all_subdomains_file, 'w') as f:
        unique_subdomains = sorted(subdomains)
        f.writelines(f"{sub}\n" for sub in unique_subdomains)
    
    return all_subdomains_file

# Function to deduplicate a list of subdomains
def deduplicate(file_path):
    with open(file_path, 'r') as f:
        unique_lines = sorted(set(f.read().splitlines()))
    with open(file_path, 'w') as f:
        f.writelines(f"{line}\n" for line in unique_lines)
    return unique_lines

# Function to check if a subdomain is active using httprobe
def is_active_with_httprobe(subdomains):
    active_subdomains = set()
    with subprocess.Popen(['httprobe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as proc:
        for subdomain in subdomains:
            proc.stdin.write(f"{subdomain}\n")
        proc.stdin.close()

        for line in proc.stdout:
            active_subdomains.add(line.strip())

    return list(active_subdomains)

# Updated function to check active subdomains
def check_active_subdomains(subdomains, output_folder):
    print("Checking active subdomains with httprobe...")
    active_subdomains_file = os.path.join(output_folder, 'active_subdomains.txt')

    active_subdomains = is_active_with_httprobe(subdomains)

    with open(active_subdomains_file, 'w') as f:
        f.writelines(f"{sub}\n" for sub in active_subdomains)

    return active_subdomains_file

# Function to check if a subdomain contains sensitive keywords
def is_sensitive(subdomain, sensitive_keywords):
    return any(keyword in subdomain for keyword in sensitive_keywords)

# Function to find sensitive subdomains
def find_sensitive_subdomains(active_subdomains_file, sensitive_keywords_file, output_folder):
    sensitive_subdomains = []
    sensitive_subdomains_file = os.path.join(output_folder, 'sensitive_subdomains.txt')

    with open(sensitive_keywords_file, 'r') as f:
        sensitive_keywords = f.read().splitlines()

    with open(active_subdomains_file, 'r') as f:
        active_subdomains = f.read().splitlines()

    for subdomain in tqdm(active_subdomains, desc="Identifying sensitive subdomains", unit="subdomain"):
        if is_sensitive(subdomain, sensitive_keywords):
            sensitive_subdomains.append(subdomain)

    with open(sensitive_subdomains_file, 'w') as f:
        f.writelines(f"{sub}\n" for sub in sensitive_subdomains)

    return sensitive_subdomains_file

# Main function
if __name__ == "__main__":
    if not check_tools():
        print("One or more required tools are not installed. Please install them and ensure they are in your PATH.")
        exit(1)

    import argparse

    parser = argparse.ArgumentParser(description="Subdomain Enumeration and Analysis Tool")
    parser.add_argument('-d', '--domain', required=True, help="Domain to enumerate")
    parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist for brute forcing")
    parser.add_argument('-s', '--sensitive', required=True, help="Path to the sensitive keywords wordlist")
    args = parser.parse_args()

    domain = args.domain
    wordlist = args.wordlist
    sensitive_keywords = args.sensitive
    output_folder = "results"

    print("Gathering subdomains...")
    all_subdomains_file = gather_subdomains(domain, output_folder)

    print("Checking active subdomains...")
    deduplicated_subdomains = deduplicate(all_subdomains_file)
    active_subdomains_file = check_active_subdomains(deduplicated_subdomains, output_folder)

    print("Identifying sensitive subdomains...")
    sensitive_subdomains_file = find_sensitive_subdomains(active_subdomains_file, sensitive_keywords, output_folder)

    print(f"All subdomains saved to {all_subdomains_file}")
    print(f"Active subdomains saved to {active_subdomains_file}")
    print(f"Sensitive subdomains saved to {sensitive_subdomains_file}")
