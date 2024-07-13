import os
import subprocess
import shlex
import requests
import shutil
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

# Function to run a command and return the output
def run_command(command):
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e}")
        return ""
    except FileNotFoundError as e:
        print(f"Executable not found: {command}\n{e}")
        return ""

# Function to check if required tools are installed
def check_tools():
    required_tools = ["sublist3r", "subfinder", "assetfinder", "ffuf"]
    for tool in required_tools:
        if not shutil.which(tool):
            print(f"Error: {tool} is not installed or not in PATH.")
            return False
    return True

# Step 1: Gather Subdomains
def gather_subdomains(domain):
    subdomains = set()

    # Sublist3r
    sublist3r_output = run_command(f"sublist3r -d {domain} -o sublist3r_output.txt")
    if os.path.isfile("sublist3r_output.txt"):
        with open("sublist3r_output.txt") as file:
            subdomains.update(file.read().splitlines())

    # Subfinder
    subfinder_output = run_command(f"subfinder -d {domain}")
    subdomains.update(subfinder_output.splitlines())

    # Assetfinder
    assetfinder_output = run_command(f"assetfinder --subs-only {domain}")
    subdomains.update(assetfinder_output.splitlines())

    # crt.sh
    crtsh_response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if crtsh_response.status_code == 200:
        crtsh_subdomains = {entry["name_value"] for entry in crtsh_response.json()}
        subdomains.update(crtsh_subdomains)
    else:
        print("Error fetching data from crt.sh")

    return subdomains

# Step 2: Deduplicate Subdomains
def deduplicate(subdomains):
    return list(set(subdomains))

# Function to check if a subdomain is active
def is_active(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Step 3: Check Active Subdomains with progress bar and parallel processing
def check_active_subdomains(subdomains):
    active_subdomains = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(is_active, subdomains), total=len(subdomains), desc="Checking subdomains", unit="subdomain"))
    for subdomain, is_active_flag in zip(subdomains, results):
        if is_active_flag:
            active_subdomains.append(subdomain)
    return active_subdomains

# Step 4: Brute Force Subdomains
def brute_force_subdomains(domain, wordlist):
    subdomains = set()
    with open(wordlist) as file:
        words = file.read().splitlines()
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(tqdm(executor.map(lambda word: f"{word}.{domain}", words), total=len(words), desc="Brute forcing subdomains", unit="subdomain"))
            subdomains.update(results)
    return subdomains

# Step 5: Check for Sensitive Subdomains
def check_sensitive_subdomains(subdomains):
    sensitive_keywords = ["admin", "secure", "internal", "confidential"]
    sensitive_subdomains = [subdomain for subdomain in subdomains if any(keyword in subdomain for keyword in sensitive_keywords)]
    return sensitive_subdomains

# Step 6: Save to File
def save_to_file(subdomains, filename):
    with open(filename, "w") as file:
        for subdomain in subdomains:
            file.write(f"{subdomain}\n")

# Function to save active subdomains to a file
def save_active_subdomains(active_subdomains, filename):
    save_to_file(active_subdomains, filename)
    print(f"Active subdomains saved to {filename}")

# Main Function
if __name__ == "__main__":
    if not check_tools():
        print("One or more required tools are not installed. Please install them and ensure they are in your PATH.")
        exit(1)
    domain = input("Enter the domain: ")
    wordlist = input("Enter the path to the wordlist: ")
    
    # Create output directory if it doesn't exist
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    print("Gathering subdomains...")
    subdomains = gather_subdomains(domain)
    print("Deduplicating subdomains...")
    unique_subdomains = deduplicate(subdomains)
    print("Checking active subdomains...")
    active_subdomains = check_active_subdomains(unique_subdomains)
    save_active_subdomains(active_subdomains, os.path.join(output_dir, "active_subdomains.txt"))
    
    print("Brute forcing subdomains...")
    brute_forced_subdomains = brute_force_subdomains(domain, wordlist)
    print("Deduplicating brute forced subdomains...")
    unique_brute_forced_subdomains = deduplicate(brute_forced_subdomains)
    print("Checking active brute forced subdomains...")
    active_brute_forced_subdomains = check_active_subdomains(unique_brute_forced_subdomains)
    
    all_active_subdomains = deduplicate(active_subdomains + active_brute_forced_subdomains)
    save_active_subdomains(all_active_subdomains, os.path.join(output_dir, "all_active_subdomains.txt"))
    
    print("Checking for sensitive subdomains...")
    sensitive_subdomains = check_sensitive_subdomains(all_active_subdomains)
    save_to_file(sensitive_subdomains, os.path.join(output_dir, "sensitive_subdomains.txt"))
    
    print(f"Sensitive subdomains saved to {os.path.join(output_dir, 'sensitive_subdomains.txt')}")
