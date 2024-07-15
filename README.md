# Subdomain Enumeration and Brute Forcing Tool

This script is designed for cybersecurity professionals and enthusiasts to gather, deduplicate, check, and brute force subdomains for a given domain. It also checks for active and potentially sensitive subdomains, providing comprehensive results in separate files within an output folder.

## Features

- **Subdomain Enumeration**: Gather subdomains using `sublist3r`, `subfinder`, `assetfinder`, and crt.sh.
- **Deduplication**: Remove duplicate subdomains to ensure unique entries.
- **Active Subdomain Checking**: Verify which subdomains are active.
- **Subdomain Brute Forcing**: Discover additional subdomains by brute forcing with a wordlist.
- **Sensitive Subdomain Detection**: Identify subdomains containing sensitive keywords.
- **Parallel Processing**: Utilize multi-threading for efficient subdomain checking and brute forcing.
- **Progress Indicators**: Display progress bars for subdomain checking and brute forcing.

## Requirements

- Python 3.x
- The following tools must be installed and available in your PATH:
  - `sublist3r`
  - `subfinder`
  - `assetfinder`
  - `ffuf`
- The `requests`, `shlex`, `subprocess`, `tqdm`, and `concurrent.futures` Python modules (can be installed via pip)

## Installation

1. Install Python 3.x from [python.org](https://www.python.org/).
2. Install required Python modules:
   ```sh
   pip install -r requirements.txt
   ```
3. Ensure the required tools are installed:
   - **Sublist3r**:
     ```sh
     git clone https://github.com/aboul3la/Sublist3r.git
     cd Sublist3r
     pip install -r requirements.txt
     sudo python setup.py install
     ```
   - **Subfinder**:
     ```sh
     go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
     ```
   - **Assetfinder**:
     ```sh
     go get -u github.com/tomnomnom/assetfinder
     ```
   - **ffuf**:
     ```sh
     go get -u github.com/ffuf/ffuf
     ```

## Usage

1. Clone the repository or download the script.
2. Run the script:
   ```sh
   python3 main.py
   ```
3. Provide the required inputs when prompted:
   - Domain name (e.g., `example.com`)
   - Path to the wordlist for brute forcing subdomains (e.g., `/path/to/subdomain_wordlist.txt`)

### Example Command

```sh
python3 main.py
```

### Script Output

The script will generate the following files in the `output` folder:
- `active_subdomains.txt`: List of active subdomains found using enumeration tools.
- `all_active_subdomains.txt`: Combined list of active subdomains from enumeration and brute forcing.
- `sensitive_subdomains.txt`: List of subdomains containing sensitive keywords.

## Notes

- Ensure you have the necessary permissions to run subdomain enumeration and brute-forcing tasks on the target domain.
- Customize the sensitive keywords in the `check_sensitive_subdomains` function as needed.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
