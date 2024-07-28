# Subdomain Enumeration and Brute Forcing Tool
This tool helps to enumerate subdomains for a given domain using multiple tools and checks for active subdomains and sensitive subdomains based on a list of keywords.

## Features

- Enumerate subdomains using `Sublist3r`, `Subfinder`, `Assetfinder`, and crt.sh
- Check for active subdomains using `httprobe`
- Identify subdomains containing sensitive keywords

## Requirements

- Python 3.x
- The following tools need to be installed and accessible in your PATH:
  - Sublist3r
  - Subfinder
  - Assetfinder
  - httprobe

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/repositoryname.git
   cd repositoryname
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the required tools (`Sublist3r`, `Subfinder`, `Assetfinder`, `httprobe`) are installed and in your PATH.

## Usage

```bash
python script.py -d <domain> -w <wordlist> -s <sensitive_keywords>
```

- `-d`, `--domain`: The domain to enumerate subdomains for.
- `-w`, `--wordlist`: Path to the wordlist for brute-forcing subdomains.
- `-s`, `--sensitive`: Path to the file containing sensitive keywords to search for in the subdomains.

## Output

The script will generate the following files in the `results` folder:

- `all_subdomains.txt`: Contains all discovered subdomains.
- `active_subdomains.txt`: Contains active subdomains.
- `sensitive_subdomains.txt`: Contains sensitive subdomains identified based on the keywords provided.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any changes or suggestions.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
