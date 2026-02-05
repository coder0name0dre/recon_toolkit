import requests
import socket
import re
import json
import csv
from datetime import datetime, timezone
from bs4 import BeautifulSoup

# Subdomain Enumeration #

def get_subdomains(domain):
# Pulls subdomains from Certificate Transparency logs (crt.sh)
# Passive OSINT - no interaction with target infrastructure.

    print(f"[info] Starting passive subdomain enumeration for {domain}")

    # crt.sh returns JSON if we specify output=json
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    headers = {
        "User-Agent": "Mozilla/5.0 (Recon-Tool SOC Edition)"
    }

    # we use a set to avoid duplicate subdomains
    subdomains = set()

    try:
        response = requests.get(url, headers=headers, timeout=10)

        # if crt.sh returns nothing useful
        if not response.text.strip():
            print("[warning] crt.sh returned an empty response")
            return []
        
        # crt.sh sometimes returns HTML instead of JSON
        if response.text.lstrip().startswith("<"):
            print("[warning] crt.sh did not return JSON (likely rate limited)")
            return []
        
        data = response.json()

        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                if domain in name:
                    subdomains.add(name.strip())

    except requests.exceptions.RequestException as e:
        print("[error] Network error contacting crt.sh:", e)

    except ValueError:
        # JSON parsing failed
        print("[warning] Failed to parse JSON from crt.sh")

    return sorted(subdomains)


# Email Collection #

def get_emails(domain):
# Extract email addresses from the homepage HTML.

    print(f"[info] Attempting email extraction from https://{domain}")

    emails = set()
    url = f"https://{domain}"

    try:
        # fetch homepage HTML
        response = requests.get(url, timeout=10)

        # Parse HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # regex pattern to match common email formats
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

        # search all visible text for emails
        found_emails = re.findall(email_pattern, soup.text)

        for email in found_emails:
            emails.add(email)

    except Exception as e:
        print("[error] Email extraction failed:", e)

    return sorted(emails)


# Port Scanning #

def scan_ports(target, ports):
# Perform a basic TCP connect scan.

    print(f"[info] Beginning authorised port scan for {target}")
    open_ports = []

    for port in ports:
        try:
            # create a new socket for each port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # timeout prevents hanging on filtered ports
            sock.settimeout(1)

            # connect_ex returns 0 if connection succeeds
            result = sock.connect_ex((target, port))

            if result == 0:
                open_ports.append(port)

            # always close sockets to avoid resource exhaustion
            sock.close()

        except Exception:
            # fail silently so one port doesn't break the scan
            pass

    return open_ports


# Output functions #

def save_json(data, filename="recon_results.json"):
# Save results in JSON format.

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print(f"[info] JSON results saved to {filename}")

def save_csv(data, filename="recon_results.csv"):
# Save results in CSV format.

    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)

        # header row
        writer.writerow(["Category", "Value"])

        # write subdomains
        for subdomain in data["subdomains"]:
            writer.writerow(["Subdomain", subdomain])

        # write emails
        for email in data["emails"]:
            writer.writerow(["Email", email])

        # write open ports
        for port in data["open_ports"]:
            writer.writerow(["Open Port", port])

    print(f"[info] CSV results saved to {filename}")


# Main Controller #

def main():
# Main execution logic.

    # get authorised target from user
    domain = input("Enter authorised target domain: ").strip()

    # record UTC timestamp for logging and auditing
    timestamp = datetime.now(timezone.utc).strftime("%d-%m-%Y %H:%M:%S UTC")

    # run passive recon modules
    subdomains = get_subdomains(domain)
    emails = get_emails(domain)

    # definer limited port list
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 8080]

    # run active recon module
    open_ports = scan_ports(domain, common_ports)

    # combine all results into a single structure
    recon_data = {
        "target": domain,
        "timestamp": timestamp,
        "subdomains": subdomains,
        "emails": emails,
        "open_ports": open_ports
    }

    # output results
    save_json(recon_data)
    save_csv(recon_data)

    print("\nRecon complete")
    print(
        f"[summary] Subdomains: {len(subdomains)} | "
        f"Emails: {len(emails)} | "
        f"Open Ports: {len(open_ports)}"
    )

if __name__ == "__main__":
    main()