# OSINT & Recon Automation Toolkit (Blue Team / SOC)

This project is a Python recon toolkit designed for blue team and SOC use cases.

It focuses on ethical, authorised recon, and analyst friendly output.


**Authorisation Required:**

This tool must only be used against domains you own or have explicit permission to assess.

---

## Features

- **Passive Subdomain Enumeration**
    - Uses Certificate Transparency logs (`crt.sh`)
    - No direct interaction with target infrastructure

- **Public Email Discovery**
    - Extracts email addresses from publicly accessible HTML
    - No crawling, brute forcing, or guessing

- **Limited Port Scanning**
    - Small, defined port list
    - Designed for authorised validation only

- **Structured Output**
    - JSON (SIEM / automation friendly)
    - CSV (analyst / reporting friendly)

---

## Intended Use Cases

This tool is designed for defensive security, including:

- SOC asset discovery
- External attack surface monitoring
- Shadow IT identification
- Incident response enrichment
- Purple team validation
- Security learning and training

**This is not an exploitation framework**

---

## Requirements

- Python 3.8 +
- Libraries:
    - `requests`
    - `beautifulsoup4`

Install dependencies:

```
pip install requests beautifulsoup4
```

---

## How To Run

1. Clone the repository:

```
git clone https://github.com/coder0name0dre/recon_toolkit.git
cd recon_toolkit
```

2. Create a virtual environment (Optional):

```
python -m venv venv
source venv/bin/activate   # macOS / Linux
venv\Scripts\activate      # Windows
```

3. Run the script:

```
python recon.py
```

4. Enter an authorised domain when prompted:

```
example.com
```

---

## Output

**JSON** (`recon_results.json`)

Structured output suitable for:

- SIEM ingestiojn
- Automation pipelines
- Long term tracking

Example:

```
{
    "target": "example.com",
    "timestamp": "05-02-2026 14:14:06 UTC",
    "subdomains": [
        "support.example.com",
        "user@example.com",
        "www.example.com"
    ],
    "emails": [],
    "open_ports": [
        80,
        443
    ]
}
```

**CSV** (`recon_results.csv`)

Analyst friendly format for:

- Excel
- Reports
- Tickets

---

## Safe Testing Targets

Recommended domains for learning and testing:

- `scasnme.nmap.org` (official Nmap scan target)
- `example.com`
- `testphp.vulnweb.com`

---

## License

This project is licensed under the [MIT License](https://github.com/coder0name0dre/recon_toolkit/blob/main/LICENSE).