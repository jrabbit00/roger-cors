# Roger CORS 🐰

CORS misconfiguration scanner for bug bounty hunting. Detects dangerous CORS policies that can lead to data theft.

## Why CORS?

CORS (Cross-Origin Resource Sharing) misconfigurations are valuable bug bounty findings:
- Can leak sensitive data to attacker-controlled origins
- Credentials + wildcard = account takeover
- Subdomain takeovers via CORS
- Reflected origins with credentials

## Features

- Tests multiple attack vectors
- Detects wildcard origins
- Finds reflected origins with credentials
- Identifies subdomain takeable CORS
- Severity ratings (HIGH/MEDIUM)
- Multi-threaded scanning
- OPTIONS request testing

## Installation

```bash
git clone https://github.com/jrabbit00/roger-cors.git
cd roger-cors
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 cors.py https://target.com/api

# Save results
python3 cors.py target.com -o findings.txt
```

## What It Detects

- `Access-Control-Allow-Origin: *` with credentials
- `null` origin allowed
- Reflected origin with credentials
- Subdomain takeable via CORS
- Any HTTPS origin allowed
- Dangerous HTTP methods exposed

## Examples

```bash
python3 cors.py https://example.com/api
python3 cors.py example.com/api -o cors_results.txt
```

## License

MIT License