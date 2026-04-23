# Roger CORS 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**CORS (Cross-Origin Resource Sharing) misconfiguration scanner for bug bounty hunting.**

Detects dangerous CORS policies including wildcard origins with credentials, reflected origins, and subdomain takeover opportunities.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

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

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger CORS helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)