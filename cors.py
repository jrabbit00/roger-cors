#!/usr/bin/env python3
"""
Roger CORS - CORS misconfiguration scanner for bug bounty hunting.
"""

import argparse
import concurrent.futures
import requests
import urllib3
import re
import sys
from urllib.parse import urlparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Test origins
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "https://target.com.evil.com",
    "https://target-original.attacker.com",
    "null",
    "https://null",
    "https://localhost",
    "https://127.0.0.1",
    "https://example.com",
]

# Origins that might indicate misconfiguration
DANGEROUS_ORIGINS = [
    "*",
    "null",
    "https://*",
    "http://*",
]


class RogerCORS:
    def __init__(self, target, threads=10, quiet=False, output=None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_url(self, url):
        """Parse URL and extract base."""
        if not url.startswith('http'):
            url = 'https://' + url
        return url
    
    def test_origin(self, url, origin):
        """Test a single origin for CORS misconfiguration."""
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET, POST, PUT, DELETE",
        }
        
        try:
            response = self.session.options(
                url, 
                headers=headers,
                timeout=10,
                verify=False
            )
            
            # Check for CORS headers
            ac_allow_origin = response.headers.get('Access-Control-Allow-Origin')
            ac_allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
            ac_allow_methods = response.headers.get('Access-Control-Allow-Methods')
            ac_allow_headers = response.headers.get('Access-Control-Allow-Headers')
            ac_expose_headers = response.headers.get('Access-Control-Expose-Headers')
            ac_max_age = response.headers.get('Access-Control-Max-Age')
            
            return {
                "url": url,
                "origin": origin,
                "status": response.status_code,
                "ACAO": ac_allow_origin,
                "ACAC": ac_allow_credentials,
                "ACAM": ac_allow_methods,
                "ACAHe": ac_allow_headers,
                "ACEHe": ac_expose_headers,
                "ACMA": ac_max_age,
            }
            
        except requests.exceptions.Timeout:
            return {"url": url, "origin": origin, "error": "timeout"}
        except Exception as e:
            return {"url": url, "origin": origin, "error": str(e)}
    
    def analyze_cors(self, result):
        """Analyze CORS response for vulnerabilities."""
        if result.get('error'):
            return None, None
        
        issues = []
        severity = None
        
        acao = result.get('ACAO', '')
        acac = result.get('ACAC', '')
        
        # Check for wildcard origin
        if acao == '*':
            issues.append("Wildcard (*) origin allowed")
            severity = "MEDIUM"
        
        # Check for null origin
        if acao == 'null':
            issues.append("null origin allowed")
            severity = "MEDIUM"
        
        # Check for dynamic origin reflection
        if result.get('origin') in acao and result['origin'] not in DANGEROUS_ORIGINS:
            issues.append(f"Origin reflected: {acao}")
            
            # Check if credentials are allowed with reflection
            if acac and acac.lower() == 'true':
                issues.append("Credentials allowed with reflected origin")
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        
        # Check for insecure origin patterns
        if acao:
            # Subdomain takeable via dots in origin
            if result['origin'] != acao and '.evil.com' in result['origin']:
                issues.append(f"Subdomain allowed: {acao}")
                severity = "HIGH"
        
        # Check for https://* pattern
        if acao == 'https://*':
            issues.append("Any HTTPS origin allowed")
            severity = "HIGH"
        
        # Check for missing Access-Control-Allow-Credentials when origin is not wildcard
        if acao and acao != '*' and not acac:
            issues.append("Missing Access-Control-Allow-Credentials")
        
        # Check for excessive methods
        if acac and acac.lower() == 'true':
            dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
            if result.get('ACAM'):
                for method in dangerous_methods:
                    if method in result['ACAM']:
                        issues.append(f"Dangerous method allowed: {method}")
        
        if issues:
            return issues, severity
        
        return None, None
    
    def scan(self):
        """Run the CORS scanner."""
        target = self.parse_url(self.target)
        
        print(f"[*] Starting CORS scan on: {target}")
        print(f"[*] Testing {len(TEST_ORIGINS)} origins")
        print("=" * 60)
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.test_origin, target, origin): origin 
                for origin in TEST_ORIGINS
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                
                if not self.quiet:
                    acao = result.get('ACAO', 'None')
                    print(f"[{result.get('status', '?')}] {result['origin']} -> ACAO: {acao}")
        
        # Analyze results
        print()
        print("=" * 60)
        print("[+] Analysis:")
        print()
        
        for result in results:
            issues, severity = self.analyze_cors(result)
            
            if issues:
                print(f"[!] VULNERABLE: {result['url']}")
                print(f"    Origin tested: {result['origin']}")
                print(f"    Severity: {severity}")
                for issue in issues:
                    print(f"    - {issue}")
                print()
                
                self.findings.append({
                    "url": result['url'],
                    "origin": result['origin'],
                    "severity": severity,
                    "issues": issues,
                    "acao": result.get('ACAO'),
                    "acac": result.get('ACAC')
                })
        
        if not self.findings:
            print("[*] No CORS misconfigurations found")
        
        # Save results
        if self.output:
            with open(self.output, 'w') as f:
                f.write(f"# CORS Scan Results for {target}\n\n")
                for finding in self.findings:
                    f.write(f"## Severity: {finding['severity']}\n")
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Origin: {finding['origin']}\n")
                    f.write(f"ACAO: {finding['acao']}\n")
                    f.write(f"ACAC: {finding['acac']}\n")
                    f.write("Issues:\n")
                    for issue in finding['issues']:
                        f.write(f"- {issue}\n")
                    f.write("\n")
        
        print(f"[*] Total vulnerabilities found: {len(self.findings)}")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger CORS - CORS misconfiguration scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL (e.g., https://target.com/api)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    
    args = parser.parse_args()
    
    scanner = RogerCORS(
        target=args.target,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()