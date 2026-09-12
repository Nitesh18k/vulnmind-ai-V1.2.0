"""
VulnMind AI - Vulnerability Scanner Module
Integrates: nuclei, nikto, sqlmap, dalfox + Python HTTP checks
"""

import subprocess
import shutil
import json
import re
import requests
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


class VulnerabilityScanner:
    """Unified vulnerability scanning orchestrator."""

    SEVERITY_COLORS = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "blue",
    }

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Dict] = []

    def run_full_scan(self, scan_level: str = "standard") -> List[Dict]:
        """
        Run all vulnerability scanners.
        scan_level: quick | standard | deep
        """
        all_findings = []

        scanners = [
            ("Security Header Check", self._check_security_headers),
            ("SSL/TLS Analysis", self._check_ssl),
            ("Common Vulnerability Checks", self._common_vuln_checks),
        ]

        if tool_available("nuclei"):
            scanners.append(("Nuclei Templates", lambda: self._nuclei_scan(scan_level)))

        if tool_available("nikto") and scan_level in ["standard", "deep"]:
            scanners.append(("Nikto Web Scanner", self._nikto_scan))

        if scan_level == "deep":
            if tool_available("sqlmap"):
                scanners.append(("SQLMap", self._sqlmap_scan))
            if tool_available("dalfox"):
                scanners.append(("DalFox XSS Scanner", self._dalfox_scan))

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as prog:
            task = prog.add_task("[cyan]Scanning...", total=len(scanners))

            for name, fn in scanners:
                prog.update(task, description=f"[cyan]{name}...")
                try:
                    results = fn()
                    if results:
                        all_findings.extend(results)
                        console.print(f"  [green]✓[/green] {name}: found [cyan]{len(results)}[/cyan] findings")
                    else:
                        console.print(f"  [dim]✓ {name}: no findings[/dim]")
                except Exception as e:
                    console.print(f"  [yellow]⚠ {name} error: {e}[/yellow]")
                prog.advance(task)

        self.findings = all_findings
        return all_findings

    def _check_security_headers(self) -> List[Dict]:
        """Check for missing/misconfigured security headers."""
        findings = []
        url = f"https://{self.target}" if not self.target.startswith("http") else self.target

        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "VulnMind/1.0"},
                             allow_redirects=True)

            headers = {k.lower(): v for k, v in r.headers.items()}

            checks = [
                {
                    "header": "strict-transport-security",
                    "name": "Missing HSTS Header",
                    "severity": "medium",
                    "type": "misconfig",
                    "description": "HTTP Strict Transport Security (HSTS) is not set. This allows downgrade attacks.",
                    "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "cwe": "CWE-319",
                },
                {
                    "header": "content-security-policy",
                    "name": "Missing Content Security Policy",
                    "severity": "medium",
                    "type": "misconfig",
                    "description": "No Content-Security-Policy header found. XSS attacks may be easier to exploit.",
                    "remediation": "Implement a restrictive CSP header to prevent XSS and data injection attacks.",
                    "cwe": "CWE-1021",
                },
                {
                    "header": "x-frame-options",
                    "name": "Missing X-Frame-Options",
                    "severity": "medium",
                    "type": "misconfig",
                    "description": "X-Frame-Options not set. The site may be vulnerable to clickjacking attacks.",
                    "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
                    "cwe": "CWE-1021",
                },
                {
                    "header": "x-content-type-options",
                    "name": "Missing X-Content-Type-Options",
                    "severity": "low",
                    "type": "misconfig",
                    "description": "X-Content-Type-Options: nosniff is not set. MIME sniffing attacks possible.",
                    "remediation": "Add: X-Content-Type-Options: nosniff",
                    "cwe": "CWE-116",
                },
                {
                    "header": "referrer-policy",
                    "name": "Missing Referrer-Policy",
                    "severity": "low",
                    "type": "misconfig",
                    "description": "Referrer-Policy not set. Sensitive URLs may be leaked via referrer header.",
                    "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
                    "cwe": "CWE-200",
                },
                {
                    "header": "permissions-policy",
                    "name": "Missing Permissions-Policy",
                    "severity": "low",
                    "type": "misconfig",
                    "description": "Permissions-Policy not configured. Browser features not restricted.",
                    "remediation": "Add Permissions-Policy to restrict access to browser features like camera, microphone, etc.",
                    "cwe": "CWE-693",
                },
            ]

            for check in checks:
                if check["header"] not in headers:
                    findings.append({
                        "name": check["name"],
                        "type": check["type"],
                        "severity": check["severity"],
                        "cvss_score": {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}.get(check["severity"], 3.0),
                        "affected_url": url,
                        "affected_param": check["header"],
                        "description": check["description"],
                        "evidence": f"Header '{check['header']}' not present in response",
                        "remediation": check["remediation"],
                        "cwe_ids": [check["cwe"]],
                        "tool": "vulnmind-headers",
                    })

            # Check for information disclosure in headers
            info_headers = ["x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version"]
            for h in info_headers:
                if h in headers and headers[h]:
                    findings.append({
                        "name": f"Server Information Disclosure ({h})",
                        "type": "disclosure",
                        "severity": "low",
                        "cvss_score": 2.0,
                        "affected_url": url,
                        "affected_param": h,
                        "description": f"Server reveals technology information via {h} header.",
                        "evidence": f"{h}: {headers[h]}",
                        "remediation": f"Remove or obfuscate the {h} response header.",
                        "cwe_ids": ["CWE-200"],
                        "tool": "vulnmind-headers",
                    })

        except requests.exceptions.SSLError:
            findings.append({
                "name": "SSL Certificate Error",
                "type": "ssl",
                "severity": "high",
                "cvss_score": 7.0,
                "affected_url": url,
                "description": "SSL certificate is invalid or untrusted.",
                "remediation": "Install a valid SSL certificate from a trusted CA.",
                "tool": "vulnmind-ssl",
            })
        except Exception as e:
            console.print(f"  [dim]Header check error: {e}[/dim]")

        return findings

    def _check_ssl(self) -> List[Dict]:
        """Check SSL/TLS configuration."""
        findings = []
        host = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        if tool_available("openssl"):
            try:
                # Check for weak protocols
                for proto in ["ssl2", "ssl3", "tls1", "tls1_1"]:
                    result = subprocess.run(
                        ["openssl", "s_client", f"-{proto}", "-connect", f"{host}:443"],
                        capture_output=True, text=True, timeout=10,
                        input=""
                    )
                    if "Cipher" in result.stdout and "error" not in result.stdout.lower():
                        proto_name = proto.replace("tls", "TLS ").replace("ssl", "SSL ")
                        findings.append({
                            "name": f"Weak Protocol Supported: {proto_name}",
                            "type": "ssl",
                            "severity": "high" if proto in ["ssl2", "ssl3"] else "medium",
                            "cvss_score": 7.0 if proto in ["ssl2", "ssl3"] else 5.0,
                            "affected_url": f"https://{host}",
                            "description": f"Server supports {proto_name} which is deprecated and insecure.",
                            "remediation": f"Disable {proto_name} in server configuration. Use TLS 1.2+ only.",
                            "cwe_ids": ["CWE-326"],
                            "tool": "openssl",
                        })
            except Exception:
                pass

        return findings

    def _common_vuln_checks(self) -> List[Dict]:
        """Common web vulnerability checks."""
        findings = []
        base_url = f"https://{self.target}" if not self.target.startswith("http") else self.target

        # Check for common sensitive files
        sensitive_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.env",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/config.php",
            "/database.php",
            "/.DS_Store",
            "/backup.zip",
            "/admin/",
            "/phpmyadmin/",
            "/server-status",
            "/server-info",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
        ]

        for path in sensitive_paths:
            try:
                r = requests.get(
                    f"{base_url}{path}",
                    timeout=5,
                    allow_redirects=False,
                    headers={"User-Agent": "VulnMind/1.0"}
                )
                if r.status_code == 200 and len(r.content) > 0:
                    severity = "critical" if path in ["/.git/config", "/.env", "/wp-config.php.bak"] else "medium"
                    severity = "info" if path in ["/robots.txt", "/sitemap.xml"] else severity

                    finding = {
                        "name": f"Sensitive File Exposed: {path}",
                        "type": "disclosure",
                        "severity": severity,
                        "cvss_score": {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 0.0}.get(severity, 3.0),
                        "affected_url": f"{base_url}{path}",
                        "description": f"Sensitive file {path} is publicly accessible.",
                        "evidence": f"HTTP {r.status_code}, Content-Length: {len(r.content)}",
                        "remediation": f"Restrict access to {path} or remove it from the web root.",
                        "cwe_ids": ["CWE-538"],
                        "tool": "vulnmind-files",
                    }
                    if path == "/.git/config":
                        finding["description"] += " Git repository may be exposed, leaking source code."
                    elif path == "/.env":
                        finding["description"] += " Environment file may contain API keys, passwords, and database credentials."

                    findings.append(finding)
            except Exception:
                pass

        # Check for open redirect
        redirect_payloads = [
            "//evil.com", "//evil.com/%2F..", "https://evil.com",
        ]
        redirect_params = ["url", "redirect", "next", "return", "returnurl", "goto", "location"]

        for param in redirect_params[:3]:  # limit checks
            for payload in redirect_payloads[:1]:
                try:
                    r = requests.get(
                        f"{base_url}?{param}={payload}",
                        timeout=5,
                        allow_redirects=False,
                        headers={"User-Agent": "VulnMind/1.0"}
                    )
                    if r.status_code in [301, 302, 303, 307, 308]:
                        location = r.headers.get("Location", "")
                        if "evil.com" in location or payload in location:
                            findings.append({
                                "name": "Open Redirect Vulnerability",
                                "type": "open_redirect",
                                "severity": "medium",
                                "cvss_score": 5.4,
                                "affected_url": f"{base_url}?{param}={payload}",
                                "affected_param": param,
                                "description": "Application redirects to attacker-controlled URL via user input.",
                                "evidence": f"Redirect to: {location}",
                                "remediation": "Validate redirect URLs against an allowlist. Reject external redirects.",
                                "cwe_ids": ["CWE-601"],
                                "tool": "vulnmind-redirect",
                            })
                except Exception:
                    pass

        return findings

    def _nuclei_scan(self, scan_level: str) -> List[Dict]:
        """Run nuclei templates."""
        console.print("  [dim]→ Running nuclei templates...[/dim]")
        findings = []

        severity_map = {
            "quick": ["-severity", "critical,high"],
            "standard": ["-severity", "critical,high,medium"],
            "deep": [],  # all severities
        }

        url = f"https://{self.target}" if not self.target.startswith("http") else self.target

        try:
            cmd = [
                "nuclei", "-u", url,
                "-silent", "-json",
                "-timeout", "10",
                "-rate-limit", "50",
            ] + severity_map.get(scan_level, ["-severity", "critical,high,medium"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    findings.append({
                        "name": info.get("name", "Unknown"),
                        "type": info.get("tags", ["unknown"])[0] if info.get("tags") else "unknown",
                        "severity": info.get("severity", "info").lower(),
                        "cvss_score": info.get("classification", {}).get("cvss-score", 0.0),
                        "affected_url": data.get("matched-at", url),
                        "description": info.get("description", ""),
                        "evidence": str(data.get("extracted-results", "")),
                        "remediation": info.get("remediation", ""),
                        "cve_ids": info.get("classification", {}).get("cve-id", []),
                        "cwe_ids": info.get("classification", {}).get("cwe-id", []),
                        "tool": "nuclei",
                        "template_id": data.get("template-id", ""),
                    })
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            console.print("  [yellow]nuclei timeout[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]nuclei error: {e}[/yellow]")

        return findings

    def _nikto_scan(self) -> List[Dict]:
        """Run nikto web scanner."""
        console.print("  [dim]→ Running nikto...[/dim]")
        findings = []

        try:
            result = subprocess.run(
                ["nikto", "-h", self.target, "-Format", "json", "-output", "/tmp/nikto_output.json",
                 "-Tuning", "x", "-maxtime", "120"],
                capture_output=True, text=True, timeout=180
            )

            try:
                import json as _json
                with open("/tmp/nikto_output.json") as f:
                    data = _json.load(f)

                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "name": vuln.get("msg", "Nikto Finding")[:100],
                        "type": "misconfig",
                        "severity": "medium",
                        "cvss_score": 5.0,
                        "affected_url": vuln.get("url", self.target),
                        "description": vuln.get("msg", ""),
                        "evidence": "",
                        "remediation": "Review and remediate the identified configuration issue.",
                        "tool": "nikto",
                    })
            except Exception:
                # Parse text output
                for line in result.stdout.split("\n"):
                    if "+ " in line and "OSVDB" in line or "+ " in line and "X-" in line:
                        findings.append({
                            "name": line.strip()[:100],
                            "type": "misconfig",
                            "severity": "low",
                            "cvss_score": 3.0,
                            "affected_url": self.target,
                            "description": line.strip(),
                            "tool": "nikto",
                        })

        except Exception as e:
            console.print(f"  [yellow]nikto error: {e}[/yellow]")

        return findings

    def _sqlmap_scan(self) -> List[Dict]:
        """Basic SQLMap check."""
        console.print("  [dim]→ Running sqlmap (basic check)...[/dim]")
        # Note: We run in non-destructive mode only
        findings = []
        try:
            result = subprocess.run(
                ["sqlmap", "-u", f"https://{self.target}/?id=1",
                 "--batch", "--level=1", "--risk=1",
                 "--technique=B", "--output-dir=/tmp/sqlmap_out",
                 "--forms", "--crawl=1"],
                capture_output=True, text=True, timeout=120
            )
            if "is vulnerable" in result.stdout.lower():
                findings.append({
                    "name": "SQL Injection Vulnerability Detected",
                    "type": "sqli",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "affected_url": f"https://{self.target}",
                    "description": "SQLMap detected SQL injection vulnerability.",
                    "evidence": "SQLMap confirmed injectable parameter",
                    "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    "cwe_ids": ["CWE-89"],
                    "cve_ids": [],
                    "tool": "sqlmap",
                })
        except Exception as e:
            console.print(f"  [yellow]sqlmap error: {e}[/yellow]")
        return findings

    def _dalfox_scan(self) -> List[Dict]:
        """DalFox XSS scanner."""
        console.print("  [dim]→ Running dalfox...[/dim]")
        findings = []
        try:
            result = subprocess.run(
                ["dalfox", "url", f"https://{self.target}",
                 "--silence", "--format", "json", "--timeout", "30"],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        if data.get("type") == "G" or "xss" in str(data).lower():
                            findings.append({
                                "name": "Cross-Site Scripting (XSS)",
                                "type": "xss",
                                "severity": "high",
                                "cvss_score": 7.4,
                                "affected_url": data.get("param_url", self.target),
                                "affected_param": data.get("param", ""),
                                "description": "Reflected XSS vulnerability found.",
                                "evidence": data.get("evidence", ""),
                                "remediation": "Encode all user output. Implement CSP. Use HttpOnly cookies.",
                                "cwe_ids": ["CWE-79"],
                                "tool": "dalfox",
                            })
                    except Exception:
                        pass
        except Exception as e:
            console.print(f"  [yellow]dalfox error: {e}[/yellow]")
        return findings

    def display_results(self):
        """Display vulnerability findings."""
        if not self.findings:
            console.print("[green]No vulnerabilities found.[/green]")
            return

        # Summary
        severity_order = ["critical", "high", "medium", "low", "info"]
        counts = {}
        for f in self.findings:
            s = f.get("severity", "info").lower()
            counts[s] = counts.get(s, 0) + 1

        console.print(f"\n[bold]Vulnerability Summary:[/bold]")
        for sev in severity_order:
            if counts.get(sev, 0) > 0:
                color = self.SEVERITY_COLORS.get(sev, "white")
                console.print(f"  [{color}]{sev.upper():10}[/{color}]: {counts[sev]}")

        console.print()

        # Table
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Name", style="white", width=40)
        table.add_column("Type", width=15)
        table.add_column("Tool", width=12)

        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.index(x.get("severity", "info").lower())
            if x.get("severity", "info").lower() in severity_order else 99
        )

        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").lower()
            color = self.SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                str(i),
                f"[{color}]{sev.upper()}[/{color}]",
                f.get("name", "Unknown")[:40],
                f.get("type", "unknown"),
                f.get("tool", "—"),
            )

        console.print(table)
