"""
VulnMind AI - Reconnaissance Engine
Integrates: subfinder, amass, assetfinder + Python fallbacks
"""

import subprocess
import socket
import json
import re
import shutil
import requests
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

console = Console()


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


class ReconEngine:
    """Main reconnaissance orchestrator."""

    def __init__(self, target: str):
        self.target = target.strip()
        self.subdomains: List[str] = []
        self.ips: List[str] = []
        self.whois_data: dict = {}
        self.dns_records: dict = {}
        self.technologies: list = []

    def run_full_recon(self, progress_callback=None) -> dict:
        """Run all recon modules and return combined results."""
        results = {}

        steps = [
            ("DNS Resolution", self._dns_resolve),
            ("Subdomain Discovery", self._discover_subdomains),
            ("WHOIS Lookup", self._whois_lookup),
            ("HTTP Probe", self._http_probe),
            ("Technology Detection", self._detect_tech),
        ]

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as prog:
            task = prog.add_task("[cyan]Running Recon...", total=len(steps))

            for step_name, step_fn in steps:
                prog.update(task, description=f"[cyan]{step_name}...")
                try:
                    step_result = step_fn()
                    results[step_name.lower().replace(" ", "_")] = step_result
                except Exception as e:
                    results[step_name.lower().replace(" ", "_")] = {"error": str(e)}
                    console.print(f"[yellow]  ⚠ {step_name} error: {e}[/yellow]")
                prog.advance(task)

        results["subdomains"] = list(set(self.subdomains))
        results["ips"] = list(set(self.ips))
        results["target"] = self.target
        return results

    def _dns_resolve(self) -> dict:
        """Basic DNS resolution."""
        records = {}
        try:
            ip = socket.gethostbyname(self.target)
            self.ips.append(ip)
            records["A"] = [ip]

            # Try reverse DNS
            try:
                host = socket.gethostbyaddr(ip)[0]
                records["PTR"] = [host]
            except Exception:
                pass

            self.dns_records = records
            return records
        except socket.gaierror:
            return {"error": f"Could not resolve {self.target}"}

    def _discover_subdomains(self) -> dict:
        """Discover subdomains using available tools + crt.sh."""
        found = set()

        # 1. crt.sh (no tool needed)
        console.print("  [dim]→ Querying crt.sh...[/dim]")
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(self.target) and sub != self.target:
                            found.add(sub)
        except Exception as e:
            console.print(f"  [dim]crt.sh error: {e}[/dim]")

        # 2. HackerTarget API
        console.print("  [dim]→ Querying HackerTarget...[/dim]")
        try:
            r = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
                timeout=10,
            )
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(self.target):
                            found.add(sub)
                            ip = line.split(",")[1].strip()
                            if ip:
                                self.ips.append(ip)
        except Exception:
            pass

        # 3. Subfinder (if available)
        if tool_available("subfinder"):
            console.print("  [dim]→ Running subfinder...[/dim]")
            try:
                result = subprocess.run(
                    ["subfinder", "-d", self.target, "-silent", "-all"],
                    capture_output=True, text=True, timeout=60
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and line.endswith(self.target):
                        found.add(line)
            except subprocess.TimeoutExpired:
                console.print("  [dim]subfinder timeout[/dim]")
            except Exception as e:
                console.print(f"  [dim]subfinder error: {e}[/dim]")

        # 4. Amass (if available)
        if tool_available("amass"):
            console.print("  [dim]→ Running amass...[/dim]")
            try:
                result = subprocess.run(
                    ["amass", "enum", "-passive", "-d", self.target, "-timeout", "30"],
                    capture_output=True, text=True, timeout=90
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and line.endswith(self.target):
                        found.add(line)
            except Exception:
                pass

        # 5. Assetfinder (if available)
        if tool_available("assetfinder"):
            console.print("  [dim]→ Running assetfinder...[/dim]")
            try:
                result = subprocess.run(
                    ["assetfinder", "--subs-only", self.target],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and line.endswith(self.target):
                        found.add(line)
            except Exception:
                pass

        # Resolve IPs for found subdomains
        for sub in list(found)[:20]:  # limit to avoid flooding
            try:
                ip = socket.gethostbyname(sub)
                self.ips.append(ip)
            except Exception:
                pass

        self.subdomains = list(found)
        return {
            "count": len(found),
            "subdomains": list(found),
            "tools_used": [
                t for t in ["crt.sh", "hackertarget", "subfinder", "amass", "assetfinder"]
                if True  # simplified
            ]
        }

    def _whois_lookup(self) -> dict:
        """WHOIS lookup using whois tool or API."""
        data = {}

        if tool_available("whois"):
            try:
                result = subprocess.run(
                    ["whois", self.target],
                    capture_output=True, text=True, timeout=20
                )
                output = result.stdout
                # Parse key fields
                for line in output.split("\n"):
                    line = line.strip()
                    for field in ["Registrar:", "Creation Date:", "Registry Expiry Date:",
                                  "Registrant Organization:", "Name Server:", "DNSSEC:"]:
                        if line.startswith(field):
                            key = field.rstrip(":")
                            val = line[len(field):].strip()
                            if key in data:
                                if isinstance(data[key], list):
                                    data[key].append(val)
                                else:
                                    data[key] = [data[key], val]
                            else:
                                data[key] = val
                data["raw_length"] = len(output)
            except Exception as e:
                data["error"] = str(e)
        else:
            try:
                r = requests.get(
                    f"https://api.hackertarget.com/whois/?q={self.target}",
                    timeout=10
                )
                data["raw"] = r.text[:500]
            except Exception:
                data["note"] = "whois tool not found, install with: apt install whois"

        return data

    def _http_probe(self) -> dict:
        """Probe HTTP/HTTPS endpoints."""
        results = {}
        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            try:
                r = requests.get(url, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": "VulnMind/1.0"})
                results[scheme] = {
                    "status": r.status_code,
                    "title": self._extract_title(r.text),
                    "server": r.headers.get("Server", ""),
                    "x_powered_by": r.headers.get("X-Powered-By", ""),
                    "content_type": r.headers.get("Content-Type", ""),
                    "final_url": str(r.url),
                    "security_headers": self._check_security_headers(r.headers),
                }
            except Exception as e:
                results[scheme] = {"error": str(e)}
        return results

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""

    def _check_security_headers(self, headers) -> dict:
        """Check for missing security headers."""
        important = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        return {h: headers.get(h, "MISSING") for h in important}

    def _detect_tech(self) -> dict:
        """Basic technology detection from HTTP response."""
        tech = []
        try:
            r = requests.get(
                f"https://{self.target}", timeout=10,
                headers={"User-Agent": "VulnMind/1.0"}
            )
            html = r.text.lower()
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Tech fingerprints
            fingerprints = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Drupal": ["drupal.js", "sites/all", "drupal"],
                "Joomla": ["joomla", "option=com_"],
                "React": ["react", "__react"],
                "Angular": ["ng-version", "angular"],
                "Vue.js": ["vue", "__vue__"],
                "PHP": [".php", "x-powered-by: php"],
                "ASP.NET": ["asp.net", "x-aspnet"],
                "Node.js": ["x-powered-by: express"],
                "Nginx": ["nginx"],
                "Apache": ["apache"],
                "CloudFlare": ["cf-ray", "cloudflare"],
                "Bootstrap": ["bootstrap"],
                "jQuery": ["jquery"],
            }

            for tech_name, patterns in fingerprints.items():
                for p in patterns:
                    if p in html or p in str(headers).lower():
                        tech.append(tech_name)
                        break

            self.technologies = list(set(tech))
        except Exception:
            pass

        return {"detected": list(set(tech))}

    def display_results(self, results: dict):
        """Display recon results in rich tables."""
        console.print()
        console.print(Panel(
            f"[bold cyan]Recon Results: {self.target}[/bold cyan]",
            border_style="cyan"
        ))

        # DNS
        if "dns_resolution" in results and "A" in results.get("dns_resolution", {}):
            console.print(f"\n[bold green]IP Addresses:[/bold green]")
            for ip in results["dns_resolution"].get("A", []):
                console.print(f"  → {ip}")

        # Subdomains
        subs = results.get("subdomain_discovery", {}).get("subdomains", [])
        if subs:
            console.print(f"\n[bold green]Subdomains Found:[/bold green] [cyan]{len(subs)}[/cyan]")
            table = Table(show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("#", style="dim", width=5)
            table.add_column("Subdomain", style="cyan")
            for i, sub in enumerate(subs[:30], 1):
                table.add_row(str(i), sub)
            if len(subs) > 30:
                table.add_row("...", f"... and {len(subs)-30} more")
            console.print(table)

        # HTTP Probe
        http_data = results.get("http_probe", {})
        if http_data:
            console.print(f"\n[bold green]HTTP Probe:[/bold green]")
            for scheme, data in http_data.items():
                if "error" not in data:
                    status_color = "green" if data.get("status") == 200 else "yellow"
                    console.print(f"  [{status_color}]{scheme.upper()}[/{status_color}] "
                                  f"Status: {data.get('status')} | "
                                  f"Title: {data.get('title', 'N/A')} | "
                                  f"Server: {data.get('server', 'Unknown')}")

        # Technologies
        tech_data = results.get("technology_detection", {})
        if tech_data.get("detected"):
            console.print(f"\n[bold green]Technologies:[/bold green] "
                          f"{', '.join(tech_data['detected'])}")

        # Security Headers
        http_data = results.get("http_probe", {})
        https_data = http_data.get("https", http_data.get("http", {}))
        sec_headers = https_data.get("security_headers", {})
        if sec_headers:
            missing = [h for h, v in sec_headers.items() if v == "MISSING"]
            if missing:
                console.print(f"\n[bold red]Missing Security Headers:[/bold red]")
                for h in missing:
                    console.print(f"  [red]✗[/red] {h}")
