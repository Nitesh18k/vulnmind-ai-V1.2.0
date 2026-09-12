"""
VulnMind AI - Port Scanner Module
Integrates: nmap (primary), naabu, masscan + Python socket fallback
"""

import subprocess
import socket
import shutil
import json
import re
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017, 6443, 2379, 10250
]

SERVICE_SIGNATURES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    6443: "Kubernetes", 2379: "etcd", 10250: "Kubelet"
}


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


class PortScanner:
    """Port scanning orchestrator."""

    def __init__(self, target: str):
        self.target = target
        self.results: List[Dict] = []

    def scan(self, scan_type: str = "common") -> List[Dict]:
        """
        Run port scan.
        scan_type: common | full | quick
        """
        if tool_available("nmap"):
            return self._nmap_scan(scan_type)
        elif tool_available("naabu"):
            return self._naabu_scan(scan_type)
        else:
            return self._python_scan(scan_type)

    def _nmap_scan(self, scan_type: str) -> List[Dict]:
        """Nmap-based scan with service/OS detection."""
        console.print("  [dim]→ Using nmap for port scanning...[/dim]")

        if scan_type == "quick":
            ports_arg = "21,22,80,443,8080,8443,3306,3389,5432"
            extra = ["-sV", "--version-intensity", "5"]
        elif scan_type == "full":
            ports_arg = "1-65535"
            extra = ["-sV", "-O", "--version-intensity", "7"]
        else:  # common
            ports_arg = ",".join(str(p) for p in COMMON_PORTS)
            extra = ["-sV", "-sC", "--version-intensity", "6"]

        cmd = [
            "nmap", "-p", ports_arg,
            "--open", "-T4",
            "-oX", "-",  # XML output to stdout
            self.target
        ] + extra

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            console.print("  [yellow]nmap timeout - trying quick scan...[/yellow]")
            return self._python_scan("quick")
        except Exception as e:
            console.print(f"  [yellow]nmap error: {e}[/yellow]")
            return self._python_scan(scan_type)

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """Parse nmap XML output."""
        ports = []
        try:
            # Simple regex-based XML parsing (avoid lxml dependency)
            port_blocks = re.findall(
                r'<port protocol="([^"]+)" portid="(\d+)">(.*?)</port>',
                xml_output, re.DOTALL
            )

            for protocol, portid, content in port_blocks:
                state_match = re.search(r'<state state="([^"]+)"', content)
                state = state_match.group(1) if state_match else "unknown"

                if state != "open":
                    continue

                service_match = re.search(
                    r'<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?[^>]*(?:extrainfo="([^"]*)")?',
                    content
                )
                service_name = ""
                product = ""
                version = ""
                extra_info = ""

                if service_match:
                    service_name = service_match.group(1) or ""
                    product = service_match.group(2) or ""
                    version = service_match.group(3) or ""
                    extra_info = service_match.group(4) or ""

                scripts = re.findall(r'<script id="([^"]+)" output="([^"]*)"', content)

                port_info = {
                    "port": int(portid),
                    "protocol": protocol,
                    "state": state,
                    "service": service_name or SERVICE_SIGNATURES.get(int(portid), "unknown"),
                    "product": product,
                    "version": version,
                    "extra_info": extra_info,
                    "scripts": {s[0]: s[1] for s in scripts},
                }

                # Check for vulnerabilities in script output
                vuln_info = []
                for script_id, output in scripts:
                    if "VULNERABLE" in output.upper() or "CVE" in output:
                        vuln_info.append(f"{script_id}: {output[:200]}")
                if vuln_info:
                    port_info["potential_vulns"] = vuln_info

                ports.append(port_info)

        except Exception as e:
            console.print(f"  [yellow]XML parse error: {e}[/yellow]")

        # Also extract OS detection
        os_match = re.search(r'<osmatch name="([^"]+)" accuracy="(\d+)"', xml_output)
        if os_match and ports:
            # Store OS info in first port entry's extra field
            pass

        self.results = ports
        return ports

    def _naabu_scan(self, scan_type: str) -> List[Dict]:
        """Naabu-based scan."""
        console.print("  [dim]→ Using naabu for port scanning...[/dim]")
        ports_arg = ",".join(str(p) for p in COMMON_PORTS)

        try:
            result = subprocess.run(
                ["naabu", "-host", self.target, "-p", ports_arg, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            ports = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    _, port_str = line.rsplit(":", 1)
                    try:
                        port = int(port_str)
                        ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": SERVICE_SIGNATURES.get(port, "unknown"),
                            "product": "",
                            "version": "",
                        })
                    except ValueError:
                        pass
            self.results = ports
            return ports
        except Exception as e:
            console.print(f"  [yellow]naabu error: {e}[/yellow]")
            return self._python_scan(scan_type)

    def _python_scan(self, scan_type: str) -> List[Dict]:
        """Pure Python socket-based scanner (fallback)."""
        console.print("  [dim]→ Using Python socket scanner (fallback)...[/dim]")

        ports_to_scan = COMMON_PORTS if scan_type != "quick" else COMMON_PORTS[:15]
        open_ports = []

        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as prog:
            task = prog.add_task("[cyan]Scanning ports...", total=len(ports_to_scan))

            for port in ports_to_scan:
                prog.advance(task)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()

                    if result == 0:
                        # Try banner grab
                        banner = ""
                        try:
                            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s2.settimeout(2)
                            s2.connect((ip, port))
                            if port in [80, 8080, 8443, 443]:
                                s2.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = s2.recv(256).decode("utf-8", errors="ignore")
                            s2.close()
                        except Exception:
                            pass

                        open_ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": SERVICE_SIGNATURES.get(port, "unknown"),
                            "product": "",
                            "version": banner[:100].strip() if banner else "",
                            "banner": banner[:200],
                        })
                except Exception:
                    pass

        self.results = open_ports
        return open_ports

    def display_results(self):
        """Display port scan results."""
        if not self.results:
            console.print("[yellow]No open ports found.[/yellow]")
            return

        console.print(f"\n[bold green]Open Ports:[/bold green] [cyan]{len(self.results)}[/cyan]")

        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Protocol", width=10)
        table.add_column("Service", style="green", width=15)
        table.add_column("Product/Version", style="white")
        table.add_column("Risk", width=10)

        risky_services = {
            21: "medium", 23: "high", 111: "medium", 135: "medium",
            139: "high", 445: "high", 1723: "medium", 3389: "high",
            5900: "high", 6379: "high", 9200: "high", 27017: "high",
        }

        for p in sorted(self.results, key=lambda x: x["port"]):
            port = p["port"]
            risk = risky_services.get(port, "low")
            risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
            risk_str = f"[{risk_colors.get(risk, 'white')}]{risk.upper()}[/{risk_colors.get(risk, 'white')}]"

            version_str = " ".join(filter(None, [p.get("product", ""), p.get("version", "")]))

            table.add_row(
                str(port),
                p.get("protocol", "tcp"),
                p.get("service", "unknown"),
                version_str[:50] or "—",
                risk_str,
            )

        console.print(table)

        # Highlight risky findings
        risky = [p for p in self.results if p["port"] in risky_services]
        if risky:
            console.print(f"\n[bold red]⚠  High-Risk Services Found:[/bold red]")
            for p in risky:
                console.print(f"  [red]•[/red] Port {p['port']}/{p.get('service', '?')} — "
                              f"potentially exploitable")
