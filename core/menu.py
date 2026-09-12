"""
VulnMind AI - Interactive Menu System
Main navigation hub for the CLI platform
"""

import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule
from rich.text import Text

console = Console()


class InteractiveMenu:
    """Main interactive CLI menu."""

    def __init__(self):
        from database.models import init_db
        init_db()
        self.user = None

    def run(self):
        """Main entry point."""
        # Auth check
        from core.auth import AuthManager, get_current_user
        self.auth = AuthManager()

        # Check existing session
        self.user = get_current_user()

        if not self.user:
            self._auth_menu()

        if not self.user:
            return

        self._main_menu()

    def _auth_menu(self):
        """Login/Register menu."""
        while not self.user:
            console.print(Panel(
                "[1] Login\n[2] Register\n[3] Exit",
                title="[bold cyan]Authentication[/bold cyan]",
                border_style="cyan",
                padding=(1, 4),
            ))
            choice = Prompt.ask("Choice", choices=["1", "2", "3"])

            if choice == "1":
                self.user = self.auth.login_prompt()
            elif choice == "2":
                self.auth.register_prompt()
            elif choice == "3":
                raise SystemExit(0)

    def _main_menu(self):
        """Main navigation menu."""
        while True:
            console.print()
            console.print(Rule(f"[bold cyan]VulnMind AI[/bold cyan] [dim]— {self.user.username} [{self.user.role}][/dim]"))
            console.print()

            menu_items = [
                Panel("[bold cyan][1][/bold cyan]\n📊 Dashboard", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][2][/bold cyan]\n🎯 Targets", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][3][/bold cyan]\n🔍 New Scan", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][4][/bold cyan]\n📁 Scan History", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][5][/bold cyan]\n🐛 Vulnerabilities", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][6][/bold cyan]\n📄 Reports", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][7][/bold cyan]\n🤖 AI Settings", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][8][/bold cyan]\n👤 Profile", border_style="dim", padding=(0, 2)),
                Panel("[bold cyan][9][/bold cyan]\n🛠  Tools Check", border_style="dim", padding=(0, 2)),
                Panel("[bold red][0][/bold red]\n🚪 Exit", border_style="dim", padding=(0, 2)),
            ]

            console.print(Columns(menu_items, equal=True, expand=True))
            console.print()

            choice = Prompt.ask("[bold]Select[/bold]",
                                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])

            if choice == "0":
                if Confirm.ask("[yellow]Exit VulnMind AI?[/yellow]"):
                    console.print("\n[bold cyan]Goodbye. Stay secure.[/bold cyan]\n")
                    raise SystemExit(0)

            elif choice == "1":
                from core.dashboard import show_dashboard
                show_dashboard(self.user)
                Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

            elif choice == "2":
                self._targets_menu()

            elif choice == "3":
                from core.scanner import ScanOrchestrator
                orchestrator = ScanOrchestrator(self.user)
                orchestrator.new_scan_wizard()
                Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

            elif choice == "4":
                self._scan_history_menu()

            elif choice == "5":
                self._vulnerabilities_menu()

            elif choice == "6":
                self._reports_menu()

            elif choice == "7":
                self._ai_settings_menu()

            elif choice == "8":
                self._profile_menu()

            elif choice == "9":
                self._tools_check()
                Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

    # ─── Targets Menu ────────────────────────────────────────────────────────

    def _targets_menu(self):
        """Target management menu."""
        while True:
            console.print()
            console.print(Panel("[bold cyan]Target Management[/bold cyan]", border_style="cyan"))

            from core.dashboard import show_target_list
            show_target_list(self.user)

            console.print()
            console.print("[1] Add Target  [2] Delete Target  [3] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3"])

            if choice == "3":
                break

            elif choice == "1":
                self._add_target()

            elif choice == "2":
                self._delete_target()

    def _add_target(self):
        """Add a new target."""
        from database.models import get_session, Target

        console.print()
        name = Prompt.ask("Target (domain/IP/URL/subdomain)").strip()
        if not name:
            return

        # Clean up
        clean = name.replace("https://", "").replace("http://", "").rstrip("/")

        console.print("Type: [1] Domain  [2] IP  [3] URL  [4] Subdomain")
        type_choice = Prompt.ask("Type", choices=["1", "2", "3", "4"], default="1")
        type_map = {"1": "domain", "2": "ip", "3": "url", "4": "subdomain"}
        target_type = type_map[type_choice]

        description = Prompt.ask("Description (optional)", default="")
        tags = Prompt.ask("Tags (comma-separated, optional)", default="")

        db = get_session()
        # Check duplicate
        existing = db.query(Target).filter_by(user_id=self.user.id, name=clean).first()
        if existing:
            console.print(f"[yellow]Target '{clean}' already exists.[/yellow]")
            db.close()
            return

        t = Target(
            user_id=self.user.id,
            name=clean,
            target_type=target_type,
            description=description,
            tags=tags,
        )
        db.add(t)
        db.commit()
        db.close()
        console.print(f"[green]✓ Target '{clean}' added.[/green]")

    def _delete_target(self):
        """Delete a target."""
        from database.models import get_session, Target

        target_id = Prompt.ask("Target ID to delete")
        if not target_id.isdigit():
            return

        db = get_session()
        t = db.query(Target).filter_by(id=int(target_id), user_id=self.user.id).first()
        if not t:
            console.print("[red]Target not found.[/red]")
            db.close()
            return

        if Confirm.ask(f"[red]Delete target '{t.name}'?[/red]"):
            db.delete(t)
            db.commit()
            console.print(f"[yellow]Target deleted.[/yellow]")
        db.close()

    # ─── Scan History Menu ───────────────────────────────────────────────────

    def _scan_history_menu(self):
        """View and manage scan history."""
        from database.models import get_session, Scan, Target, Vulnerability

        while True:
            db = get_session()
            scans = (
                db.query(Scan)
                .filter_by(user_id=self.user.id)
                .order_by(Scan.started_at.desc())
                .limit(20)
                .all()
            )
            db.close()

            console.print()
            console.print(Panel("[bold cyan]Scan History[/bold cyan]", border_style="cyan"))

            if not scans:
                console.print("[yellow]No scans yet.[/yellow]")
                Prompt.ask("\n[dim]Press Enter[/dim]", default="")
                return

            table = Table(show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("ID", style="dim", width=5)
            table.add_column("Target", style="cyan", width=28)
            table.add_column("Type", width=14)
            table.add_column("Status", width=12)
            table.add_column("Risk", width=12, justify="center")
            table.add_column("Progress", width=10, justify="center")
            table.add_column("Date", width=18)

            status_colors = {"done": "green", "running": "yellow", "failed": "red", "pending": "dim"}
            level_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}

            for scan in scans:
                db = get_session()
                target = db.query(Target).filter_by(id=scan.target_id).first()
                db.close()

                sc = status_colors.get(scan.status, "white")
                risk_score = scan.risk_score or 0
                if risk_score >= 75: rl, rc = "CRITICAL", "red"
                elif risk_score >= 50: rl, rc = "HIGH", "yellow"
                elif risk_score >= 25: rl, rc = "MEDIUM", "blue"
                elif risk_score > 0: rl, rc = "LOW", "green"
                else: rl, rc = "—", "dim"

                table.add_row(
                    str(scan.id),
                    target.name[:26] if target else "—",
                    scan.scan_type or "—",
                    f"[{sc}]{scan.status.upper()}[/{sc}]",
                    f"[{rc}]{rl}[/{rc}]",
                    f"{scan.progress or 0}%",
                    scan.started_at.strftime("%m/%d %H:%M") if scan.started_at else "—",
                )

            console.print(table)
            console.print()
            console.print("[1] View Scan Details  [2] Delete Scan  [3] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3"])

            if choice == "3":
                break

            elif choice == "1":
                scan_id = Prompt.ask("Scan ID")
                if scan_id.isdigit():
                    self._view_scan_detail(int(scan_id))

            elif choice == "2":
                scan_id = Prompt.ask("Scan ID to delete")
                if scan_id.isdigit():
                    db = get_session()
                    s = db.query(Scan).filter_by(id=int(scan_id), user_id=self.user.id).first()
                    if s and Confirm.ask(f"[red]Delete scan #{scan_id}?[/red]"):
                        db.delete(s)
                        db.commit()
                        console.print("[yellow]Scan deleted.[/yellow]")
                    db.close()

    def _view_scan_detail(self, scan_id: int):
        """Show detailed scan results."""
        from database.models import get_session, Scan, Target, Vulnerability, Asset
        from core.dashboard import show_vuln_list

        db = get_session()
        scan = db.query(Scan).filter_by(id=scan_id, user_id=self.user.id).first()
        if not scan:
            console.print("[red]Scan not found.[/red]")
            db.close()
            return

        target = db.query(Target).filter_by(id=scan.target_id).first()
        vuln_count = db.query(Vulnerability).filter_by(scan_id=scan_id).count()
        asset_count = db.query(Asset).filter_by(scan_id=scan_id).count()
        db.close()

        console.print()
        console.print(Panel(
            f"[bold cyan]Scan #{scan_id} Details[/bold cyan]",
            border_style="cyan"
        ))

        info_table = Table(show_header=False, border_style="dim", box=None)
        info_table.add_column("Field", style="bold cyan", width=20)
        info_table.add_column("Value")

        info_table.add_row("Target", target.name if target else "—")
        info_table.add_row("Scan Type", scan.scan_type or "—")
        info_table.add_row("Status", scan.status.upper())
        info_table.add_row("Risk Score", f"{scan.risk_score:.1f}/100" if scan.risk_score else "—")
        info_table.add_row("Vulnerabilities", str(vuln_count))
        info_table.add_row("Assets Found", str(asset_count))
        info_table.add_row("Started", str(scan.started_at))
        info_table.add_row("Finished", str(scan.finished_at) if scan.finished_at else "—")

        console.print(info_table)

        if scan.ai_analysis:
            console.print()
            console.print(Panel(
                scan.ai_analysis[:800] + ("..." if len(scan.ai_analysis) > 800 else ""),
                title="[bold cyan]AI Executive Summary[/bold cyan]",
                border_style="dim",
            ))

        console.print()
        show_vuln_list(self.user, scan_id)
        Prompt.ask("\n[dim]Press Enter[/dim]", default="")

    # ─── Vulnerabilities Menu ────────────────────────────────────────────────

    def _vulnerabilities_menu(self):
        """Browse all vulnerabilities."""
        from core.dashboard import show_vuln_list
        from database.models import get_session, Vulnerability, Scan

        console.print()
        console.print(Panel("[bold cyan]All Vulnerabilities[/bold cyan]", border_style="cyan"))

        # Filter options
        console.print("[1] All Severities  [2] Critical Only  [3] High+  [4] Filter by Scan ID  [5] Back")
        choice = Prompt.ask("Filter", choices=["1", "2", "3", "4", "5"])

        if choice == "5":
            return

        if choice == "4":
            scan_id = Prompt.ask("Scan ID")
            if scan_id.isdigit():
                show_vuln_list(self.user, int(scan_id))
        else:
            db = get_session()
            query = db.query(Vulnerability).join(Scan).filter(Scan.user_id == self.user.id)

            if choice == "2":
                query = query.filter(Vulnerability.severity == "critical")
            elif choice == "3":
                query = query.filter(Vulnerability.severity.in_(["critical", "high"]))

            vulns = query.order_by(Vulnerability.severity).all()
            db.close()

            if not vulns:
                console.print("[yellow]No vulnerabilities found.[/yellow]")
                Prompt.ask("\n[dim]Press Enter[/dim]", default="")
                return

            # Show detail for specific vuln
            show_vuln_list(self.user)

            console.print()
            detail = Prompt.ask("Enter vuln ID for details (or Enter to skip)", default="")
            if detail.isdigit():
                db = get_session()
                v = db.query(Vulnerability).filter_by(id=int(detail)).first()
                if v:
                    self._show_vuln_detail(v)
                db.close()

        Prompt.ask("\n[dim]Press Enter[/dim]", default="")

    def _show_vuln_detail(self, v):
        """Display full vulnerability details."""
        sev_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "cyan", "info": "dim"}
        color = sev_colors.get((v.severity or "info").lower(), "white")

        console.print()
        console.print(Panel(
            f"[{color}]{(v.severity or 'info').upper()}[/{color}] — {v.name}",
            title="[bold cyan]Vulnerability Detail[/bold cyan]",
            border_style="cyan"
        ))

        fields = [
            ("Type", v.vuln_type),
            ("CVSS Score", str(v.cvss_score)),
            ("CVE IDs", ", ".join(json.loads(v.cve_ids or "[]")) or "—"),
            ("CWE IDs", ", ".join(json.loads(v.cwe_ids or "[]")) or "—"),
            ("MITRE ATT&CK", ", ".join(json.loads(v.mitre_attack or "[]")) or "—"),
            ("Affected URL", v.affected_url or "—"),
            ("Affected Parameter", v.affected_param or "—"),
            ("Tool", v.tool or "—"),
            ("Confirmed", "Yes" if v.confirmed else "No"),
        ]

        table = Table(show_header=False, border_style="dim", box=None, padding=(0, 1))
        table.add_column("Field", style="bold cyan", width=22)
        table.add_column("Value")
        for f, val in fields:
            table.add_row(f, val or "—")
        console.print(table)

        if v.description:
            console.print(f"\n[bold cyan]Description:[/bold cyan]\n{v.description}")
        if v.evidence:
            console.print(f"\n[bold cyan]Evidence:[/bold cyan]\n[dim]{v.evidence}[/dim]")
        if v.business_impact:
            console.print(f"\n[bold cyan]Business Impact:[/bold cyan]\n{v.business_impact}")
        if v.remediation:
            console.print(f"\n[bold green]Remediation:[/bold green]\n{v.remediation}")

    # ─── Reports Menu ────────────────────────────────────────────────────────

    def _reports_menu(self):
        """Report management menu."""
        import glob

        reports_dir = os.path.expanduser("~/.vulnmind/reports")
        os.makedirs(reports_dir, exist_ok=True)

        while True:
            console.print()
            console.print(Panel("[bold cyan]Reports[/bold cyan]", border_style="cyan"))

            report_files = sorted(
                glob.glob(os.path.join(reports_dir, "report_*")),
                key=os.path.getmtime,
                reverse=True
            )

            if report_files:
                table = Table(show_header=True, header_style="bold cyan", border_style="dim")
                table.add_column("#", style="dim", width=4)
                table.add_column("Filename", style="cyan", width=55)
                table.add_column("Type", width=8)
                table.add_column("Size", width=10, justify="right")
                table.add_column("Created", width=18)

                for i, fp in enumerate(report_files[:20], 1):
                    fname = os.path.basename(fp)
                    ext = fname.rsplit(".", 1)[-1].upper()
                    size = os.path.getsize(fp)
                    size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/1024/1024:.1f} MB"
                    mtime = os.path.getmtime(fp)
                    import datetime
                    dt = datetime.datetime.fromtimestamp(mtime).strftime("%m/%d %H:%M")
                    table.add_row(str(i), fname[:53], ext, size_str, dt)

                console.print(table)
            else:
                console.print("[yellow]No reports generated yet. Run a scan first.[/yellow]")

            console.print()
            console.print(f"[bold dim]Reports location: {reports_dir}[/bold dim]")
            console.print()
            console.print("[1] Generate Report from Scan  [2] Open Report Location  [3] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3"])

            if choice == "3":
                break

            elif choice == "2":
                console.print(f"[cyan]Reports are in: {reports_dir}[/cyan]")
                console.print("[dim]Open with: xdg-open ~/.vulnmind/reports/[/dim]")

            elif choice == "1":
                scan_id = Prompt.ask("Scan ID to generate report for")
                if scan_id.isdigit():
                    self._generate_report_for_scan(int(scan_id))

        Prompt.ask("\n[dim]Press Enter[/dim]", default="")

    def _generate_report_for_scan(self, scan_id: int):
        """Generate reports for an existing scan."""
        from database.models import get_session, Scan, Target, Vulnerability, Asset

        db = get_session()
        scan = db.query(Scan).filter_by(id=scan_id, user_id=self.user.id).first()
        if not scan:
            console.print("[red]Scan not found.[/red]")
            db.close()
            return

        target = db.query(Target).filter_by(id=scan.target_id).first()
        vulns = db.query(Vulnerability).filter_by(scan_id=scan_id).all()
        assets = db.query(Asset).filter_by(scan_id=scan_id).all()
        db.close()

        ports = [json.loads(a.extra) for a in assets if a.asset_type == "port" and a.extra and a.extra != "{}"]
        subdomains = [a.value for a in assets if a.asset_type == "subdomain"]

        scan_data = {
            "target": target.name if target else "Unknown",
            "scan_type": scan.scan_type or "unknown",
            "subdomains": subdomains,
            "ports": ports,
            "vulnerabilities": [
                {
                    "name": v.name, "type": v.vuln_type, "severity": v.severity,
                    "cvss_score": v.cvss_score or 0, "affected_url": v.affected_url or "",
                    "affected_param": v.affected_param or "", "description": v.description or "",
                    "evidence": v.evidence or "", "remediation": v.remediation or "",
                    "cve_ids": json.loads(v.cve_ids or "[]"),
                    "cwe_ids": json.loads(v.cwe_ids or "[]"),
                    "mitre_attack": json.loads(v.mitre_attack or "[]"),
                    "tool": v.tool or "",
                }
                for v in vulns
            ],
            "ai_analysis": {"executive_summary": scan.ai_analysis or ""},
            "risk": {"score": scan.risk_score or 0,
                     "level": "critical" if (scan.risk_score or 0) >= 75 else
                              "high" if (scan.risk_score or 0) >= 50 else
                              "medium" if (scan.risk_score or 0) >= 25 else "low"},
        }

        from reports.generator import ReportGenerator
        reporter = ReportGenerator(scan_data)
        paths = reporter.generate_all()

        console.print()
        for fmt, path in paths.items():
            console.print(f"  [green]✓[/green] {fmt.upper()}: [cyan]{path}[/cyan]")

    # ─── AI Settings Menu ────────────────────────────────────────────────────

    def _ai_settings_menu(self):
        """AI provider configuration."""
        while True:
            console.print()
            console.print(Panel("[bold cyan]AI Provider Settings[/bold cyan]", border_style="cyan"))

            db_sess = __import__("database.models", fromlist=["get_session"]).get_session()
            from database.models import User as UserModel
            u = db_sess.query(UserModel).filter_by(id=self.user.id).first()
            keys = json.loads(u.api_keys or "{}")
            default_provider = u.default_provider or "not set"
            default_model = u.default_model or "not set"
            db_sess.close()

            console.print(f"[bold]Current Provider:[/bold] [cyan]{default_provider}[/cyan]  "
                          f"[bold]Model:[/bold] [cyan]{default_model}[/cyan]")
            console.print()
            console.print("[1] Configure API Keys  [2] Test Connection  [3] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3"])

            if choice == "3":
                break

            elif choice == "1":
                self.auth.manage_api_keys(self.user)

            elif choice == "2":
                self._test_ai_connection(keys, default_provider, default_model)

    def _test_ai_connection(self, keys: dict, provider: str, model: str):
        """Test AI provider connection."""
        from ai.providers import AIManager

        api_key = keys.get(provider, "")
        if not api_key and provider != "ollama":
            console.print(f"[red]No API key for {provider}. Configure it first.[/red]")
            return

        console.print(f"[dim]Testing {provider} ({model})...[/dim]")
        ok, msg = AIManager.test_provider(provider, api_key, model)
        if ok:
            console.print(f"[green]✓ {msg}[/green]")
        else:
            console.print(f"[red]✗ {msg}[/red]")

    # ─── Profile Menu ────────────────────────────────────────────────────────

    def _profile_menu(self):
        """User profile management."""
        while True:
            console.print()
            console.print(Panel(
                f"[bold cyan]Profile[/bold cyan] — {self.user.username} [{self.user.role}]",
                border_style="cyan"
            ))
            console.print("[1] Change Password  [2] Manage API Keys  [3] Logout  [4] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])

            if choice == "4":
                break
            elif choice == "1":
                self.auth.change_password(self.user)
            elif choice == "2":
                self.auth.manage_api_keys(self.user)
            elif choice == "3":
                self.auth.logout()
                self.user = None
                self._auth_menu()
                break

    # ─── Tools Check ─────────────────────────────────────────────────────────

    # (bin_name, purpose, install method, package/go-path used for that method)
    TOOLS = [
        # Recon
        ("subfinder", "Subdomain Discovery", "go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("amass", "DNS Enumeration", "apt", "amass"),
        ("assetfinder", "Asset Discovery", "go", "github.com/tomnomnom/assetfinder@latest"),
        # Port Scanning
        ("nmap", "Port Scanner", "apt", "nmap"),
        ("naabu", "Fast Port Scanner", "go", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        ("masscan", "Mass Port Scanner", "apt", "masscan"),
        # Web
        ("katana", "Web Crawler", "go", "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("waybackurls", "Historical URLs", "go", "github.com/tomnomnom/waybackurls@latest"),
        # Vuln Scanning
        ("nuclei", "Vuln Templates", "go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("nikto", "Web Scanner", "apt", "nikto"),
        ("sqlmap", "SQL Injection", "apt", "sqlmap"),
        ("dalfox", "XSS Scanner", "go", "github.com/hahwul/dalfox/v2@latest"),
        ("wapiti", "Web App Scanner", "pip", "wapiti3"),
        # Utils
        ("whois", "WHOIS Lookup", "apt", "whois"),
        ("openssl", "SSL Analysis", "apt", "openssl"),
    ]

    def _tools_check(self):
        """Check which security tools are installed, and offer to auto-install the rest."""
        import shutil

        while True:
            console.print()
            console.print(Panel("[bold cyan]Security Tools Status[/bold cyan]", border_style="cyan"))

            table = Table(show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("Tool", style="cyan", width=15)
            table.add_column("Purpose", width=25)
            table.add_column("Status", width=14)
            table.add_column("Install Via", style="dim")

            missing = []
            installed = 0
            for tool, purpose, method, pkg in self.TOOLS:
                found = shutil.which(tool) is not None
                status = "[bold green]✓ Installed[/bold green]" if found else "[red]✗ Missing[/red]"
                if found:
                    installed += 1
                else:
                    missing.append((tool, purpose, method, pkg))
                table.add_row(tool, purpose, status, "" if found else f"{method}: {pkg}")

            console.print(table)
            console.print()
            console.print(f"[bold]Installed:[/bold] [cyan]{installed}/{len(self.TOOLS)}[/cyan] tools")

            if not missing:
                console.print("[bold green]All tools are installed![/bold green]")
                return

            console.print()
            console.print("[1] Auto-Install Missing Tools  [2] Show Manual Install Commands  [3] Back")
            choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="3")

            if choice == "3":
                return
            elif choice == "2":
                self._show_manual_install(missing)
                Prompt.ask("\n[dim]Press Enter[/dim]", default="")
            elif choice == "1":
                self._auto_install_tools(missing)
                Prompt.ask("\n[dim]Press Enter to re-check tools[/dim]", default="")
                # loop back around and re-scan tool status

    def _show_manual_install(self, missing: list):
        """Print manual install commands for the given missing tools."""
        apt_pkgs = [pkg for _, _, m, pkg in missing if m == "apt"]
        pip_pkgs = [pkg for _, _, m, pkg in missing if m == "pip"]
        go_pkgs = [pkg for _, _, m, pkg in missing if m == "go"]

        console.print()
        if apt_pkgs:
            console.print("[bold yellow]Kali/Debian (apt):[/bold yellow]")
            console.print(f"[dim]  sudo apt-get install -y {' '.join(apt_pkgs)}[/dim]")
        if pip_pkgs:
            console.print("[bold yellow]Python (pip):[/bold yellow]")
            console.print(f"[dim]  pip install {' '.join(pip_pkgs)} --break-system-packages[/dim]")
        if go_pkgs:
            console.print("[bold yellow]Go tools (requires Go installed):[/bold yellow]")
            for pkg in go_pkgs:
                console.print(f"[dim]  go install -v {pkg}[/dim]")

    def _auto_install_tools(self, missing: list):
        """Actually download and install the missing tools for the user."""
        import shutil
        import subprocess

        apt_missing = [(t, pkg) for t, _, m, pkg in missing if m == "apt"]
        pip_missing = [(t, pkg) for t, _, m, pkg in missing if m == "pip"]
        go_missing = [(t, pkg) for t, _, m, pkg in missing if m == "go"]

        console.print()
        console.print(Panel("[bold cyan]Auto-Installing Missing Tools[/bold cyan]", border_style="cyan"))

        # ── apt-based tools ──────────────────────────────────────────────
        if apt_missing:
            if not shutil.which("apt-get"):
                console.print("[yellow]⚠ apt-get not found on this system — skipping apt-based tools "
                               "(this feature targets Debian/Kali Linux).[/yellow]")
            else:
                pkgs = [pkg for _, pkg in apt_missing]
                console.print(f"[dim]→ Installing via apt: {', '.join(pkgs)}[/dim]")
                sudo = [] if os.geteuid() == 0 else ["sudo"]
                try:
                    subprocess.run(sudo + ["apt-get", "update", "-qq"],
                                   capture_output=True, text=True, timeout=180)
                    result = subprocess.run(
                        sudo + ["apt-get", "install", "-y"] + pkgs,
                        capture_output=True, text=True, timeout=600
                    )
                    if result.returncode == 0:
                        console.print(f"  [green]✓[/green] apt packages installed: {', '.join(pkgs)}")
                    else:
                        console.print(f"  [red]✗ apt install failed:[/red] {result.stderr.strip()[:300]}")
                except subprocess.TimeoutExpired:
                    console.print("  [red]✗ apt install timed out.[/red]")
                except Exception as e:
                    console.print(f"  [red]✗ apt install error: {e}[/red]")

        # ── pip-based tools ───────────────────────────────────────────────
        if pip_missing:
            pkgs = [pkg for _, pkg in pip_missing]
            console.print(f"[dim]→ Installing via pip: {', '.join(pkgs)}[/dim]")
            try:
                result = subprocess.run(
                    ["python3", "-m", "pip", "install"] + pkgs + ["--break-system-packages", "-q"],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    console.print(f"  [green]✓[/green] pip packages installed: {', '.join(pkgs)}")
                else:
                    console.print(f"  [red]✗ pip install failed:[/red] {result.stderr.strip()[:300]}")
            except subprocess.TimeoutExpired:
                console.print("  [red]✗ pip install timed out.[/red]")
            except Exception as e:
                console.print(f"  [red]✗ pip install error: {e}[/red]")

        # ── Go-based tools ───────────────────────────────────────────────
        if go_missing:
            if not shutil.which("go"):
                console.print("[yellow]⚠ Go is not installed — skipping Go-based tools.[/yellow]")
                console.print("[dim]  Install Go first: sudo apt install golang  OR  https://go.dev/dl/[/dim]")
            else:
                for tool_name, go_path in go_missing:
                    console.print(f"[dim]→ Installing {tool_name} via go install...[/dim]")
                    try:
                        result = subprocess.run(
                            ["go", "install", "-v", go_path],
                            capture_output=True, text=True, timeout=180
                        )
                        if result.returncode == 0:
                            console.print(f"  [green]✓[/green] Installed: {tool_name}")
                        else:
                            console.print(f"  [red]✗ Failed to install {tool_name}:[/red] "
                                          f"{result.stderr.strip()[:300]}")
                    except subprocess.TimeoutExpired:
                        console.print(f"  [red]✗ {tool_name} install timed out.[/red]")
                    except Exception as e:
                        console.print(f"  [red]✗ {tool_name} install error: {e}[/red]")

                gopath_bin = os.path.join(
                    subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip() or
                    os.path.expanduser("~/go"), "bin"
                )
                if gopath_bin not in os.environ.get("PATH", ""):
                    console.print()
                    console.print(f"[yellow]⚠ Go binaries install to {gopath_bin}, which isn't on your PATH "
                                   f"yet.[/yellow]")
                    console.print(f"[dim]  Add it with: export PATH=$PATH:{gopath_bin}[/dim]")

        console.print()
        console.print("[bold cyan]Auto-install finished. Re-checking tool status...[/bold cyan]")
