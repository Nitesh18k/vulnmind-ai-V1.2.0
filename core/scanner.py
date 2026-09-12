"""
VulnMind AI - Scan Orchestrator
Coordinates all scanning modules for a complete assessment
"""

import json
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from database.models import get_session, Scan, Target, Vulnerability, Asset
from modules.recon import ReconEngine
from modules.portscan import PortScanner
from modules.vulnscan import VulnerabilityScanner
from modules.cve_mapper import CVEMapper, calculate_risk_score
from ai.providers import AIManager

console = Console()


class ScanOrchestrator:
    """Manages full vulnerability assessment workflow."""

    SCAN_TYPES = {
        "1": ("quick", "Quick Scan", "DNS + Common Ports + Security Headers (~2 min)"),
        "2": ("standard", "Standard Scan", "Recon + Port Scan + Vuln Check + AI Analysis (~5-10 min)"),
        "3": ("full", "Full Assessment", "Complete assessment with all tools + Deep Vuln Scan + CVE Mapping (~15-30 min)"),
        "4": ("recon_only", "Recon Only", "Subdomain discovery + DNS + WHOIS only"),
        "5": ("ports_only", "Port Scan Only", "Port scanning and service detection only"),
    }

    def __init__(self, user):
        self.user = user

    def new_scan_wizard(self):
        """Interactive scan wizard."""
        console.print()
        console.print(Panel("[bold cyan]New Security Scan[/bold cyan]", border_style="cyan"))

        # Select target
        db = get_session()
        targets = db.query(Target).filter_by(user_id=self.user.id).all()
        db.close()

        target_name = None

        if targets:
            console.print("\n[bold]Existing Targets:[/bold]")
            for i, t in enumerate(targets, 1):
                console.print(f"  [{i}] {t.name} ({t.target_type})")
            console.print(f"  [N] Enter new target")
            console.print()

            choice = Prompt.ask("Select target", default="N")
            if choice.upper() != "N" and choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(targets):
                    target_name = targets[idx].name
                    target_id = targets[idx].id
                else:
                    console.print("[red]Invalid selection[/red]")
                    return
            else:
                target_name = None

        if not target_name:
            target_name = Prompt.ask("Enter target (domain/IP/URL)").strip()
            if not target_name:
                console.print("[red]Target cannot be empty.[/red]")
                return

            # Normalize
            target_clean = target_name.replace("https://", "").replace("http://", "").rstrip("/")

            # Save target
            db = get_session()
            target_type = "ip" if target_clean.replace(".", "").isdigit() else "domain"
            t = Target(
                user_id=self.user.id,
                name=target_clean,
                target_type=target_type,
            )
            db.add(t)
            db.commit()
            target_id = t.id
            target_name = target_clean
            db.close()

        # Normalize target
        target_name = target_name.replace("https://", "").replace("http://", "").rstrip("/")

        # Select scan type
        console.print("\n[bold]Scan Types:[/bold]")
        for key, (_, name, desc) in self.SCAN_TYPES.items():
            console.print(f"  [{key}] [cyan]{name}[/cyan] — {desc}")

        scan_choice = Prompt.ask("\nSelect scan type", choices=list(self.SCAN_TYPES.keys()), default="2")
        scan_type_key, scan_name, _ = self.SCAN_TYPES[scan_choice]

        console.print()
        confirmed = Confirm.ask(f"Start [cyan]{scan_name}[/cyan] on [bold]{target_name}[/bold]?")
        if not confirmed:
            return

        self.run_scan(target_name, target_id, scan_type_key)

    def run_scan(self, target: str, target_id: int, scan_type: str):
        """Execute the scan workflow."""
        # Create scan record
        db = get_session()
        scan = Scan(
            user_id=self.user.id,
            target_id=target_id,
            scan_type=scan_type,
            status="running",
            started_at=datetime.datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        console.print()
        console.print(Rule(f"[bold cyan]VulnMind AI — {scan_type.replace('_', ' ').title()} — {target}[/bold cyan]"))
        console.print()

        all_results = {
            "target": target,
            "scan_type": scan_type,
            "subdomains": [],
            "ports": [],
            "vulnerabilities": [],
            "ai_analysis": {},
            "risk": {},
        }

        try:
            # ── PHASE 1: RECONNAISSANCE ──────────────────────────────────────────
            if scan_type not in ["ports_only"]:
                console.print(Panel("[bold]Phase 1: Reconnaissance[/bold]", border_style="blue", padding=(0,2)))
                recon = ReconEngine(target)
                recon_results = recon.run_full_recon()

                all_results["subdomains"] = recon_results.get("subdomains", [])
                recon.display_results(recon_results)

                # Save discovered assets
                db = get_session()
                for sub in all_results["subdomains"][:100]:
                    a = Asset(scan_id=scan_id, target_id=target_id, asset_type="subdomain", value=sub)
                    db.add(a)
                for ip in recon_results.get("ips", [])[:50]:
                    a = Asset(scan_id=scan_id, target_id=target_id, asset_type="ip", value=ip)
                    db.add(a)
                db.commit()
                db.close()

                self._update_scan_progress(scan_id, 25)

            if scan_type == "recon_only":
                report_paths = self._generate_reports_and_finalize(scan_id, all_results, [])
                console.print()
                console.print(Rule("[bold green]Recon Complete[/bold green]"))
                console.print(f"  Subdomains found: [cyan]{len(all_results['subdomains'])}[/cyan]")
                console.print(f"  Reports saved to: [cyan]{list(report_paths.values())[0] if report_paths else 'N/A'}[/cyan]")
                console.print(f"  Scan ID: [dim]{scan_id}[/dim]")
                console.print()
                return

            # ── PHASE 2: PORT SCANNING ───────────────────────────────────────────
            if scan_type != "recon_only":
                console.print()
                console.print(Panel("[bold]Phase 2: Port Scanning[/bold]", border_style="blue", padding=(0,2)))
                port_scan_type = "full" if scan_type == "full" else "quick" if scan_type == "quick" else "common"
                port_scanner = PortScanner(target)
                ports = port_scanner.scan(port_scan_type)
                all_results["ports"] = ports
                port_scanner.display_results()

                # Save port assets
                db = get_session()
                for p in ports:
                    a = Asset(
                        scan_id=scan_id, target_id=target_id, asset_type="port",
                        value=str(p["port"]),
                        extra=json.dumps(p)
                    )
                    db.add(a)
                db.commit()
                db.close()

                self._update_scan_progress(scan_id, 50)

            if scan_type == "ports_only":
                report_paths = self._generate_reports_and_finalize(scan_id, all_results, [])
                console.print()
                console.print(Rule("[bold green]Port Scan Complete[/bold green]"))
                console.print(f"  Open ports found: [cyan]{len(all_results['ports'])}[/cyan]")
                console.print(f"  Reports saved to: [cyan]{list(report_paths.values())[0] if report_paths else 'N/A'}[/cyan]")
                console.print(f"  Scan ID: [dim]{scan_id}[/dim]")
                console.print()
                return

            # ── PHASE 3: VULNERABILITY SCANNING ─────────────────────────────────
            console.print()
            console.print(Panel("[bold]Phase 3: Vulnerability Scanning[/bold]", border_style="blue", padding=(0,2)))

            vuln_level = "deep" if scan_type == "full" else "quick" if scan_type == "quick" else "standard"
            vuln_scanner = VulnerabilityScanner(target)
            raw_vulns = vuln_scanner.run_full_scan(vuln_level)
            vuln_scanner.display_results()

            self._update_scan_progress(scan_id, 65)

            # ── PHASE 4: CVE MAPPING ─────────────────────────────────────────────
            console.print()
            console.print(Panel("[bold]Phase 4: CVE & MITRE Mapping[/bold]", border_style="blue", padding=(0,2)))
            cve_mapper = CVEMapper()
            enriched_vulns = cve_mapper.enrich_all(raw_vulns)
            all_results["vulnerabilities"] = enriched_vulns

            if enriched_vulns:
                cve_mapper.display_cve_table(enriched_vulns[:15])

            # ── PHASE 5: RISK SCORING ─────────────────────────────────────────────
            risk = calculate_risk_score(enriched_vulns, all_results["ports"])
            all_results["risk"] = risk

            risk_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}
            risk_color = risk_colors.get(risk["level"], "white")
            console.print()
            console.print(Panel(
                f"[bold]Risk Score: [{risk_color}]{risk['score']:.0f}/100[/{risk_color}] "
                f"— {risk['level'].upper()} RISK[/bold]",
                border_style=risk_color, padding=(0, 2)
            ))

            self._update_scan_progress(scan_id, 80)

            # ── PHASE 6: AI ANALYSIS ─────────────────────────────────────────────
            if scan_type in ["standard", "full"]:
                console.print()
                console.print(Panel("[bold]Phase 5: AI Analysis[/bold]", border_style="blue", padding=(0,2)))

                ai_provider = AIManager.get_provider(self.user)
                if ai_provider:
                    console.print(f"  [dim]→ Sending results to AI for analysis...[/dim]")
                    ai_input = {
                        "target": target,
                        "scan_type": scan_type,
                        "findings": [
                            {k: v for k, v in vuln.items() if k != "nvd_data"}
                            for vuln in enriched_vulns[:20]  # limit tokens
                        ],
                        "ports": all_results["ports"][:30],
                        "assets": {"subdomains": len(all_results["subdomains"])},
                    }
                    ai_analysis = ai_provider.analyze_vulnerabilities(ai_input)
                    all_results["ai_analysis"] = ai_analysis

                    exec_summary = ai_analysis.get("executive_summary", "")
                    if exec_summary:
                        console.print()
                        console.print("[bold cyan]AI Executive Summary:[/bold cyan]")
                        console.print(Panel(exec_summary[:600] + ("..." if len(exec_summary) > 600 else ""),
                                           border_style="dim", padding=(1, 2)))
                else:
                    console.print("  [yellow]No AI provider configured. Skipping AI analysis.[/yellow]")
                    console.print("  [dim]Set up an AI provider in Profile → API Keys.[/dim]")

            self._update_scan_progress(scan_id, 90)

            # ── PHASE 7: REPORT GENERATION ────────────────────────────────────────
            report_paths = self._generate_reports_and_finalize(scan_id, all_results, enriched_vulns)

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Scan interrupted by user.[/yellow]")
            self._update_scan_status(scan_id, "failed")
            return
        except Exception as e:
            console.print(f"\n[red]Scan error: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            self._update_scan_status(scan_id, "failed")
            return

        # Final summary
        console.print()
        console.print(Rule("[bold green]Scan Complete[/bold green]"))
        console.print()
        sev_counts = {}
        for v in enriched_vulns:
            s = v.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        summary_parts = []
        if sev_counts.get("critical"): summary_parts.append(f"[red]{sev_counts['critical']} Critical[/red]")
        if sev_counts.get("high"): summary_parts.append(f"[yellow]{sev_counts['high']} High[/yellow]")
        if sev_counts.get("medium"): summary_parts.append(f"[blue]{sev_counts['medium']} Medium[/blue]")
        if sev_counts.get("low"): summary_parts.append(f"[cyan]{sev_counts['low']} Low[/cyan]")

        if summary_parts:
            console.print(f"  Findings: {' | '.join(summary_parts)}")
        console.print(f"  Reports saved to: [cyan]{list(report_paths.values())[0] if report_paths else 'N/A'}[/cyan]")
        console.print(f"  Scan ID: [dim]{scan_id}[/dim]")
        console.print()

    def _generate_reports_and_finalize(self, scan_id: int, all_results: dict, enriched_vulns: list) -> dict:
        """Generate PDF/HTML/TXT reports, persist findings, and mark the scan done.

        Used by every scan type (quick/standard/full/recon_only/ports_only) so
        that a report is always produced from whatever data that scan type
        collected — a scan with only recon or only port data still gets a
        full set of reports, just without a vulnerabilities section.
        """
        console.print()
        console.print(Panel("[bold]Report Generation[/bold]", border_style="blue", padding=(0, 2)))

        # Make sure a risk score reflects whatever we actually collected
        if not all_results.get("risk"):
            all_results["risk"] = calculate_risk_score(enriched_vulns, all_results.get("ports", []))

        from reports.generator import ReportGenerator
        reporter = ReportGenerator(all_results)
        report_paths = reporter.generate_all()

        if report_paths:
            for fmt, path in report_paths.items():
                console.print(f"  [green]✓[/green] {fmt.upper()} report: [cyan]{path}[/cyan]")
        else:
            console.print("  [red]✗ No reports could be generated. Check the errors above.[/red]")

        if enriched_vulns:
            self._save_vulnerabilities(scan_id, enriched_vulns)

        self._finalize_scan(scan_id, all_results, report_paths)
        return report_paths

    def _update_scan_progress(self, scan_id: int, progress: int):
        db = get_session()
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.progress = progress
            db.commit()
        db.close()

    def _update_scan_status(self, scan_id: int, status: str):
        db = get_session()
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = status
            scan.finished_at = datetime.datetime.utcnow()
            db.commit()
        db.close()

    def _save_vulnerabilities(self, scan_id: int, vulns: list):
        db = get_session()
        for v in vulns:
            vuln = Vulnerability(
                scan_id=scan_id,
                name=v.get("name", "Unknown")[:256],
                vuln_type=v.get("type", "unknown")[:64],
                severity=v.get("severity", "info").lower()[:16],
                cvss_score=v.get("cvss_score", 0.0),
                cve_ids=json.dumps(v.get("cve_ids", [])),
                cwe_ids=json.dumps(v.get("cwe_ids", [])),
                affected_url=v.get("affected_url", ""),
                affected_param=v.get("affected_param", "")[:256],
                description=v.get("description", ""),
                evidence=v.get("evidence", ""),
                remediation=v.get("remediation", ""),
                business_impact=v.get("business_impact", ""),
                tool=v.get("tool", "")[:64],
                mitre_attack=json.dumps(v.get("mitre_attack", [])),
            )
            db.add(vuln)
        db.commit()
        db.close()

    def _finalize_scan(self, scan_id: int, results: dict, report_paths: dict = None):
        db = get_session()
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = "done"
            scan.progress = 100
            scan.finished_at = datetime.datetime.utcnow()
            scan.risk_score = results.get("risk", {}).get("score", 0)
            ai = results.get("ai_analysis", {})
            scan.ai_analysis = ai.get("executive_summary", "")[:5000] if ai else ""
            sev = results.get("risk", {}).get("breakdown", {}).get("severity_counts", {})
            scan.severity_counts = json.dumps(sev)
            db.commit()
        db.close()
