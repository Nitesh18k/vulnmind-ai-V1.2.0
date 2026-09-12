"""
VulnMind AI - Dashboard & Statistics Display
"""

import json
import datetime
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from database.models import get_session, Scan, Target, Vulnerability, Asset, User

console = Console()


def show_dashboard(user):
    """Display the main statistics dashboard."""
    db = get_session()

    # Fetch stats
    total_targets = db.query(Target).filter_by(user_id=user.id).count()
    total_scans = db.query(Scan).filter_by(user_id=user.id).count()
    completed_scans = db.query(Scan).filter_by(user_id=user.id, status="done").count()

    # Vulnerability counts
    all_vulns = (
        db.query(Vulnerability)
        .join(Scan)
        .filter(Scan.user_id == user.id)
        .all()
    )

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        s = (v.severity or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Recent scans
    recent_scans = (
        db.query(Scan)
        .filter_by(user_id=user.id)
        .order_by(Scan.started_at.desc())
        .limit(10)
        .all()
    )

    # Asset count
    total_assets = db.query(Asset).join(Scan).filter(Scan.user_id == user.id).count()

    db.close()

    console.print()
    console.print(Panel(
        f"[bold cyan]Security Operations Dashboard[/bold cyan]  "
        f"[dim]— {user.username} | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}[/dim]",
        border_style="cyan"
    ))

    # Stats cards
    cards = [
        Panel(
            Align.center(f"[bold cyan]{total_targets}[/bold cyan]\n[dim]Targets[/dim]"),
            border_style="cyan", padding=(0, 2)
        ),
        Panel(
            Align.center(f"[bold green]{total_scans}[/bold green]\n[dim]Total Scans[/dim]"),
            border_style="green", padding=(0, 2)
        ),
        Panel(
            Align.center(f"[bold magenta]{total_assets}[/bold magenta]\n[dim]Assets Found[/dim]"),
            border_style="magenta", padding=(0, 2)
        ),
        Panel(
            Align.center(f"[bold red]{sev_counts['critical']}[/bold red]\n[dim]Critical[/dim]"),
            border_style="red", padding=(0, 2)
        ),
        Panel(
            Align.center(f"[bold yellow]{sev_counts['high']}[/bold yellow]\n[dim]High[/dim]"),
            border_style="yellow", padding=(0, 2)
        ),
        Panel(
            Align.center(f"[bold blue]{sev_counts['medium']}[/bold blue]\n[dim]Medium[/dim]"),
            border_style="blue", padding=(0, 2)
        ),
    ]

    console.print(Columns(cards, equal=True))
    console.print()

    # ASCII severity chart
    console.print("[bold cyan]Vulnerability Distribution[/bold cyan]")
    max_count = max(sev_counts.values()) if any(sev_counts.values()) else 1

    severity_styles = {
        "critical": ("■", "red"),
        "high": ("■", "yellow"),
        "medium": ("■", "blue"),
        "low": ("■", "cyan"),
        "info": ("■", "dim"),
    }

    for sev, (char, color) in severity_styles.items():
        count = sev_counts.get(sev, 0)
        bar_len = int((count / max_count) * 40) if max_count > 0 else 0
        bar = f"[{color}]{char * bar_len}[/{color}]"
        console.print(f"  {sev.upper():10} {bar} [dim]{count}[/dim]")

    console.print()

    # Recent scans table
    if recent_scans:
        console.print("[bold cyan]Recent Scans[/bold cyan]")
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("ID", style="dim", width=5)
        table.add_column("Target", style="cyan", width=30)
        table.add_column("Type", width=12)
        table.add_column("Status", width=12)
        table.add_column("Risk", width=10)
        table.add_column("Vulns", width=8, justify="center")
        table.add_column("Date", width=18)

        status_colors = {
            "done": "green", "running": "yellow",
            "failed": "red", "pending": "dim"
        }
        level_colors = {
            "critical": "red", "high": "yellow",
            "medium": "blue", "low": "green"
        }

        for scan in recent_scans:
            db = get_session()
            target = db.query(Target).filter_by(id=scan.target_id).first()
            vuln_count = db.query(Vulnerability).filter_by(scan_id=scan.id).count()
            db.close()

            status_color = status_colors.get(scan.status, "white")
            risk_level = "—"
            risk_color = "dim"

            if scan.risk_score:
                if scan.risk_score >= 75:
                    risk_level = "CRITICAL"
                    risk_color = "red"
                elif scan.risk_score >= 50:
                    risk_level = "HIGH"
                    risk_color = "yellow"
                elif scan.risk_score >= 25:
                    risk_level = "MEDIUM"
                    risk_color = "blue"
                else:
                    risk_level = "LOW"
                    risk_color = "green"

            table.add_row(
                str(scan.id),
                target.name if target else "—",
                scan.scan_type or "—",
                f"[{status_color}]{scan.status.upper()}[/{status_color}]",
                f"[{risk_color}]{risk_level}[/{risk_color}]",
                str(vuln_count),
                scan.started_at.strftime("%m/%d %H:%M") if scan.started_at else "—",
            )

        console.print(table)
    else:
        console.print("[dim]No scans yet. Start a scan from the Scan menu.[/dim]")

    console.print()


def show_target_list(user):
    """Display all targets."""
    db = get_session()
    targets = db.query(Target).filter_by(user_id=user.id).all()
    db.close()

    if not targets:
        console.print("[yellow]No targets added yet.[/yellow]")
        return

    console.print(f"\n[bold cyan]Targets ({len(targets)})[/bold cyan]")
    table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("ID", style="dim", width=5)
    table.add_column("Name", style="cyan", width=35)
    table.add_column("Type", width=12)
    table.add_column("Tags", width=20)
    table.add_column("Added", width=18)

    for t in targets:
        table.add_row(
            str(t.id),
            t.name,
            t.target_type or "—",
            t.tags or "—",
            t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else "—",
        )

    console.print(table)


def show_vuln_list(user, scan_id: int = None):
    """Display vulnerabilities."""
    db = get_session()

    query = db.query(Vulnerability).join(Scan).filter(Scan.user_id == user.id)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)

    vulns = query.order_by(Vulnerability.severity).all()
    db.close()

    if not vulns:
        console.print("[yellow]No vulnerabilities found.[/yellow]")
        return

    console.print(f"\n[bold cyan]Vulnerabilities ({len(vulns)})[/bold cyan]")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_colors = {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "cyan", "info": "dim"
    }

    sorted_vulns = sorted(vulns, key=lambda x: sev_order.get((x.severity or "info").lower(), 5))

    table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Name", width=40)
    table.add_column("CVSS", width=8, justify="center")
    table.add_column("CVE", width=18)
    table.add_column("Tool", width=12)

    for i, v in enumerate(sorted_vulns, 1):
        sev = (v.severity or "info").lower()
        color = sev_colors.get(sev, "white")
        cves = json.loads(v.cve_ids or "[]")
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            v.name or "Unknown",
            f"{v.cvss_score:.1f}" if v.cvss_score else "—",
            ", ".join(cves[:1]) or "—",
            v.tool or "—",
        )

    console.print(table)
