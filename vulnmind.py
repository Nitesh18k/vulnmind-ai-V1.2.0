#!/usr/bin/env python3
"""
VulnMind AI - Enterprise CLI Vulnerability Assessment Platform
For Kali Linux | AI-Powered Security Analysis
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from core.banner import show_banner
from core.menu import InteractiveMenu

app = typer.Typer(
    name="vulnmind",
    help="VulnMind AI - Enterprise Vulnerability Assessment Platform",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def main(
    interactive: bool = typer.Option(True, "--interactive/--no-interactive", "-i/-n",
                                      help="Launch interactive menu"),
    target: str = typer.Option(None, "--target", "-t", help="Target domain/IP for quick scan"),
    config: bool = typer.Option(False, "--config", "-c", help="Open configuration wizard"),
    version: bool = typer.Option(False, "--version", "-v", help="Show version info"),
):
    """
    [bold cyan]VulnMind AI[/bold cyan] - Enterprise-grade CLI Vulnerability Assessment Platform
    
    Run without arguments to launch the interactive menu.
    """
    show_banner()

    if version:
        console.print("[bold green]VulnMind AI v1.2.0[/bold green]")
        console.print("Built for Kali Linux | AI-Powered Security Analysis")
        return

    if config:
        from core.config_wizard import ConfigWizard
        wizard = ConfigWizard()
        wizard.run()
        return

    if target:
        from core.quick_scan import QuickScan
        scanner = QuickScan(target)
        scanner.run()
        return

    # Default: interactive menu
    menu = InteractiveMenu()
    menu.run()


if __name__ == "__main__":
    app()
