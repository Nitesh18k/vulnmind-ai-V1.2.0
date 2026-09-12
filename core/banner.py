"""
VulnMind AI - Banner Display
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
import datetime

console = Console()

BANNER = r"""
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███╗   ███╗██╗███╗   ██╗██████╗      █████╗ ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║████╗ ████║██║████╗  ██║██╔══██╗    ██╔══██╗██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║  ██║    ███████║██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║    ██╔══██║██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝    ██║  ██║██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝     ╚═╝  ╚═╝╚═╝
"""

def show_banner():
    """Display the VulnMind AI banner."""
    console.clear()
    
    # Gradient-style banner
    banner_text = Text(BANNER)
    banner_text.stylize("bold cyan")
    
    console.print(Align.center(banner_text))
    
    # Tagline
    tagline = Text()
    tagline.append("[ ", style="dim white")
    tagline.append("Enterprise Vulnerability Assessment Platform", style="bold green")
    tagline.append(" | ", style="dim white")
    tagline.append("AI-Powered Security Analysis", style="bold yellow")
    tagline.append(" | ", style="dim white")
    tagline.append("Kali Linux Edition", style="bold red")
    tagline.append(" ]", style="dim white")
    
    console.print(Align.center(tagline))
    console.print()
    
    # Info bar
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info_items = [
        f"[bold cyan]Version:[/bold cyan] [white]1.2.0[/white]",
        f"[bold cyan]Date:[/bold cyan] [white]{now}[/white]",
        f"[bold cyan]Author:[/bold cyan] [white]NITESH[/white]",
        f"[bold cyan]Platform:[/bold cyan] [white]Kali Linux[/white]",
    ]
    
    info_text = "  |  ".join(info_items)
    console.print(Align.center(f"[dim]{'─' * 80}[/dim]"))
    console.print(Align.center(info_text))
    console.print(Align.center(f"[dim]{'─' * 80}[/dim]"))
    console.print()
    
    # Legal disclaimer
    console.print(Align.center(
        "[bold red]⚠  LEGAL DISCLAIMER:[/bold red] [dim]Use only on systems you own or have explicit written permission to test.[/dim]"
    ))
    console.print()
