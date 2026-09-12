"""
VulnMind AI - Quick Scan (non-interactive mode)
"""

from rich.console import Console
from rich.rule import Rule
from core.auth import get_current_user, AuthManager

console = Console()


class QuickScan:
    """Quick non-interactive scan from CLI."""

    def __init__(self, target: str):
        self.target = target.replace("https://", "").replace("http://", "").rstrip("/")

    def run(self):
        console.print(Rule(f"[bold cyan]VulnMind AI — Quick Scan: {self.target}[/bold cyan]"))

        user = get_current_user()
        if not user:
            # Auto-login as admin for quick scan
            from database.models import init_db, get_session, User
            from core.auth import hash_password
            init_db()
            db = get_session()
            user = db.query(User).filter_by(username="admin").first()
            db.close()

        if not user:
            console.print("[red]No user session. Run vulnmind.py to login first.[/red]")
            return

        # Add target to DB
        from database.models import get_session, Target
        db = get_session()
        target_obj = db.query(Target).filter_by(user_id=user.id, name=self.target).first()
        if not target_obj:
            target_obj = Target(
                user_id=user.id,
                name=self.target,
                target_type="domain",
            )
            db.add(target_obj)
            db.commit()
        target_id = target_obj.id
        db.close()

        # Run scan
        from core.scanner import ScanOrchestrator
        orchestrator = ScanOrchestrator(user)
        orchestrator.run_scan(self.target, target_id, "quick")
