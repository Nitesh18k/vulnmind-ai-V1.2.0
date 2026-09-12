"""
VulnMind AI - Authentication & Session Manager
"""

import hashlib
import json
import os
import secrets
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from database.models import get_session, init_db, User

console = Console()
SESSION_FILE = os.path.expanduser("~/.vulnmind/session.json")


def hash_password(password: str) -> str:
    salt = "vulnmind_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def load_session() -> dict:
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_session(data: dict):
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump(data, f)


def clear_session():
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)


def get_current_user():
    session_data = load_session()
    if not session_data.get("user_id"):
        return None
    db = get_session()
    user = db.query(User).filter_by(id=session_data["user_id"]).first()
    db.close()
    return user


class AuthManager:
    def __init__(self):
        init_db()
        self._ensure_admin()

    def _ensure_admin(self):
        """Create default admin if no users exist."""
        db = get_session()
        count = db.query(User).count()
        if count == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin"),
                role="admin",
                api_keys="{}",
            )
            db.add(admin)
            db.commit()
            console.print("[dim]Default admin created: admin/admin[/dim]")
        db.close()

    def login_prompt(self) -> User | None:
        """Prompt user to login."""
        console.print(Panel(
            "[bold cyan]VulnMind AI[/bold cyan] — Login Required",
            border_style="cyan",
            padding=(1, 4),
        ))

        username = Prompt.ask("[bold]Username[/bold]")
        password = Prompt.ask("[bold]Password[/bold]", password=True)

        db = get_session()
        user = db.query(User).filter_by(
            username=username,
            password_hash=hash_password(password)
        ).first()
        db.close()

        if user:
            save_session({"user_id": user.id, "username": user.username, "role": user.role})
            console.print(f"\n[bold green]✓  Welcome back, {user.username}![/bold green]")
            return user
        else:
            console.print("\n[bold red]✗  Invalid credentials.[/bold red]")
            return None

    def register_prompt(self):
        """Register a new user."""
        console.print(Panel("[bold cyan]Register New Account[/bold cyan]", border_style="cyan"))

        username = Prompt.ask("Username")
        db = get_session()
        if db.query(User).filter_by(username=username).first():
            console.print("[red]Username already taken.[/red]")
            db.close()
            return

        password = Prompt.ask("Password", password=True)
        confirm = Prompt.ask("Confirm Password", password=True)

        if password != confirm:
            console.print("[red]Passwords do not match.[/red]")
            db.close()
            return

        user = User(
            username=username,
            password_hash=hash_password(password),
            role="user",
            api_keys="{}",
        )
        db.add(user)
        db.commit()
        db.close()
        console.print(f"[bold green]✓  Account created for {username}. Please login.[/bold green]")

    def logout(self):
        clear_session()
        console.print("[bold yellow]Logged out.[/bold yellow]")

    def change_password(self, user: User):
        old_pw = Prompt.ask("Current Password", password=True)
        if hash_password(old_pw) != user.password_hash:
            console.print("[red]Incorrect password.[/red]")
            return
        new_pw = Prompt.ask("New Password", password=True)
        confirm = Prompt.ask("Confirm New Password", password=True)
        if new_pw != confirm:
            console.print("[red]Passwords do not match.[/red]")
            return
        db = get_session()
        u = db.query(User).filter_by(id=user.id).first()
        u.password_hash = hash_password(new_pw)
        db.commit()
        db.close()
        console.print("[bold green]✓  Password changed.[/bold green]")

    def manage_api_keys(self, user: User):
        """Manage AI provider API keys."""
        while True:
            db = get_session()
            u = db.query(User).filter_by(id=user.id).first()
            keys = json.loads(u.api_keys or "{}")
            db.close()

            console.print()
            console.print(Panel("[bold cyan]AI Provider API Keys[/bold cyan]", border_style="cyan"))

            table = Table(show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("Provider", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Model")

            providers = {
                "openai": ["gpt-4o", "gpt-4o-mini"],
                "gemini": ["gemini-2.5-flash", "gemini-2.5-pro"],
                "claude": ["claude-sonnet-4-6", "claude-opus-4-6"],
                "groq": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b", "mixtral-8x7b-32768"],
                "ollama": ["llama3", "mistral", "deepseek-r1"],
            }

            for p in providers:
                status = "✓ Configured" if keys.get(p) else "✗ Not set"
                style = "green" if keys.get(p) else "red"
                model = keys.get(f"{p}_model") or providers[p][0]
                table.add_row(p.title(), f"[{style}]{status}[/{style}]", model)

            console.print(table)
            console.print()
            console.print("[1] Set API Key  [2] Remove Key  [3] Set Default Provider  [4] Back")

            choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])

            if choice == "4":
                break

            if choice == "1":
                provider = Prompt.ask("Provider", choices=list(providers.keys()))
                api_key = Prompt.ask(f"{provider.title()} API Key", password=True)
                models = providers[provider]
                console.print(f"Models: {', '.join(models)}")
                model = Prompt.ask("Model", default=models[0])
                keys[provider] = api_key
                keys[f"{provider}_model"] = model
                db = get_session()
                u = db.query(User).filter_by(id=user.id).first()
                u.api_keys = json.dumps(keys)
                db.commit()
                db.close()
                console.print(f"[green]✓ {provider.title()} configured.[/green]")

            elif choice == "2":
                provider = Prompt.ask("Provider to remove", choices=list(providers.keys()))
                keys.pop(provider, None)
                keys.pop(f"{provider}_model", None)
                db = get_session()
                u = db.query(User).filter_by(id=user.id).first()
                u.api_keys = json.dumps(keys)
                db.commit()
                db.close()
                console.print(f"[yellow]Removed {provider}.[/yellow]")

            elif choice == "3":
                provider = Prompt.ask("Default provider", choices=list(providers.keys()))
                db = get_session()
                u = db.query(User).filter_by(id=user.id).first()
                u.default_provider = provider
                db.commit()
                db.close()
                console.print(f"[green]✓ Default set to {provider}.[/green]")
