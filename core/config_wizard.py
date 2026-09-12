"""
VulnMind AI - First-Run Configuration Wizard
"""

import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule

console = Console()


class ConfigWizard:
    """Interactive configuration wizard for first-time setup."""

    def run(self):
        console.print()
        console.print(Rule("[bold cyan]VulnMind AI — Configuration Wizard[/bold cyan]"))
        console.print()
        console.print(Panel(
            "Welcome! Let's configure VulnMind AI for first use.\n"
            "This wizard will help you set up your AI provider and preferences.",
            border_style="cyan", padding=(1, 2)
        ))
        console.print()

        # Database init
        from database.models import init_db
        init_db()
        console.print("[green]✓[/green] Database initialized")

        # Create reports dir
        reports_dir = os.path.expanduser("~/.vulnmind/reports")
        os.makedirs(reports_dir, exist_ok=True)
        console.print(f"[green]✓[/green] Reports directory: {reports_dir}")

        console.print()

        # AI Provider Setup
        console.print("[bold cyan]AI Provider Setup[/bold cyan]")
        console.print("VulnMind AI uses AI to analyze vulnerabilities and generate reports.")
        console.print()

        providers = {
            "1": ("openai", "OpenAI GPT", ["gpt-4o", "gpt-4o-mini"]),
            "2": ("gemini", "Google Gemini", ["gemini-2.5-flash", "gemini-2.5-pro"]),
            "3": ("claude", "Anthropic Claude", ["claude-sonnet-4-6", "claude-opus-4-6"]),
            "4": ("groq", "Groq (Fast/Free)", ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"]),
            "5": ("ollama", "Ollama (Local/Free)", ["llama3", "mistral", "deepseek-r1"]),
            "6": (None, "Skip for now", []),
        }

        console.print("Available AI Providers:")
        for k, (_, name, models) in providers.items():
            model_str = f"({', '.join(models[:2])})" if models else ""
            console.print(f"  [{k}] {name} {model_str}")

        provider_choice = Prompt.ask("Select provider", choices=list(providers.keys()), default="6")
        provider_id, provider_name, provider_models = providers[provider_choice]

        if provider_id:
            if provider_id == "ollama":
                host = Prompt.ask("Ollama host", default="http://localhost:11434")
                model = Prompt.ask("Model", default=provider_models[0])
                api_key_data = {"ollama_host": host, "ollama_model": model, "ollama": "local"}
            else:
                api_key = Prompt.ask(f"{provider_name} API Key", password=True)
                console.print(f"Available models: {', '.join(provider_models)}")
                model = Prompt.ask("Model", default=provider_models[0])
                api_key_data = {provider_id: api_key, f"{provider_id}_model": model}

            # Save to default admin user
            from database.models import get_session, User
            from core.auth import hash_password

            db = get_session()
            admin = db.query(User).filter_by(username="admin").first()
            if not admin:
                admin = User(
                    username="admin",
                    password_hash=hash_password("admin"),
                    role="admin",
                    api_keys="{}",
                )
                db.add(admin)
                db.commit()

            existing_keys = json.loads(admin.api_keys or "{}")
            existing_keys.update(api_key_data)
            admin.api_keys = json.dumps(existing_keys)
            admin.default_provider = provider_id
            admin.default_model = model
            db.commit()
            db.close()

            console.print(f"[green]✓[/green] {provider_name} configured with model: {model}")

        console.print()
        console.print(Rule("[bold green]Configuration Complete![/bold green]"))
        console.print()
        console.print("Default credentials: [bold]admin / admin[/bold]")
        console.print("[yellow]⚠  Change your password after first login.[/yellow]")
        console.print()
        console.print("Run [bold cyan]python vulnmind.py[/bold cyan] to start VulnMind AI")
        console.print()
