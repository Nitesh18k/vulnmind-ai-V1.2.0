"""
VulnMind AI - Universal AI Provider Abstraction Layer
Supports: OpenAI, Gemini, Claude, Groq, Ollama
"""

import json
import os
import requests
from abc import ABC, abstractmethod
from rich.console import Console

console = Console()


class AIProvider(ABC):
    """Base class for all AI providers."""

    @abstractmethod
    def chat(self, messages: list, system: str = "") -> str:
        pass

    def analyze_vulnerabilities(self, scan_data: dict) -> dict:
        """Standard vulnerability analysis prompt."""
        system = """You are an expert cybersecurity analyst and penetration tester.
Analyze the provided vulnerability scan results and return a structured JSON response.
Be precise, technical, and actionable. Focus on real security risks."""

        prompt = f"""Analyze these vulnerability scan results:

TARGET: {scan_data.get('target', 'Unknown')}
SCAN TYPE: {scan_data.get('scan_type', 'Unknown')}

FINDINGS:
{json.dumps(scan_data.get('findings', []), indent=2)}

OPEN PORTS & SERVICES:
{json.dumps(scan_data.get('ports', []), indent=2)}

ASSETS DISCOVERED:
{json.dumps(scan_data.get('assets', []), indent=2)}

Provide a JSON response with this exact structure:
{{
  "executive_summary": "High-level summary for management (2-3 paragraphs)",
  "risk_score": <0-100 integer>,
  "overall_severity": "critical|high|medium|low",
  "false_positives": ["list of finding names that appear to be false positives"],
  "confirmed_vulnerabilities": [
    {{
      "name": "vulnerability name",
      "type": "sqli|xss|ssrf|rce|lfi|idor|csrf|misconfig|disclosure|other",
      "severity": "critical|high|medium|low|info",
      "cvss_score": 0.0,
      "affected_url": "url",
      "affected_param": "parameter name",
      "description": "Technical description",
      "evidence": "Evidence from scan",
      "business_impact": "Business impact explanation",
      "remediation": "Step-by-step remediation",
      "cve_suggestions": ["CVE-YYYY-XXXXX"],
      "cwe_ids": ["CWE-XXX"],
      "mitre_attack": ["T1190"]
    }}
  ],
  "attack_surface_analysis": "Analysis of the overall attack surface",
  "priority_actions": ["Action 1", "Action 2", "Action 3"],
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}

Return ONLY valid JSON, no markdown."""

        messages = [{"role": "user", "content": prompt}]
        try:
            response = self.chat(messages, system=system)
            # Strip markdown if present
            response = response.strip()
            if response.startswith("```"):
                lines = response.split("\n")
                response = "\n".join(lines[1:-1])
            return json.loads(response)
        except json.JSONDecodeError as e:
            console.print(f"[yellow]Warning: Could not parse AI JSON response: {e}[/yellow]")
            return {
                "executive_summary": response[:500] if response else "AI analysis failed.",
                "risk_score": 50,
                "overall_severity": "medium",
                "false_positives": [],
                "confirmed_vulnerabilities": [],
                "attack_surface_analysis": "",
                "priority_actions": [],
                "recommendations": [],
            }
        except Exception as e:
            console.print(f"[red]AI analysis error: {e}[/red]")
            return {}


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"

    def chat(self, messages: list, system: str = "") -> str:
        if system:
            messages = [{"role": "system", "content": system}] + messages

        resp = requests.post(
            self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class GeminiProvider(AIProvider):
    """Google Gemini provider."""

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def chat(self, messages: list, system: str = "") -> str:
        contents = []
        if system:
            # Gemini uses system_instruction
            pass

        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        payload = {"contents": contents, "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096}}
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}

        resp = requests.post(
            f"{self.base_url}?key={self.api_key}",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1/messages"

    def chat(self, messages: list, system: str = "") -> str:
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": messages,
        }
        if system:
            payload["system"] = system

        resp = requests.post(
            self.base_url,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]


class GroqProvider(AIProvider):
    """Groq provider (fast inference)."""

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def chat(self, messages: list, system: str = "") -> str:
        if system:
            messages = [{"role": "system", "content": system}] + messages

        resp = requests.post(
            self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class OllamaProvider(AIProvider):
    """Ollama local LLM provider."""

    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")

    def chat(self, messages: list, system: str = "") -> str:
        if system:
            messages = [{"role": "system", "content": system}] + messages

        resp = requests.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.3},
            },
            timeout=300,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]

    def test_connection(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


class AIManager:
    """Factory and manager for AI providers."""

    PROVIDERS = {
        "openai": OpenAIProvider,
        "gemini": GeminiProvider,
        "claude": ClaudeProvider,
        "groq": GroqProvider,
        "ollama": OllamaProvider,
    }

    # Sane fallback model per provider, used only if the user never picked one.
    # NOTE: must never be the literal string "default" - that isn't a real
    # model name for any of these APIs and would make every request fail.
    DEFAULT_MODELS = {
        "openai": "gpt-4o-mini",
        "gemini": "gemini-2.5-flash",
        "claude": "claude-sonnet-4-6",
        "groq": "llama-3.3-70b-versatile",
    }

    @classmethod
    def get_provider(cls, user) -> AIProvider | None:
        """Get the configured AI provider for a user."""
        import json
        keys = json.loads(user.api_keys or "{}")
        provider_name = user.default_provider or "openai"

        if provider_name == "ollama":
            model = keys.get("ollama_model", "llama3")
            host = keys.get("ollama_host", "http://localhost:11434")
            return OllamaProvider(model=model, host=host)

        api_key = keys.get(provider_name)
        if not api_key:
            console.print(f"[red]No API key configured for {provider_name}. Go to Profile > API Keys.[/red]")
            return None

        Provider = cls.PROVIDERS.get(provider_name)
        if not Provider:
            console.print(f"[red]Unknown provider: {provider_name}[/red]")
            return None

        fallback_model = cls.DEFAULT_MODELS.get(provider_name, "gpt-4o-mini")
        model = keys.get(f"{provider_name}_model") or fallback_model

        return Provider(api_key=api_key, model=model)

    @classmethod
    def test_provider(cls, provider_name: str, api_key: str, model: str) -> tuple[bool, str]:
        """Test an AI provider connection."""
        try:
            if provider_name == "ollama":
                p = OllamaProvider(model=model)
                ok = p.test_connection()
                return ok, "Ollama connected" if ok else "Ollama not running"

            Provider = cls.PROVIDERS.get(provider_name)
            if not Provider:
                return False, f"Unknown provider: {provider_name}"

            p = Provider(api_key=api_key, model=model)
            response = p.chat([{"role": "user", "content": "Reply with just: OK"}])
            if response:
                return True, f"Connected! Model response: {response[:50]}"
            return False, "Empty response"
        except requests.exceptions.HTTPError as e:
            return False, f"HTTP Error: {e.response.status_code} - {e.response.text[:100]}"
        except Exception as e:
            return False, str(e)
