"""
VulnMind AI - CVE Mapping Engine
Integrates: NVD API, MITRE ATT&CK
"""

import requests
import json
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_ATTACK_URL = "https://attack.mitre.org/techniques/"

# CWE -> Common vulnerability type mapping
CWE_VULN_MAP = {
    "CWE-79": {"name": "Cross-Site Scripting", "attack_id": "T1059"},
    "CWE-89": {"name": "SQL Injection", "attack_id": "T1190"},
    "CWE-22": {"name": "Path Traversal", "attack_id": "T1083"},
    "CWE-78": {"name": "OS Command Injection", "attack_id": "T1059"},
    "CWE-94": {"name": "Code Injection", "attack_id": "T1059"},
    "CWE-611": {"name": "XML External Entity", "attack_id": "T1190"},
    "CWE-918": {"name": "SSRF", "attack_id": "T1190"},
    "CWE-200": {"name": "Information Disclosure", "attack_id": "T1040"},
    "CWE-284": {"name": "Improper Access Control", "attack_id": "T1548"},
    "CWE-287": {"name": "Improper Authentication", "attack_id": "T1078"},
    "CWE-352": {"name": "CSRF", "attack_id": "T1185"},
    "CWE-434": {"name": "Unrestricted File Upload", "attack_id": "T1190"},
    "CWE-502": {"name": "Deserialization", "attack_id": "T1190"},
    "CWE-601": {"name": "Open Redirect", "attack_id": "T1185"},
    "CWE-310": {"name": "Cryptographic Issues", "attack_id": "T1600"},
    "CWE-319": {"name": "Cleartext Transmission", "attack_id": "T1040"},
    "CWE-326": {"name": "Inadequate Encryption", "attack_id": "T1600"},
    "CWE-538": {"name": "File & Directory Info Disclosure", "attack_id": "T1083"},
    "CWE-798": {"name": "Hardcoded Credentials", "attack_id": "T1552"},
}

# Vulnerability type keyword -> CWE/CVE mapping
VULN_TYPE_CVSS = {
    "sqli": 9.8, "xss": 7.4, "ssrf": 9.1, "rce": 10.0, "lfi": 7.5,
    "idor": 6.5, "csrf": 6.5, "misconfig": 5.0, "disclosure": 4.3,
    "open_redirect": 5.4, "ssl": 5.9, "xxe": 8.6,
}


class CVEMapper:
    """Maps vulnerabilities to CVEs and MITRE ATT&CK."""

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self._cache = {}

    def enrich_vulnerability(self, vuln: Dict) -> Dict:
        """Enrich a vulnerability with CVE, CVSS, and MITRE data."""
        enriched = vuln.copy()

        # Get CVE suggestions based on name/type
        if not enriched.get("cve_ids"):
            suggested_cves = self._suggest_cves(vuln)
            enriched["cve_ids"] = suggested_cves

        # Get CVSS score
        if not enriched.get("cvss_score") or enriched.get("cvss_score") == 0:
            cvss = VULN_TYPE_CVSS.get(vuln.get("type", ""), 5.0)
            enriched["cvss_score"] = cvss

        # Get MITRE ATT&CK mapping
        mitre = self._get_mitre_mapping(vuln)
        if mitre:
            enriched["mitre_attack"] = mitre

        # Get CWE details
        cwe_ids = enriched.get("cwe_ids", [])
        if cwe_ids:
            enriched["cwe_details"] = self._get_cwe_details(cwe_ids)

        # Fetch NVD data for known CVEs
        if enriched.get("cve_ids"):
            nvd_data = self._fetch_nvd_data(enriched["cve_ids"][0])
            if nvd_data:
                enriched["nvd_data"] = nvd_data
                if nvd_data.get("cvss_v3"):
                    enriched["cvss_score"] = max(enriched.get("cvss_score", 0), nvd_data["cvss_v3"])

        return enriched

    def _suggest_cves(self, vuln: Dict) -> List[str]:
        """Suggest CVEs based on vulnerability type and name."""
        vuln_type = vuln.get("type", "").lower()
        name = vuln.get("name", "").lower()

        # Known CVE suggestions for common issues
        suggestions = {
            "sqli": [],  # Generic, too many CVEs
            "xss": [],
            "log4j": ["CVE-2021-44228", "CVE-2021-45046"],
            "spring": ["CVE-2022-22965"],
            "struts": ["CVE-2017-5638"],
            "heartbleed": ["CVE-2014-0160"],
            "shellshock": ["CVE-2014-6271"],
            "spectre": ["CVE-2017-5753"],
        }

        for keyword, cves in suggestions.items():
            if keyword in name or keyword in vuln_type:
                return cves

        return []

    def _get_mitre_mapping(self, vuln: Dict) -> List[str]:
        """Map vulnerability to MITRE ATT&CK technique IDs."""
        vuln_type = vuln.get("type", "").lower()
        cwe_ids = vuln.get("cwe_ids", [])

        mitre_map = {
            "sqli": ["T1190", "T1213"],
            "xss": ["T1059.007", "T1185"],
            "ssrf": ["T1190", "T1552"],
            "rce": ["T1190", "T1059"],
            "lfi": ["T1083", "T1005"],
            "idor": ["T1548", "T1213"],
            "csrf": ["T1185"],
            "misconfig": ["T1190"],
            "disclosure": ["T1040", "T1213"],
            "open_redirect": ["T1185"],
            "ssl": ["T1040", "T1600"],
            "xxe": ["T1190"],
        }

        techniques = mitre_map.get(vuln_type, [])

        # Also check CWE mappings
        for cwe in cwe_ids:
            cwe_data = CWE_VULN_MAP.get(cwe, {})
            if cwe_data.get("attack_id") and cwe_data["attack_id"] not in techniques:
                techniques.append(cwe_data["attack_id"])

        return list(set(techniques))

    def _get_cwe_details(self, cwe_ids: List[str]) -> List[Dict]:
        """Get CWE details."""
        details = []
        for cwe in cwe_ids:
            if cwe in CWE_VULN_MAP:
                details.append({
                    "id": cwe,
                    "name": CWE_VULN_MAP[cwe]["name"],
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
                })
            else:
                details.append({"id": cwe, "name": "Unknown", "url": ""})
        return details

    def _fetch_nvd_data(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE details from NVD API."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        try:
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            r = requests.get(
                f"{NVD_API_BASE}?cveId={cve_id}",
                headers=headers,
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Get CVSS v3 score
            cvss_v3 = None
            cvss_v3_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss_v3_data:
                cvss_v3 = cvss_v3_data[0].get("cvssData", {}).get("baseScore")

            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                ""
            )

            result = {
                "id": cve_id,
                "description": description[:500],
                "cvss_v3": cvss_v3,
                "severity": cvss_v3_data[0].get("cvssData", {}).get("baseSeverity", "").lower()
                if cvss_v3_data else "",
                "published": cve_data.get("published", ""),
                "references": [
                    r.get("url", "") for r in cve_data.get("references", [])[:3]
                ],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }

            self._cache[cve_id] = result
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            console.print(f"  [dim]NVD API error for {cve_id}: {e}[/dim]")
            return None
        except Exception:
            return None

    def enrich_all(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Enrich all vulnerabilities with CVE/MITRE data."""
        enriched = []

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as prog:
            task = prog.add_task("[cyan]Mapping CVEs...", total=len(vulnerabilities))

            for vuln in vulnerabilities:
                enriched_vuln = self.enrich_vulnerability(vuln)
                enriched.append(enriched_vuln)
                prog.advance(task)

        return enriched

    def display_cve_table(self, vulnerabilities: List[Dict]):
        """Display CVE mapping results."""
        console.print(f"\n[bold cyan]CVE & MITRE ATT&CK Mapping[/bold cyan]")

        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Vulnerability", width=35)
        table.add_column("CVE IDs", width=20)
        table.add_column("CVSS", width=8, justify="center")
        table.add_column("CWE", width=15)
        table.add_column("MITRE ATT&CK", width=20)

        severity_colors = {"critical": "red", "high": "red", "medium": "yellow",
                           "low": "cyan", "info": "blue"}

        for v in vulnerabilities:
            sev = v.get("severity", "info").lower()
            color = severity_colors.get(sev, "white")
            cvss = v.get("cvss_score", 0)
            cvss_color = "red" if cvss >= 9 else "yellow" if cvss >= 7 else "cyan"

            cves = ", ".join(v.get("cve_ids", [])[:2]) or "—"
            cwes = ", ".join(v.get("cwe_ids", [])[:2]) or "—"
            mitre = ", ".join(v.get("mitre_attack", [])[:2]) or "—"

            table.add_row(
                f"[{color}]{v.get('name', 'Unknown')[:33]}[/{color}]",
                cves,
                f"[{cvss_color}]{cvss:.1f}[/{cvss_color}]",
                cwes,
                mitre,
            )

        console.print(table)


def calculate_risk_score(vulnerabilities: List[Dict], open_ports: List[Dict]) -> Dict:
    """Calculate overall risk score for the target."""
    if not vulnerabilities:
        return {"score": 0, "level": "low", "breakdown": {}}

    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    weighted_sum = 0
    max_possible = 0

    for v in vulnerabilities:
        sev = v.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        weight = severity_weights.get(sev, 0)
        weighted_sum += weight * min(v.get("cvss_score", 5.0) / 10.0, 1.0)

    # Normalize to 0-100
    if vulnerabilities:
        base_score = min((weighted_sum / len(vulnerabilities)) * 10, 100)
    else:
        base_score = 0

    # Bonus for critical findings
    if severity_counts["critical"] > 0:
        base_score = min(base_score + severity_counts["critical"] * 5, 100)
    if severity_counts["high"] > 0:
        base_score = min(base_score + severity_counts["high"] * 2, 100)

    # Port exposure factor
    high_risk_ports = [p for p in open_ports if p.get("port") in
                       [21, 23, 111, 135, 139, 445, 3389, 5900, 6379, 9200, 27017]]
    if high_risk_ports:
        base_score = min(base_score + len(high_risk_ports) * 3, 100)

    score = round(base_score, 1)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "breakdown": {
            "severity_counts": severity_counts,
            "total_vulnerabilities": len(vulnerabilities),
            "high_risk_ports": len(high_risk_ports),
        }
    }
