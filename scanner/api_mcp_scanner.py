#!/usr/bin/env python3
import sys
import json
import yaml
import re
from pathlib import Path
from typing import Dict, Any, List

SECRET_REGEX = re.compile(r"(sk_live_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})")

class APIMCPShiftLeftScanner:
    """
    Automated CI/CD Shift-Left Security Scanner for API schemas (OpenAPI/Swagger)
    and Model Context Protocol (MCP) server configurations.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan_openapi_spec(self, file_path: str) -> List[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as f:
            if path.suffix in [".yaml", ".yml"]:
                spec = yaml.safe_load(f)
            else:
                spec = json.load(f)

        paths = spec.get("paths", {})
        for route, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    # Check for missing authentication security definitions
                    security = details.get("security", spec.get("security", []))
                    if not security and not route.endswith("/health"):
                        self.findings.append({
                            "severity": "HIGH",
                            "category": "OWASP API2:2023 Broken Authentication",
                            "file": str(path),
                            "target": f"{method.upper()} {route}",
                            "message": "Endpoint exposed without required security/auth requirements."
                        })

                    # Check for missing requestBody schema in state-changing endpoints
                    if method.lower() in ["post", "put", "patch"] and "requestBody" not in details:
                        self.findings.append({
                            "severity": "MEDIUM",
                            "category": "OWASP API8:2023 Lack of Input Validation",
                            "file": str(path),
                            "target": f"{method.upper()} {route}",
                            "message": "State-changing endpoint missing strict requestBody schema validation."
                        })

        return self.findings

    def scan_mcp_config(self, file_path: str) -> List[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check for hardcoded secrets
        for match in SECRET_REGEX.finditer(content):
            self.findings.append({
                "severity": "CRITICAL",
                "category": "CWE-798 Hardcoded Secrets",
                "file": str(path),
                "target": "credential_declaration",
                "message": f"Hardcoded credential/API key discovered: {match.group(0)[:10]}..."
            })

        try:
            data = json.loads(content) if path.suffix == ".json" else yaml.safe_load(content)
        except Exception:
            return self.findings

        # Scan MCP tool permissions if declared
        mcp_servers = data.get("mcpServers", {})
        for srv_name, srv_conf in mcp_servers.items():
            tools = srv_conf.get("tools", [])
            for t in tools:
                if not t.get("scopes") or not t.get("risk_tier"):
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "MCP Security: Unscoped Tool Permission",
                        "file": str(path),
                        "target": f"Server {srv_name} -> Tool {t.get('name', 'unknown')}",
                        "message": "MCP tool defined without explicit least-privilege permission scoping."
                    })

        return self.findings

    def run_audit(self, target_dir: str) -> int:
        print(f"[*] Starting Sentinel Shift-Left API & MCP Security Scan on: {target_dir}")
        base = Path(target_dir)

        # Scan OpenAPI / Swagger
        for ext in ["*.json", "*.yaml", "*.yml"]:
            for f in base.glob(f"**/{ext}"):
                if "openapi" in f.name.lower() or "swagger" in f.name.lower():
                    self.scan_openapi_spec(str(f))
                if "mcp" in f.name.lower():
                    self.scan_mcp_config(str(f))

        critical_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")

        print("\n--- AUDIT REPORT ---")
        if not self.findings:
            print("[+] PASS: Zero security violations detected. Shift-left gate approved.")
            return 0

        for f in self.findings:
            print(f"[{f['severity']}] {f['category']} - {f['target']}: {f['message']}")

        print(f"\nTotal findings: {len(self.findings)} (Critical: {critical_count}, High: {high_count})")
        if critical_count > 0 or high_count > 0:
            print("[-] GATE FAILED: Security findings exceed CI/CD deployment threshold.")
            return 1
        return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = APIMCPShiftLeftScanner()
    sys.exit(scanner.run_audit(target))
