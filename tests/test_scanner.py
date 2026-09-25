import tempfile
import os
import json
from scanner.api_mcp_scanner import APIMCPShiftLeftScanner

def test_scanner_flags_insecure_openapi():
    insecure_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test Insecure API", "version": "1.0"},
        "paths": {
            "/api/v1/insecure-users": {
                "get": {
                    "summary": "List all users without auth",
                    # No security key!
                }
            }
        }
    }
    with tempfile.NamedTemporaryFile("w", suffix="_openapi.json", delete=False) as f:
        json.dump(insecure_spec, f)
        temp_path = f.name

    try:
        scanner = APIMCPShiftLeftScanner()
        findings = scanner.scan_openapi_spec(temp_path)
        assert len(findings) > 0
        assert any(f["category"] == "OWASP API2:2023 Broken Authentication" for f in findings)
    finally:
        os.remove(temp_path)

def test_scanner_flags_hardcoded_secret():
    mcp_config = """
    mcpServers:
      enterprise-db:
        command: "python"
        env:
          API_KEY: "sk_live_12345678901234567890"
    """
    with tempfile.NamedTemporaryFile("w", suffix="_mcp.yaml", delete=False) as f:
        f.write(mcp_config)
        temp_path = f.name

    try:
        scanner = APIMCPShiftLeftScanner()
        findings = scanner.scan_mcp_config(temp_path)
        assert len(findings) > 0
        assert any("Hardcoded Secrets" in f["category"] for f in findings)
    finally:
        os.remove(temp_path)
