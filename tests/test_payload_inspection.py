import pytest
from fastapi import HTTPException
from src.gateway.payload_inspector import payload_inspector

def test_detect_sqli():
    threats = payload_inspector.inspect_text("SELECT * FROM users WHERE id = 1 OR 1=1")
    assert len(threats) > 0
    assert any("SQL Injection" in t for t in threats)

def test_detect_command_injection():
    threats = payload_inspector.inspect_text("test_file.txt; rm -rf /")
    assert len(threats) > 0
    assert any("OS Command Injection" in t for t in threats)

def test_detect_path_traversal():
    threats = payload_inspector.inspect_text("../../etc/passwd")
    assert len(threats) > 0
    assert any("Path Traversal" in t for t in threats)

def test_safe_payload_passes():
    threats = payload_inspector.inspect_text("Normal safe user title and search query")
    assert len(threats) == 0

def test_enforce_safe_payload_exception():
    with pytest.raises(HTTPException) as exc:
        payload_inspector.enforce_safe_payload(b"title", parsed_json={"query": "UNION SELECT 1,2,3--"})
    assert exc.value.status_code == 400
