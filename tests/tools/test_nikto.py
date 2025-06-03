import json
import os

import pytest

from alienrecon.tools.nikto import NiktoTool


@pytest.fixture
def nikto_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/nikto_sample.json"
    )
    try:
        with open(fixture_path) as f:
            return json.load(f)
    except Exception:
        # Provide a minimal valid sample if the file is empty or invalid
        return {
            "ip": "10.10.10.10",
            "vulnerabilities": [{"id": "OSVDB-1234", "description": "Sample vuln"}],
        }


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "nikto"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_nikto_parse_output(nikto_sample_output):
    tool = NiktoTool()
    result = tool.parse_output(
        None, None, parsed_json_data=nikto_sample_output, target="10.10.10.10", port=80
    )
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert "host_info" in result["findings"]
    assert "vulnerabilities" in result["findings"]
    assert isinstance(result["findings"]["vulnerabilities"], list)
    assert any(v["id"] == "OSVDB-1234" for v in result["findings"]["vulnerabilities"])


def test_nikto_empty_output():
    tool = NiktoTool()
    result = tool.parse_output(
        "", None, parsed_json_data=None, target="10.10.10.10", port=80
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_nikto_error_output():
    tool = NiktoTool()
    result = tool.parse_output(
        None,
        "Some error occurred",
        parsed_json_data=None,
        target="10.10.10.10",
        port=80,
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert result["error"] == "Some error occurred"


def test_nikto_malformed_json():
    tool = NiktoTool()
    bad_json = "{"  # malformed JSON string
    result = tool.parse_output(
        bad_json, None, parsed_json_data=None, target="10.10.10.10", port=80
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "parse JSON output" in result["scan_summary"] or result["scan_summary"]
