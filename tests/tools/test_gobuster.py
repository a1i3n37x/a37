import os

import pytest

from alienrecon.tools.gobuster import GobusterTool


@pytest.fixture
def gobuster_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/gobuster_sample.txt"
    )
    with open(fixture_path) as f:
        return f.read()


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "gobuster"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_gobuster_parse_output(gobuster_sample_output):
    tool = GobusterTool()
    result = tool.parse_output(
        gobuster_sample_output, None, target_ip="10.10.10.10", port=80
    )
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert isinstance(result["findings"], list)
    paths = [f["path"] for f in result["findings"] if "path" in f]
    assert "/admin" in paths
    assert "/index.html" in paths
    assert any(f["status"] == "200" for f in result["findings"])
    assert any(f["status"] == "301" for f in result["findings"])


def test_gobuster_empty_output():
    tool = GobusterTool()
    result = tool.parse_output("", None, target_ip="10.10.10.10", port=80)
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_gobuster_error_output():
    tool = GobusterTool()
    result = tool.parse_output(
        None, "Some error occurred", target_ip="10.10.10.10", port=80
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert result["error"] == "Some error occurred"


def test_gobuster_malformed_output():
    tool = GobusterTool()
    bad_output = "random non-gobuster text that cannot be parsed"
    result = tool.parse_output(bad_output, None, target_ip="10.10.10.10", port=80)
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "parse output" in result["scan_summary"] or result["scan_summary"]
