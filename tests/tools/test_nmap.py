import os

import pytest

from alienrecon.tools.nmap import NmapTool


@pytest.fixture
def nmap_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/nmap_sample.xml"
    )
    with open(fixture_path) as f:
        return f.read()


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "nmap"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_nmap_parse_output(nmap_sample_output):
    tool = NmapTool()
    result = tool.parse_output(nmap_sample_output, None, target="10.10.10.10")
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert "hosts" in result["findings"]
    hosts = result["findings"]["hosts"]
    assert isinstance(hosts, list)
    assert len(hosts) == 1
    host = hosts[0]
    assert host["host"] == "10.10.10.10"
    assert any(p["port"] == 22 for p in host["open_ports"])
    assert any(p["port"] == 80 for p in host["open_ports"])


def test_nmap_empty_output():
    tool = NmapTool()
    result = tool.parse_output("", None, target="10.10.10.10")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_nmap_error_output():
    tool = NmapTool()
    result = tool.parse_output(None, "Some error occurred", target="10.10.10.10")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert result["error"] == "Some error occurred"


def test_nmap_malformed_xml():
    tool = NmapTool()
    bad_xml = "<nmaprun><host><status state='up'/></host>"  # missing closing tags
    result = tool.parse_output(bad_xml, None, target="10.10.10.10")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "parse XML output" in result["scan_summary"]
