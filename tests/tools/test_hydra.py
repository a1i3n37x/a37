import os

import pytest

from alienrecon.tools.hydra import HydraTool


@pytest.fixture
def hydra_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/hydra_sample.txt"
    )
    with open(fixture_path) as f:
        return f.read()


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "hydra"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_hydra_parse_output(hydra_sample_output):
    tool = HydraTool()
    result = tool.parse_output(
        hydra_sample_output,
        None,
        target="10.10.10.10",
        username="admin",
        service_protocol="http-get",
        port=80,
    )
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert "host" in result["findings"] or "raw_stdout_sample" in result["findings"]
    if "host" in result["findings"]:
        assert result["findings"]["username"] == "admin"
        assert result["findings"]["password"] == "password123"


def test_hydra_empty_output():
    tool = HydraTool()
    result = tool.parse_output(
        "",
        None,
        target="10.10.10.10",
        username="admin",
        service_protocol="http-get",
        port=80,
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_hydra_error_output():
    tool = HydraTool()
    result = tool.parse_output(
        None,
        "Some error occurred",
        target="10.10.10.10",
        username="admin",
        service_protocol="http-get",
        port=80,
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert result["error"] == "Some error occurred"


def test_hydra_malformed_output():
    tool = HydraTool()
    bad_output = "random non-hydra text that cannot be parsed"
    result = tool.parse_output(
        bad_output,
        None,
        target="10.10.10.10",
        username="admin",
        service_protocol="http-get",
        port=80,
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "parse output" in result["scan_summary"] or result["scan_summary"]
