import json
import os

import pytest

from alienrecon.tools.smb import SmbTool


@pytest.fixture
def smb_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/enum4linuxng_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "smb_enum"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_smb_parse_output(smb_sample_output):
    tool = SmbTool()
    result = tool.parse_output(
        None, None, parsed_json_data=smb_sample_output, target="10.10.10.10"
    )
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert "users" in result["findings"]
    assert "groups" in result["findings"]
    assert "shares" in result["findings"]
    assert any(u["name"] == "bob" for u in result["findings"]["users"])
    assert any(
        g == "Administrators" or g == "Users"
        for g in [
            x["name"] if isinstance(x, dict) and "name" in x else x
            for x in result["findings"]["groups"]
        ]
    )


def test_smb_empty_output():
    tool = SmbTool()
    result = tool.parse_output("", None, parsed_json_data=None, target="10.10.10.10")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_smb_error_output():
    tool = SmbTool()
    result = tool.parse_output(
        None, "Some error occurred", parsed_json_data=None, target="10.10.10.10"
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert result["error"] == "Some error occurred"


def test_smb_malformed_json():
    tool = SmbTool()
    bad_json = "{"  # malformed JSON string
    result = tool.parse_output(
        bad_json, None, parsed_json_data=None, target="10.10.10.10"
    )
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "parse JSON output" in result["scan_summary"] or result["scan_summary"]
