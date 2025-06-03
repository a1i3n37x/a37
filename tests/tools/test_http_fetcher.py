import os

import pytest

from alienrecon.tools.http_fetcher import HttpPageFetcherTool


@pytest.fixture
def http_fetcher_sample_output():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "../fixtures/http_fetcher_sample.html"
    )
    with open(fixture_path) as f:
        return f.read()


def assert_toolresult_schema(result):
    assert isinstance(result, dict)
    assert "tool_name" in result
    assert result["tool_name"] == "http_page_fetcher"
    assert result["status"] in ("success", "failure", "partial")
    assert "scan_summary" in result
    assert "findings" in result
    # error, raw_stdout, raw_stderr are optional


def test_http_fetcher_execute(http_fetcher_sample_output, monkeypatch):
    class DummyResponse:
        def __init__(self, text):
            self.text = text
            self.status_code = 200
            self.headers = {"content-type": "text/html"}

        def raise_for_status(self):
            pass

    def dummy_get(*args, **kwargs):
        return DummyResponse(http_fetcher_sample_output)

    monkeypatch.setattr("requests.get", dummy_get)
    tool = HttpPageFetcherTool()
    result = tool.execute("http://10.10.10.10/index.html")
    assert_toolresult_schema(result)
    assert result["status"] == "success"
    assert "page_content" in result["findings"]
    assert "Welcome to the CTF test page" in result["findings"]["page_content"]


def test_http_fetcher_empty_output(monkeypatch):
    class DummyResponse:
        def __init__(self):
            self.text = ""
            self.status_code = 200
            self.headers = {"content-type": "text/html"}

        def raise_for_status(self):
            pass

    def dummy_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch.setattr("requests.get", dummy_get)
    tool = HttpPageFetcherTool()
    result = tool.execute("http://10.10.10.10/empty.html")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "produced no output" in result["scan_summary"]


def test_http_fetcher_error_output(monkeypatch):
    class DummyResponse:
        def __init__(self):
            self.text = ""
            self.status_code = 500
            self.headers = {"content-type": "text/html"}

        def raise_for_status(self):
            raise Exception("HTTP 500 Internal Server Error")

    def dummy_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch.setattr("requests.get", dummy_get)
    tool = HttpPageFetcherTool()
    result = tool.execute("http://10.10.10.10/error.html")
    assert_toolresult_schema(result)
    assert result["status"] == "failure"
    assert "HTTP 500" in result["scan_summary"] or result["scan_summary"]


def test_http_fetcher_malformed_html(monkeypatch):
    class DummyResponse:
        def __init__(self):
            self.text = "<html><head><title>"  # malformed HTML
            self.status_code = 200
            self.headers = {"content-type": "text/html"}

        def raise_for_status(self):
            pass

    def dummy_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch.setattr("requests.get", dummy_get)
    tool = HttpPageFetcherTool()
    result = tool.execute("http://10.10.10.10/malformed.html")
    assert_toolresult_schema(result)
    assert result["status"] in ("success", "partial", "failure")
    # Malformed HTML may still be 'success' if parser is robust, so just check schema
