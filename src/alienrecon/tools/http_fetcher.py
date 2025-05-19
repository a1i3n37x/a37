import logging
from typing import Any

import requests  # Using requests library

logger = logging.getLogger(__name__)


class HttpPageFetcherTool:
    name: str = "http_page_fetcher"
    description: str = (
        "Fetches the HTML or text content of a given web page for analysis."
    )

    def __init__(self):
        # Could initialize a requests.Session() here if needed for cookies, persistent headers etc.
        # For now, simple requests.get is used.
        pass

    def execute(self, url_to_fetch: str, timeout: int = 15) -> dict[str, Any]:
        """
        Fetches the HTML/text content from the given URL.

        Args:
            url_to_fetch: The full URL to fetch (e.g., "http://10.10.149.215:80/index.html").
            timeout: Request timeout in seconds.

        Returns:
            A dictionary with "scan_summary" and "findings".
            "findings" includes "page_content" (string or None), "status_code" (int),
            and "content_type" (string). Includes an "error" key if fetching fails.
        """
        logger.info(f"Attempting to fetch web content from: {url_to_fetch}")
        findings: dict[str, Any] = {
            "page_content": None,
            "status_code": None,
            "content_type": None,
            "page_content_truncated": False,
            "error": None,
        }
        summary = f"Attempted to fetch content from {url_to_fetch}."

        try:
            headers = {"User-Agent": "AlienRecon-Probe/1.0 (Web Content Sniffer)"}
            # Disable SSL verification for typical CTF environments with self-signed certs.
            # In a production tool for real targets, this would be a security risk.
            response = requests.get(
                url_to_fetch,
                timeout=timeout,
                headers=headers,
                verify=False,
                allow_redirects=True,
            )

            findings["status_code"] = response.status_code
            findings["content_type"] = response.headers.get("content-type", "").lower()

            # Check if the request was successful before trying to read content
            response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)

            if (
                "text/" in findings["content_type"]
            ):  # Broadly check for text-based content types
                # Limit content size to avoid overwhelming the LLM
                # Max 20k chars, roughly 4k-5k tokens. Adjust as needed.
                # Common LLM context windows are much larger now, but cost and processing time are factors.
                max_content_size = 20000
                page_content_raw = response.text

                if len(page_content_raw) > max_content_size:
                    logger.warning(
                        f"Page content from {url_to_fetch} is large ({len(page_content_raw)} bytes). "
                        f"Truncating to {max_content_size} bytes for LLM."
                    )
                    findings["page_content_truncated"] = True
                    findings["page_content"] = page_content_raw[:max_content_size]
                else:
                    findings["page_content"] = page_content_raw

                summary = f"Successfully fetched and processed text content from {url_to_fetch} (Status: {response.status_code})."
            else:
                summary = (
                    f"Fetched resource from {url_to_fetch} (Status: {response.status_code}), "
                    f"but it does not appear to be a primary text-based content type "
                    f"(Content-Type: {findings['content_type']}). "
                    "No page text extracted for direct LLM analysis of content, but metadata is available."
                )
                # findings["page_content"] remains None or could hold a placeholder
                findings["page_content"] = (
                    f"[Non-primary-text content of type: {findings['content_type']}]"
                )

        except requests.exceptions.HTTPError as e:
            summary = f"HTTP error fetching {url_to_fetch}: {e}"
            logger.error(summary)
            findings["error"] = str(e)
            # status_code and content_type might already be set from response.headers if response object exists
            if e.response is not None:
                if findings["status_code"] is None:
                    findings["status_code"] = e.response.status_code
                if findings["content_type"] is None:
                    findings["content_type"] = e.response.headers.get(
                        "content-type", ""
                    ).lower()
        except requests.exceptions.ConnectionError as e:
            summary = f"Connection error fetching {url_to_fetch}: {e}"
            logger.error(summary)
            findings["error"] = str(e)
        except requests.exceptions.Timeout as e:
            summary = f"Timeout fetching {url_to_fetch}: {e}"
            logger.error(summary)
            findings["error"] = str(e)
        except (
            requests.exceptions.RequestException
        ) as e:  # Catch other requests-related exceptions
            summary = f"A network request error occurred fetching {url_to_fetch}: {e}"
            logger.error(summary, exc_info=True)
            findings["error"] = str(e)
        except Exception as e:  # Catch any other unexpected error
            summary = f"An unexpected error occurred while fetching {url_to_fetch}: {e}"
            logger.error(summary, exc_info=True)
            findings["error"] = str(e)

        return {"scan_summary": summary, "findings": findings}
