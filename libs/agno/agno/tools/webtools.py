from typing import List, Optional
from urllib.parse import urlparse

import httpx

from agno.tools import Toolkit
from agno.utils.log import logger

# Private IP ranges that should not be accessed (SSRF protection)
_PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "0.",
    "169.254.",  # link-local
)

_PRIVATE_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)


def _is_private_url(url: str) -> bool:
    """Check if a URL points to a private/internal address."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check for private hostnames
        if hostname.lower() in _PRIVATE_HOSTNAMES:
            return True

        # Check for private IP prefixes
        if any(hostname.startswith(prefix) for prefix in _PRIVATE_IP_PREFIXES):
            return True

        # Block file:// and other non-http schemes
        if parsed.scheme not in ("http", "https"):
            return True

        return False
    except Exception:
        return True  # Block on parse error


class WebTools(Toolkit):
    """
    A toolkit for working with web-related tools.
    """

    def __init__(
        self,
        retries: int = 3,
        expand_url: bool = True,
        allowed_hosts: Optional[List[str]] = None,
        block_private: bool = True,
        **kwargs,
    ):
        self.retries = retries
        self.allowed_hosts = allowed_hosts
        self.block_private = block_private

        tools = []
        if expand_url:
            tools.append(self.expand_url)

        super().__init__(name="web_tools", tools=tools, **kwargs)

    def _is_url_allowed(self, url: str) -> bool:
        """Check if a URL is allowed based on SSRF protections."""
        if self.block_private and _is_private_url(url):
            return False

        if self.allowed_hosts:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
                if hostname.lower() not in [h.lower() for h in self.allowed_hosts]:
                    return False
            except Exception:
                return False

        return True

    def expand_url(self, url: str) -> str:
        """
        Expands a shortened URL to its final destination using HTTP HEAD requests with retries.

        :param url: The URL to expand.

        :return: The final destination URL if successful; otherwise, returns the original URL.
        """
        # SSRF protection: validate URL before fetching
        if not self._is_url_allowed(url):
            logger.warning(f"expand_url: URL blocked by SSRF protection: {url}")
            return url

        timeout = 5
        for attempt in range(1, self.retries + 1):
            try:
                response = httpx.head(url, follow_redirects=True, timeout=timeout)
                final_url = str(response.url)

                # Also validate the final URL after redirects
                if not self._is_url_allowed(final_url):
                    logger.warning(f"expand_url: Final URL blocked by SSRF protection: {final_url}")
                    return url

                logger.info(f"expand_url: {url} expanded to {final_url} on attempt {attempt}")
                return final_url
            except Exception:
                logger.exception(f"Error expanding URL {url} on attempt {attempt}")

        return url
