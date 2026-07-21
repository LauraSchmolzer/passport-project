"""
    Fetch the CRL from a distribution point
"""
from typing import List, Optional
from ldap3 import Server, Connection
from urllib.parse import urlparse, unquote
import requests

import logging
logger = logging.getLogger(__name__)


def fetch_crl( urls: List[str], timeout: int = 10, user_agent: Optional[str] = None) -> tuple[str | None, bytes | None]:
    headers = {"User-Agent": user_agent} if user_agent else {}

    for url in urls:
        scheme = urlparse(url).scheme.lower()

        try:
            if scheme in ("http", "https"):
                data = fetch_http_crl(url, headers, timeout)
            elif scheme == "ldap":
                data = fetch_ldap_crl(url)
            else:
                logger.debug("Unsupported CRL URL scheme: %s", url)
                continue
        except Exception as exc:
            logger.warning("Failed %s: %s", url, exc)
            continue

        if data is None:
            continue

        logger.info("Fetched %s (%d bytes)", url, len(data))
        return url, data

    return None, None


def fetch_http_crl( url: str, headers: dict, timeout: int) -> bytes | None:
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()

    data = resp.content

    # DER CRLs start with ASN.1 SEQUENCE (0x30)
    if not data or data[0] != 0x30:
        logger.info(
            "Not a DER CRL: %s (content-type=%s)",
            url,
            resp.headers.get("content-type"),
        )
        return None

    return data


def fetch_ldap_crl(url: str) -> bytes | None:
    parsed = urlparse(url)

    host = parsed.hostname
    if not host:
        logger.info("LDAP URL has no hostname: %s", url)
        return None

    dn = unquote(parsed.path.lstrip("/"))

    query = parsed.query.split("?")
    attribute = query[0] if query and query[0] else "certificateRevocationList"

    with Connection(Server(host), auto_bind=True) as conn:
        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            attributes=[attribute],
        )

        if not conn.entries:
            return None

        values = conn.entries[0][attribute].raw_values
        return values[0] if values else None