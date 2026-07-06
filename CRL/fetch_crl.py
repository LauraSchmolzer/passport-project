"""
    Fetch the CRL from a distribution point
"""
from typing import List, Optional

import logging
logger = logging.getLogger(__name__)

def fetch_crl(urls: List[str], timeout: int = 10, user_agent: Optional[str] = None):
    import requests
 
    headers = {"User-Agent": user_agent} if user_agent else {}
 
    for url in urls:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            logger.debug(f"  failed {url} -> {exc}")
            continue
 
        if resp.status_code != 200:
            logger.debug(f"  http {resp.status_code} {url}")
            continue
 
        data = resp.content
        # a CRL is DER-encoded ASN.1, starts with 0x30 (SEQUENCE)
        if not data or data[0] != 0x30:
            logger.info(f"  !not a CRL! {url} -> content-type={resp.headers.get('content-type')}, "
                  f"first bytes={data[:16]!r}")
            continue
 
        logger.info(f"  ok {url} ({len(data)} bytes)")
        return url, data
 
    return None, None
   