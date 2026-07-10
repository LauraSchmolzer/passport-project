
from typing import Iterator

from dataclasses import dataclass
from PKD.load.mls import SOURCES, HashSource
from PKD.load.fetch_helpers import fetch
from PKD.load.sha_helpers import sha1, sha256, find_sha

@dataclass
class MLData:
    country : str
    raw: bytes
    sha256_finger: str
    hash_check: bool | None


def load_mls() -> Iterator[MLData]:
    for source in SOURCES:
        raw = fetch(source.ml_url)

        raw_sha = sha256(raw)

        if source.hash_source == HashSource.WEBPAGE:
            web_sha = find_sha(source)
            if source.hash_version == "sha1":
                sha = sha1(raw)
            else:
                sha = raw_sha
            hash_check = (web_sha == sha)
        else:
            hash_check = None

        yield MLData(
            country=source.code,
            raw=raw,
            sha256_finger=raw_sha,
            hash_check=hash_check
        )
