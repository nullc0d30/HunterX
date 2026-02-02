# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from dataclasses import dataclass
import hashlib
from .session import StealthSession
from .utils import logger

@dataclass
class Fingerprint:
    url: str
    status_code: int
    content_length: int
    headers: dict
    body_hash: str
    response_time: float
    text: str
    # V2 Additions
    server_banner: str = ""
    error_hash: str = ""
    redirect_target: str = ""

class Fingerprinter:
    def __init__(self, session: StealthSession):
        self.session = session

    def baseline(self, url: str) -> Fingerprint:
        """
        Establish a baseline for the target URL.
        """
        logger.info(f"Fingerprinting baseline for: {url}")
        resp = self.session.get(url)
        
        if not resp:
            logger.error("Failed to get baseline response")
            return None

        body_hash = hashlib.md5(resp.content).hexdigest()
        
        fp = Fingerprint(
            url=url,
            status_code=resp.status_code,
            content_length=len(resp.content),
            headers=dict(resp.headers),
            body_hash=body_hash,
            response_time=resp.elapsed.total_seconds(),
            text=resp.text,
            server_banner=resp.headers.get("Server", "") or resp.headers.get("X-Powered-By", ""),
            error_hash=hashlib.md5(resp.text.encode()).hexdigest() if resp.status_code >= 400 else "",
            redirect_target=resp.headers.get("Location", "")
        )
        logger.debug(f"Baseline established: Status={fp.status_code}, Length={fp.content_length}, Banner={fp.server_banner}")
        return fp
