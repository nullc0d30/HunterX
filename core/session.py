# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import requests
import time
import random
from urllib3.exceptions import InsecureRequestWarning
from .config import config
from .utils import logger

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class StealthSession:
    """
    Wrapper around requests.Session to provide stealth capabilities:
    - Random User-Agent (Per Session)
    - Randomized request delays (Jitter)
    - Adaptive Backoff on 429/Errors
    - CAPTCHA detection
    """
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._rotate_ua()
        self.session.headers.update(config.base_headers)
        
        # Anti-Ban State
        self.consecutive_errors = 0
        self.current_delay = config.min_delay

    def _rotate_ua(self):
        """Rotate User-Agent from config."""
        ua = random.choice(config.user_agents)
        self.session.headers.update({"User-Agent": ua})

    def request(self, method: str, url: str, **kwargs):
        """
        Execute request with stealth logic.
        """
        # 1. Adaptive Delay & Jitter
        jitter = random.uniform(0, 0.5)
        time.sleep(self.current_delay + jitter)

        # 2. Add Timeout if not present
        if "timeout" not in kwargs:
            kwargs["timeout"] = config.timeout

        try:
            response = self.session.request(method, url, **kwargs)
            
            # 3. Anti-Ban Logic
            if response.status_code == 429:
                logger.warning("Rate limit detected (429). Backing off...")
                self._handle_backoff(response)
                return None # Signal to engine to retry or skip
                
            if response.status_code >= 500:
                self.consecutive_errors += 1
                if self.consecutive_errors > 5:
                    logger.warning("Critical: Consecutive server errors. Pausing scan.")
                    time.sleep(10)
            else:
                self.consecutive_errors = 0
                # Slowly recover delay
                self.current_delay = max(config.min_delay, self.current_delay * 0.9)

            # 4. CAPTCHA Check
            if self._is_captcha(response):
                logger.critical("CAPTCHA detected! Aborting request flow.")
                time.sleep(30) # Hard pause
                return None

            return response

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed: {url} | Error: {e}")
            self.consecutive_errors += 1
            return None 

    def _handle_backoff(self, response):
        """Increase delay exponentially based on retry-after or default."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                wait = int(retry_after)
            except:
                wait = 10
        else:
            wait = 5 * (2 ** min(self.consecutive_errors, 4))
        
        logger.info(f"Sleeping for {wait}s due to backoff.")
        time.sleep(wait)
        self.current_delay = min(config.max_delay, self.current_delay * 2)

    def _is_captcha(self, response) -> bool:
        """Check content for captcha indicators."""
        text = response.text.lower()
        if "captcha" in text or "turnstile" in text or "challenge-form" in text:
            return True
        return False

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)
