import threading
import time
import random
import requests
from urllib3.exceptions import InsecureRequestWarning

from .config import config
from .utils import logger
from .auth import setup_auth

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RateLimitError(Exception):
    pass


class CaptchaError(Exception):
    pass


class StealthSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._rotate_ua()
        self.session.headers.update(config.base_headers)

        # Auth setup if configured
        if config.auth.type != "none":
            auth_ctx = setup_auth(self.session, config.auth)
            if auth_ctx.authenticated:
                logger.info(f"Authenticated using {config.auth.type} method")

        # Anti-Ban State
        self.consecutive_errors = 0
        self.current_delay = config.min_delay

        # Token bucket rate limiter
        self._bucket_capacity = config.max_rps
        self._bucket_tokens = config.max_rps
        self._bucket_last_refill = time.time()
        self._bucket_lock = threading.Lock()

    def _rotate_ua(self):
        ua = random.choice(config.user_agents)
        self.session.headers.update({"User-Agent": ua})

    def _consume_token(self):
        with self._bucket_lock:
            now = time.time()
            elapsed = now - self._bucket_last_refill
            self._bucket_tokens = min(self._bucket_capacity, self._bucket_tokens + elapsed * self._bucket_capacity)
            self._bucket_last_refill = now
            if self._bucket_tokens < 1:
                sleep_time = (1 - self._bucket_tokens) / self._bucket_capacity
                time.sleep(sleep_time)
                self._bucket_tokens = 0
            else:
                self._bucket_tokens -= 1

    def request(self, method: str, url: str, **kwargs):
        self._consume_token()

        jitter = random.uniform(0, 0.5)
        time.sleep(self.current_delay + jitter)

        if "timeout" not in kwargs:
            kwargs["timeout"] = config.timeout

        try:
            response = self.session.request(method, url, **kwargs)

            if response.status_code == 429:
                logger.warning("Rate limit detected (429). Backing off...")
                self.consecutive_errors += 1
                self._handle_backoff(response)
                raise RateLimitError("Rate limited (429)")

            if response.status_code >= 500:
                self.consecutive_errors += 1
                if self.consecutive_errors > 5:
                    logger.warning("Critical: Consecutive server errors. Pausing scan.")
                    time.sleep(10)
            else:
                self.consecutive_errors = 0
                self.current_delay = max(config.min_delay, self.current_delay * 0.9)

            if self._is_captcha(response):
                logger.critical("CAPTCHA detected! Aborting request flow.")
                time.sleep(30)
                raise CaptchaError("CAPTCHA detected")

            return response

        except (RateLimitError, CaptchaError):
            raise
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed: {url} | Error: {e}")
            self.consecutive_errors += 1
            return None

    def _handle_backoff(self, response):
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                wait = int(retry_after)
            except (ValueError, TypeError):
                wait = 10
        else:
            wait = 5 * (2 ** min(self.consecutive_errors, 4))

        logger.info(f"Sleeping for {wait}s due to backoff.")
        time.sleep(wait)
        self.current_delay = min(config.max_delay, self.current_delay * 2)

    def _is_captcha(self, response) -> bool:
        text = response.text.lower()
        if "captcha" in text or "turnstile" in text or "challenge-form" in text:
            return True
        return False

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)
