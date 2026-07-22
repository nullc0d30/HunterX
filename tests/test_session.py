# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock
from core.config import config
from core.session import StealthSession


def test_session_init():
    s = StealthSession()
    assert s.consecutive_errors == 0
    assert s.current_delay == config.min_delay
    assert s._bucket_capacity == config.max_rps
    assert s._bucket_tokens == config.max_rps


def test_session_rotate_ua():
    s = StealthSession()
    old_ua = s.session.headers.get("User-Agent")
    s._rotate_ua()
    new_ua = s.session.headers.get("User-Agent")
    assert isinstance(new_ua, str)
    assert len(new_ua) > 10


def test_session_captcha_detection():
    s = StealthSession()
    mock_resp = MagicMock()
    mock_resp.text = "Please solve this captcha to continue"
    mock_resp.status_code = 200
    assert s._is_captcha(mock_resp) is True


def test_session_no_captcha():
    s = StealthSession()
    mock_resp = MagicMock()
    mock_resp.text = "Welcome to the admin panel"
    mock_resp.status_code = 200
    assert s._is_captcha(mock_resp) is False


def test_session_backoff_calc():
    s = StealthSession()
    mock_resp = MagicMock()
    mock_resp.headers = {"Retry-After": "5"}
    s.consecutive_errors = 1
    s._handle_backoff(mock_resp)
    assert s.current_delay > config.min_delay


def test_session_backoff_no_header():
    s = StealthSession()
    mock_resp = MagicMock()
    mock_resp.headers = {}
    s.consecutive_errors = 2
    s._handle_backoff(mock_resp)
    assert s.current_delay > config.min_delay
