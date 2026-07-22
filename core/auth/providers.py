import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests


@dataclass
class AuthContext:
    """Holds authentication state for a session."""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False
    auth_type: str = "none"


class AuthProvider:
    """Handles authentication setup for different auth types."""

    @staticmethod
    def configure(session: requests.Session, auth_type: str, **kwargs) -> AuthContext:
        ctx = AuthContext(auth_type=auth_type)

        if auth_type == "none":
            return ctx

        if auth_type == "basic":
            username = kwargs.get("username", "")
            password = kwargs.get("password", "")
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(username, password)
            ctx.authenticated = True

        elif auth_type == "bearer":
            token = kwargs.get("token", "")
            if token:
                ctx.headers["Authorization"] = f"Bearer {token}"
                session.headers.update(ctx.headers)
                ctx.authenticated = True

        elif auth_type == "cookie":
            cookie_file = kwargs.get("cookie_file", "")
            if cookie_file and os.path.exists(cookie_file):
                with open(cookie_file) as f:
                    cookies = json.load(f)
                for name, value in cookies.items():
                    session.cookies.set(name, value)
                    ctx.cookies[name] = value
                ctx.authenticated = True

        elif auth_type == "form":
            login_url = kwargs.get("login_url", "")
            login_data = kwargs.get("login_data", {})
            if login_url and login_data:
                resp = session.post(login_url, data=login_data)
                if resp.ok:
                    ctx.authenticated = True

        return ctx


def setup_auth(session: requests.Session, config_auth) -> AuthContext:
    """Convenience wrapper using config dataclass."""
    return AuthProvider.configure(
        session,
        auth_type=getattr(config_auth, "type", "none"),
        username=getattr(config_auth, "username", None),
        password=getattr(config_auth, "password", None),
        token=getattr(config_auth, "token", None),
        cookie_file=getattr(config_auth, "cookie_file", None),
        login_url=getattr(config_auth, "login_url", None),
        login_data=getattr(config_auth, "login_data", {}),
    )
