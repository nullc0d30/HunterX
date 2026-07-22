import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.auth import AuthProvider, AuthContext

def test_auth_none():
    import requests
    session = requests.Session()
    ctx = AuthProvider.configure(session, "none")
    assert ctx.auth_type == "none"
    assert not ctx.authenticated

def test_auth_bearer():
    import requests
    session = requests.Session()
    ctx = AuthProvider.configure(session, "bearer", token="mytoken123")
    assert ctx.authenticated
    assert session.headers.get("Authorization") == "Bearer mytoken123"

def test_auth_context_dataclass():
    ctx = AuthContext(auth_type="bearer", headers={"Authorization": "Bearer test"})
    assert ctx.auth_type == "bearer"
    assert ctx.headers["Authorization"] == "Bearer test"
