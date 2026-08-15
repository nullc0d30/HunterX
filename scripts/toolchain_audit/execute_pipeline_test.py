"""Prove the full execution pipeline: preflight sync -> command construct -> execute -> parse -> observation."""
from __future__ import annotations

import json

from hunterx.platform import build_platform


def main() -> None:
    plat = build_platform()
    service = plat.tool_readiness_service
    toolchain = plat.toolchain_service
    engine = plat.execution_engine

    # 1. Preflight sync (what `hunterx hunt` does before execution)
    preflight = service.preflight(["asset_discovery", "port_discovery", "content_discovery", "proof_validation"])
    print("=== PREFLIGHT ===")
    print("status:", getattr(preflight, "status", "n/a"))
    print("may_execute:", getattr(preflight, "may_execute", "n/a"))

    # 2. After preflight sync, engine should know installed tools
    healthy = [t for t in ["nmap", "subfinder", "httpx", "ffuf", "nuclei"] if engine.health_check(t)]
    print("\n=== ENGINE HEALTH AFTER PREFLIGHT SYNC ===")
    for t in ["nmap", "subfinder", "httpx", "ffuf", "nuclei", "sqlmap"]:
        print(f"  {t}: healthy={engine.health_check(t)}")

    # 3. Execute a safe tool against a harmless target
    print("\n=== EXECUTE (nmap -p 443 example.com) ===")
    result = toolchain.execute("nmap", "example.com", parameters={"ports": "443"}, scope="example.com")
    print("execution_id:", result.get("execution_id"))
    print("status:", result.get("status"))

    # 4. Parse the stored output
    execution_id = result.get("execution_id")
    parsed = toolchain.inspect_result(execution_id) if execution_id else {}
    print("\n=== PARSED RESULT ===")
    print(json.dumps(parsed, indent=1)[:800])


if __name__ == "__main__":
    main()
