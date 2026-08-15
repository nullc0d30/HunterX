from hunterx.platform import build_platform

plat = build_platform()
svc = plat.tool_readiness_service
for tid in ["tcp-connect", "traceroute", "crt-sh", "openapi-parser", "postman-parser", "crobat", "sstimap"]:
    d = svc._definitions.build(tid)
    if d is None:
        print(tid, "NO DEFINITION")
        continue
    print(tid, "kind=", d.kind, "exe=", repr(d.executable), "caps=", d.capabilities)
