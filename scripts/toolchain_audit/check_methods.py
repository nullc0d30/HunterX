import json

from hunterx.tools.readiness.manifest import INSTALL_METHODS

for t in [
    "netexec", "impacket", "enum4linux-ng", "massdns", "gauplus", "jsluice",
    "xxeinjector", "kiterunner", "codeql", "metasploit", "searchsploit", "zap",
    "trivy", "syft", "grype", "kube-bench", "crobat", "jwt-tool", "openvas",
    "exploitdb", "sstimap", "wapiti", "linkfinder",
]:
    methods = INSTALL_METHODS.get(t, [])
    print(t, "->", json.dumps([m.to_dict() for m in methods]) if methods else "NONE")
