"""Capture milestone screenshots from collected evidence (text snapshots)."""
import glob
import json
import os

BASE = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
TS = sorted(glob.glob(f"{BASE}/*/"))[-1].split("/")[-2]
base = f"{BASE}/{TS}"
S = f"{base}/screenshots"
os.makedirs(S, exist_ok=True)


def snap(name, text):
    open(f"{S}/{name}.txt", "w").write(text)
    print("captured", name)


def load(name):
    try:
        return json.load(open(f"{base}/evidence/{name}.json"))
    except Exception:
        return {}


# 04-mission-created
try:
    m = json.load(open(f"{base}/telemetry/mission.json"))
    snap("04-mission-created", json.dumps({
        "mission_id": m.get("mission_id"),
        "target": m.get("target", "https://juice-shop.herokuapp.com"),
        "objective": m.get("objective"),
    }, indent=1))
except Exception as e:
    snap("04-mission-created", str(e))

# 05-target-model
snap("05-target-model", "nmap top-50:\n" + load("nmap-top50").get("stdout", "")[:900])

# 06-recon
snap("06-recon", load("http-headers").get("stdout", "")[:1100])

# 07-technology-discovery
try:
    t = json.load(open(f"{base}/telemetry/target-assessment.json"))
    tech = [s for s in t["steps"] if s["label"] in ("http-probing", "tech-fingerprint")]
    snap("07-technology-discovery", json.dumps(tech, indent=1)[:1200])
except Exception as e:
    snap("07-technology-discovery", str(e))

# 08-endpoint-discovery
try:
    k = open(f"{base}/evidence/katana-urls.txt").read()
    snap("08-endpoint-discovery", f"katana discovered {len(k.splitlines())} URLs:\n" + k[:1300])
except Exception as e:
    snap("08-endpoint-discovery", str(e))

# 09-parameter-discovery
v = load("vuln-probes")
snap("09-parameter-discovery", json.dumps({k: (v2.get("code") if isinstance(v2, dict) else "?") for k, v2 in v.items()}, indent=1))

# 12-vulnerability-discovery
snap("12-vulnerability-discovery", json.dumps(load("sqli-verification"), indent=1)[:1400])

print("done")
