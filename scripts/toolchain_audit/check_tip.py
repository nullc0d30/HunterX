import json

from hunterx.tools.intelligence.api import ToolIntelligenceAPI

m = json.load(open("/home/nc/hunterx/HunterX/capabilities/full-toolchain-intelligence.json"))
t = m["tools"]
print("tcp-connect in manifest:", "tcp-connect" in t)
print("traceroute in manifest:", "traceroute" in t)
tip = ToolIntelligenceAPI()
ids = sorted(meta.tool_id for meta in tip.list_tools())
print("TIP tools count:", len(ids))
extra = [i for i in ids if i not in t]
print("extra TIP not in manifest:", extra)
print("manifest not in TIP:", [i for i in t if i not in ids])
