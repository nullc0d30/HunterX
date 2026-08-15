import json

d = json.load(open("/home/nc/hunterx/HunterX/artifacts/toolchain-audit/category-coverage.json"))
print("total:", d["total_capabilities"], "ready:", d["ready_capabilities"], "missing:", d["missing_capabilities"])
print()
hdr = f"{'CAPABILITY':28} {'LVL':11} {'N':2}  AVAILABLE"
print(hdr)
for c in d["capabilities"]:
    print(f"{c['capability']:28} {c['level']:11} {c['executable_provider_count']:2}  {','.join(c['available'])}")
