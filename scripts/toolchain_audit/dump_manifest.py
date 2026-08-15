import json, sys

d = json.load(open('capabilities/full-toolchain-intelligence.json'))
t = d['tools']
print("TOOL_COUNT:", len(t))
for k, v in sorted(t.items()):
    print(f"{k:22} | {v['category']:12} | {v['support_level']:18} | adapter={v.get('adapter', 'NONE')} | parser={v.get('parser', 'NONE')} | caps={','.join(v.get('capabilities', []))}")
