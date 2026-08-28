import sys
for mod in list(sys.modules.keys()):
    if 'hunterx' in mod:
        del sys.modules[mod]

from hunterx.config.settings import AISettings
import linecache

lines = linecache.getlines('src/hunterx/config/settings.py')
for i, line in enumerate(lines, 1):
    if 94 <= i <= 115:
        print(f'{i}: {line.rstrip()}')