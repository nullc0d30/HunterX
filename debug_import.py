import sys
import traceback

try:
    from hunterx.config.settings import AISettings
    print('Import successful')
except Exception as e:
    print('Import error:', e)
    traceback.print_exc()

import ast
with open('src/hunterx/config/settings.py', 'r') as f:
    source = f.read()
try:
    tree = ast.parse(open('src/hunterx/config/settings.py').read())
    print('AST parse OK')
except SyntaxError as e:
    print(f'Syntax error: {e}')
    print(f'Line {e.lineno}, offset {e.offset}')
    lines = open('src/hunterx/config/settings.py').readlines()
    if e.lineno <= len(open('src/hunterx/config/settings.py').readlines()):
        print(f'Line {e.lineno}: {open("src/hunterx/config/settings.py").readlines()[e.lineno-1].rstrip()}')