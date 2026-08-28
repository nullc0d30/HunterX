import sys

try:
    with open('src/hunterx/config/settings.py', 'r') as f:
        code = f.read()
    compile(code, 'settings.py', 'exec')
    print('Syntax OK')
except SyntaxError as e:
    print(f'Syntax error: {e}')
    print(f'Line {e.lineno}, offset {e.offset}')
    lines = open('src/hunterx/config/settings.py').readlines()
    if e.lineno <= len(open('src/hunterx/config/settings.py').readlines()):
        print(f'Line {e.lineno}: {open("src/hunterx/config/settings.py").readlines()[e.lineno-1].rstrip()}')