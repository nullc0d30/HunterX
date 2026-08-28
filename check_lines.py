with open('src/hunterx/config/settings.py', 'rb') as f:
    content = f.read()
lines = content.split(b'\n')
for i, line in enumerate(lines[105:115], 107):
    print(f'{i}: {line}')
    print(f'  Length: {len(line)}')
    print(f'  Ends with CRLF: {line.endswith(b"\r")}')