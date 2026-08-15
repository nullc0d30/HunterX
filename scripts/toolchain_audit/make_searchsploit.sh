#!/usr/bin/env bash
set -euo pipefail
cat > /home/nc/.local/bin/searchsploit <<'WRAP'
#!/usr/bin/env bash
cd /opt/hunterx-tools/exploitdb || exit 1
exec /usr/bin/perl /opt/hunterx-tools/exploitdb/searchsploit "$@"
WRAP
chmod +x /home/nc/.local/bin/searchsploit
chmod +x /opt/hunterx-tools/exploitdb/searchsploit
/home/nc/.local/bin/searchsploit --version 2>&1 | head -2
echo "EXIT: $?"
