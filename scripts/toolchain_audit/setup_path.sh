#!/usr/bin/env bash
set -euo pipefail

cat > /etc/profile.d/hunterx-tools-path.sh <<'EOF'
# HunterX toolchain PATH (go/cargo/local bin dirs) - managed by toolchain audit
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
EOF
chmod 644 /etc/profile.d/hunterx-tools-path.sh
echo "WROTE /etc/profile.d/hunterx-tools-path.sh"
cat /etc/profile.d/hunterx-tools-path.sh
