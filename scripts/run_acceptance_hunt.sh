#!/bin/bash
# Acceptance hunt launcher — fully detached, logs everything.
export HUNTERX_RESOURCE_TOOL_TIMEOUT_S=120
LOG=/opt/hunterx/reports/acceptance_hunt_console.log
cd /root
sudo hunterx hunt --json --output /opt/hunterx/reports/acceptance full_security_assessment http://localhost:3010 >> "$LOG" 2>&1
echo "" >> "$LOG"
echo "HUNT_EXIT_CODE=$?" >> "$LOG"
