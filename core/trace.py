# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import json
import os
from datetime import datetime

class TraceLogger:
    def __init__(self, output_dir="reports"):
        from .legal import get_copyright_text, get_disclaimer
        self.log_file = os.path.join(output_dir, "attack_trace.log")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(self.log_file, "w") as f:
            f.write("HunterX Attack Trace Log\n")
            f.write(f"{get_copyright_text()}\n")
            f.write(f"Started: {datetime.now().isoformat()}\n")
            f.write(f"{get_disclaimer()}\n")
            f.write("-" * 60 + "\n")
            
    def log(self, event_type: str, message: str, data: dict = None):
        """
        Log a decision or event in the attack trace.
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "message": message,
            "data": data or {}
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
