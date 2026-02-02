# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from .utils import logger
import json
import os
from datetime import datetime

class TraceLogger:
    def __init__(self, output_dir="reports"):
        self.log_file = os.path.join(output_dir, "attack_trace.log")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
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
