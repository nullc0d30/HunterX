# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from rich.console import Console
from rich.logging import RichHandler
import logging
import random
import string

# Setup Rich Console
console = Console()

def setup_logger(level="INFO"):
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)]
    )
    return logging.getLogger("hunterx")

logger = setup_logger()

def random_string(length=8):
    """Generate a random string for cache busting or markers."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
