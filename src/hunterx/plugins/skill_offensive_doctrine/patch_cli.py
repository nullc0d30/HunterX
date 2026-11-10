from __future__ import annotations
"""Patch register_default_commands to add doctrine commands."""

def patch_register_default_commands():
    from hunterx.cli import commands as cli_commands
    from hunterx.plugins.skill_offensive_doctrine.cli_hooks import register_doctrine_commands
    
    original = cli_commands.register_default_commands
    
    def wrapped(app, platform=None):
        original(app, platform)
        register_doctrine_commands(app.registry)
    
    cli_commands.register_default_commands = wrapped
