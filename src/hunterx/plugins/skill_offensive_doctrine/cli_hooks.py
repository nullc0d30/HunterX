from __future__ import annotations
from hunterx.plugins.skill_offensive_doctrine.state_block import DoctrineState
from hunterx.plugins.skill_offensive_doctrine.activator import confirmation_message

_state = DoctrineState()

def _state_handler(argv: list[str]) -> int:
    print(_state.summary())
    return 0

def _doctrine_on_handler(argv: list[str]) -> int:
    print(confirmation_message())
    return 0

def register_doctrine_commands(registry):
    registry.register("state", _state_handler, help_text="Show doctrine state block")
    registry.register("doctrine on", _doctrine_on_handler, help_text="Activate offensive security doctrine")
