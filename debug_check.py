import sys
for mod in list(sys.modules.keys()):
    if 'hunterx' in mod:
        del sys.modules[mod]

import hunterx.config.settings as settings_module
cls = settings_module.AISettings

print('Class __dict__ keys (non-private):')
for k in sorted(cls.__dict__.keys()):
    if not k.startswith('_'):
        print(f'  {k}')

print()
print('Checking for field definitions in class __dict__:')
for field in ['provider', 'model', 'base_url', 'timeout', 'lmstudio_key', 'ollama_key', 'openai_compatible_key']:
    print(f'  {field} in cls.__dict__: {field in cls.__dict__}')

print()
print('Annotations:')
for k, v in cls.__annotations__.items():
    print(f'  {k}: {v}')