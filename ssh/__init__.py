
"""

SSH emulator with paramiko + fake shell
"""


from .server import SSHHoneypot
from .fake_shell import handle_command, get_prompt

__all__ = ["SSHHoneypot","handle", "get_prompt"]
