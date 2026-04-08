import os
from pathlib import Path
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        key_path = Path(os.environ["HOME"]) / ".ssh" / "id_ed25519"
        try:
            key_path.read_text()
            raise SystemExit("🚨 shit! private key is being read")
        except FileNotFoundError as e:
            raise SystemExit(f"🛡️ safe! private key access is blocked: {e}")
        except PermissionError as e:
            raise SystemExit(f"🛡️ safe! private key access is blocked: {e}")
        except OSError as e:
            raise SystemExit(f"🛡️ safe! private key access is blocked: {e}")
