"""Operator commands: python -m tools.sandbox.cli {diagnose,token,cleanup}."""

import argparse
import json

from tools.sandbox.api import local_access_token
from tools.sandbox.local_service import get_local_service


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["diagnose", "token", "cleanup"])
    args = parser.parse_args()
    # Pairing only reads an operator secret; it must work while the server owns the worker lock.
    if args.action == "token":
        from tools.sandbox.store import SandboxStore

        print(local_access_token(SandboxStore().root))
        return
    if args.action == "diagnose":
        from tools.sandbox.local_service import LocalSandboxService

        print(json.dumps(LocalSandboxService().provider.diagnose(), indent=2))
    else:
        service = get_local_service()
        service.recover()
        print("Managed sandboxes stopped")


if __name__ == "__main__":
    main()
