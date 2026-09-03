"""Dump the OpenAPI schema to a file.

The running service only serves the schema in development, so anything that
needs it outside a dev box -- a client generator, a diff in CI that catches an
accidental API change -- gets it from here instead.

    make openapi                    # writes docs/openapi.json
    python server/export_openapi.py -   # or to stdout
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Force the documented build regardless of what .env says, and keep the import
# from touching a real database.
os.environ["ZKVAULT_ENVIRONMENT"] = "development"
os.environ.setdefault("ZKVAULT_DATABASE_URL", "sqlite://")

from app.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402


def main() -> int:
    get_settings.cache_clear()
    schema = json.dumps(create_app().openapi(), indent=2, sort_keys=True) + "\n"

    target = sys.argv[1] if len(sys.argv) > 1 else str(HERE.parent / "docs" / "openapi.json")
    if target == "-":
        sys.stdout.write(schema)
        return 0
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(schema)
    print(f"wrote {path} ({len(schema)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
