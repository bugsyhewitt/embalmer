"""Enable `python -m embalmer ...` (mirrors the `embalmer` console script)."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
