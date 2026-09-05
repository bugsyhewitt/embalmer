# Worker output: ci: un-dark VEX + autopsy tests (drop --ignore)

## Change

Single-line edit to `.github/workflows/ci.yml`:

```diff
-      - run: pytest -m "not integration" --ignore=tests/test_autopsy.py --ignore=tests/test_vex.py --ignore=tests/test_vex_override.py
+      - run: pytest -m "not integration"
```

## Verification

- All three previously-ignored files were confirmed free of binwalk references.
- `binary-pipeline` git dependency resolves correctly via `pip install -e ".[dev]"` — no `importorskip` guard needed in `test_autopsy.py`.
- `ruff check embalmer/` passes with no changes.
- 66 newly-included tests (29 test_vex + 26 test_vex_override + 11 test_autopsy) all PASSED.
- Full suite: 798 passed, 5 deselected (integration markers), 4 errors in test_wheel_ship_gate.py (pre-existing: `python -m build` unavailable in venv; unrelated to this change).
