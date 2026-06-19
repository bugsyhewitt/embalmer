"""Wheel ship-gate tests for embalmer — pin the v0.1.0 install contract.

A v0.1.0 release is shipped iff:
  - the wheel builds cleanly from pyproject.toml,
  - the wheel installs into a fresh venv with no project-local state,
  - the installed package's __version__ matches pyproject.toml,
  - the CLI entry point (`embalmer`) is on PATH and `embalmer --version` works,
  - `python -m embalmer` works (regression pin for __main__.py).

Each test builds its own wheel in a tmp_path so the ship-gate is hermetic.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

pytestmark = pytest.mark.ship_gate


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory) -> Path:
    """Build the wheel + sdist into a temp dir; return the wheel path.

    Uses `python -m build` (system-installed) so this fixture works whether
    or not `build` is in the project venv.
    """
    out = tmp_path_factory.mktemp("dist") / "out"
    subprocess.check_call(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("embalmer-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


def test_wheel_builds_cleanly(built_wheel: Path) -> None:
    """The wheel file exists and has the expected name pattern."""
    assert re.match(r"embalmer-0\.1\.0-.*\.whl", built_wheel.name), built_wheel.name


def test_wheel_version_matches_pyproject() -> None:
    """pyproject.toml [project] version == '0.1.0' (regression pin)."""
    data = tomllib.loads(PYPROJECT.read_text())
    assert data["project"]["version"] == "0.1.0"


def test_wheel_installs_into_fresh_venv(built_wheel: Path, tmp_path: Path) -> None:
    """pip install the wheel into a fresh venv; exit 0."""
    venv = tmp_path / "fresh"
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    subprocess.check_call([str(pip), "install", "--quiet", str(built_wheel)])
    # entry point on PATH
    assert (venv / "bin" / "embalmer").exists()


def test_wheel_version_importable_in_fresh_venv(
    built_wheel: Path, tmp_path: Path
) -> None:
    """`import embalmer` from the fresh venv reports __version__ == '0.1.0'."""
    venv = tmp_path / "fresh_v"
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    py = venv / "bin" / "python"
    subprocess.check_call([str(pip), "install", "--quiet", str(built_wheel)])
    out = subprocess.check_output(
        [str(py), "-c", "import embalmer; print(embalmer.__version__)"],
        text=True,
    ).strip()
    assert out == "0.1.0", out


def test_installed_wheel_public_api(built_wheel: Path, tmp_path: Path) -> None:
    """`embalmer --version` from the fresh venv prints 'embalmer 0.1.0'."""
    venv = tmp_path / "fresh_a"
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    cli = venv / "bin" / "embalmer"
    subprocess.check_call([str(pip), "install", "--quiet", str(built_wheel)])
    out = subprocess.check_output([str(cli), "--version"], text=True).strip()
    assert out == "embalmer 0.1.0", out


def test_python_dash_m_embalmer_works(tmp_path: Path) -> None:
    """`python -m embalmer --version` works (regression pin for __main__.py)."""
    venv = tmp_path / "fresh_m"
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    py = venv / "bin" / "python"
    subprocess.check_call([str(pip), "install", "--quiet", REPO_ROOT])  # editable
    out = subprocess.check_output(
        [str(py), "-m", "embalmer", "--version"], text=True
    ).strip()
    assert out == "embalmer 0.1.0", out
