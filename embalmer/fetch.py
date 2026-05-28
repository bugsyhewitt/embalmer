"""Live firmware acquisition via graverobber.

embalmer does not implement vendor-specific firmware download logic. It shells
out to graverobber — the necromancer suite's firmware-acquisition tool — to
fetch a firmware image from a vendor URL, then hands the resulting local path to
the normal extract -> creds/certs/binaries/sbom pipeline.

[Worker decision (R10): graverobber CLI over a Python import]
We invoke ``graverobber fetch --url <url> --output <path>`` via subprocess
rather than importing graverobber as a library. The CLI is the stable contract
across suite versions and matches the convention already used for every other
heavy external tool in embalmer (unblob/binwalk in extract.py, blight/autopsy
in binaries.py). The subprocess boundary is isolated into the single
``_run_graverobber`` seam so the unit tests mock it and the suite runs without
graverobber installed; the real binary is exercised only under
``@pytest.mark.integration`` against a stub executable.

The contract embalmer relies on:

* ``graverobber fetch --url <URL> --output <PATH>`` downloads the firmware blob
  to exactly ``<PATH>`` and exits 0 on success.
* On failure graverobber exits non-zero; its stderr is surfaced to the user.

graverobber owns vendor-format quirks, authentication, and blob extraction.
embalmer only needs a local file path back.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

GRAVEROBBER_BINARY = "graverobber"


class FetchError(RuntimeError):
    """Raised when graverobber is unavailable or the download fails."""


def _run_graverobber(url: str, output: Path, graverobber_binary: str) -> None:
    """Invoke the graverobber CLI to download `url` into `output`.

    Isolated into its own function so unit tests can monkeypatch this single
    seam instead of patching subprocess globally — mirroring extract._run_unblob
    and the binaries SubprocessAnalyzer seams.
    """
    if shutil.which(graverobber_binary) is None:
        raise FetchError(
            f"graverobber binary {graverobber_binary!r} not found on PATH. "
            "Install graverobber from the necromancer suite, or download the "
            "firmware manually and pass it with --firmware."
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        graverobber_binary,
        "fetch",
        "--url",
        url,
        "--output",
        str(output),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise FetchError(
            f"graverobber exited {proc.returncode} fetching {url!r}.\n"
            f"stderr: {proc.stderr.strip()}"
        )


def fetch(
    url: str,
    output: str | Path,
    graverobber_binary: str = GRAVEROBBER_BINARY,
) -> Path:
    """Download a firmware image from `url` to `output` via graverobber.

    Args:
        url: Vendor firmware URL to download (graverobber handles the
            vendor-specific download format and authentication).
        output: Local path to write the firmware blob to.
        graverobber_binary: Path or name of the graverobber CLI
            (default: ``"graverobber"`` on PATH).

    Returns:
        The local :class:`~pathlib.Path` to the downloaded firmware, suitable
        for handing directly to :func:`embalmer.extract.extract`.

    Raises:
        FetchError: if the URL is empty, graverobber is unavailable, the
            download exits non-zero, or graverobber claims success but produced
            no file at `output`.
    """
    if not url or not url.strip():
        raise FetchError("a non-empty --url is required for graverobber fetch")

    output = Path(output)
    _run_graverobber(url, output, graverobber_binary)

    # graverobber exited 0 — verify it actually produced the blob it promised.
    if not output.is_file():
        raise FetchError(
            f"graverobber exited 0 but no firmware file was written to {output}. "
            "The download may have failed silently or written elsewhere."
        )

    return output
