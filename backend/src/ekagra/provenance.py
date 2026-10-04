"""What a results file needs in order to be regenerable later.

A number you cannot reproduce is not a measurement, and this project has twice
been caught out by a missing knob: experiment 14 in the companion project did
not record its epoch count and could not regenerate its own published row, and
in October 2026 a lead-time figure could not be attributed to either a library
upgrade or a thread count because neither was written down.

`environment()` returns the things that silently decide a result:

  versions      only of libraries the run actually imported, so the record
                describes this run rather than the machine's package list
  threads       torch's thread count and the OpenMP/MKL variables, because
                fused kernels and XGBoost reduce floats in thread order and a
                different count gives a different answer
  git           the commit the run was made from, and whether the tree was
                dirty, so a row can be traced to code

Every experiment merges this into its payload under "environment".
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Libraries whose version can change a result. Only those already imported by
# the running experiment are reported - importing them here to read a version
# would both slow the run and misrepresent what it used.
WATCHED = ("numpy", "scipy", "pandas", "sklearn", "xgboost", "torch", "matplotlib")


def _versions() -> dict:
    out = {}
    for name in WATCHED:
        mod = sys.modules.get(name)
        version = getattr(mod, "__version__", None) if mod else None
        if version:
            out[name] = str(version)
    return out


def _threads() -> dict:
    out = {"cpu_count": os.cpu_count()}
    torch = sys.modules.get("torch")
    if torch is not None:
        try:
            out["torch_num_threads"] = torch.get_num_threads()
            out["torch_interop_threads"] = torch.get_num_interop_threads()
        except Exception:                      # pragma: no cover - torch internals
            pass
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
        out[var] = os.environ.get(var)         # None means "left to the library"
    return out


def _git(start: Path | None = None) -> dict:
    """The commit this ran from. Tolerates not being in a git tree."""
    cwd = str(start or Path(__file__).resolve().parent)
    def run(*args):
        try:
            r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                               text=True, timeout=10)
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None
    commit = run("rev-parse", "--short", "HEAD")
    if commit is None:
        return {}
    status = run("status", "--porcelain")
    return {"commit": commit, "dirty": bool(status)}


def environment() -> dict:
    return {
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "versions": _versions(),
        "threads": _threads(),
        "git": _git(),
    }


def stamped(payload: dict) -> dict:
    """`payload` plus its environment, for writing to a results file."""
    return {**payload, "environment": environment()}
