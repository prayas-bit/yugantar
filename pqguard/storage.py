"""Atomic state persistence and crash-safe storage helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def get_state_dir(app_name: str = "pqguard-track4") -> Path:
    """Resolve writable state directory, honoring TRACK4_STATE_DIR."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        path = Path(env_dir)
    else:
        path = Path(tempfile.gettempdir()) / app_name
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes atomically via a temporary file in the same directory + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: Any) -> None:
    """Serialize JSON deterministically and write atomically."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    atomic_write_bytes(path, encoded)


def read_json_or_default(path: Path, default: Any) -> Any:
    """Read JSON from path if it exists, otherwise return default."""
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
