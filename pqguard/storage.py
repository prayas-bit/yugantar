"""Atomic state persistence and crash-safe storage helpers.

Security properties:
- Rejects symlinks on state directories and target files to prevent symlink-following attacks.
- Enforces 0700 directory permissions and 0600 file permissions on POSIX platforms.
- Note: Windows does not use POSIX mode bits; ACLs depend on the user's profile/temp folder.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


def _enforce_posix_dir_perms(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o700)


def _enforce_posix_file_perms(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o600)


def _validate_safe_dir(path: Path) -> None:
    """Reject symlinks and verify ownership on existing directories."""
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError(f"Refusing symlink in state directory path: {ancestor}")
    if path.exists():
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"Unsafe non-directory path: {path}")
        if os.name == "posix" and hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise PermissionError(f"State directory not owned by current user: {path}")


def create_secure_temp_dir(prefix: str = "pqguard-") -> Path:
    """Create an unpredictable temporary directory with 0700 permissions on POSIX."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    _enforce_posix_dir_perms(path)
    return path


def get_state_dir(app_name: str = "pqguard-track4") -> Path:
    """Resolve writable state directory, honoring TRACK4_STATE_DIR with symlink & permission checks."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        path = Path(env_dir)
    else:
        uid_tag = str(os.getuid()) if hasattr(os, "getuid") else os.environ.get("USERNAME", "user")
        path = Path(tempfile.gettempdir()) / f"{app_name}-{uid_tag}"
    _validate_safe_dir(path)
    path.mkdir(parents=True, exist_ok=True)
    _enforce_posix_dir_perms(path)
    return path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes atomically via a temporary file in the same directory + fsync + os.replace."""
    if path.is_symlink():
        raise ValueError(f"Refusing to write through symlink: {path}")
    _validate_safe_dir(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _enforce_posix_dir_perms(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _enforce_posix_file_perms(tmp_path)
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
