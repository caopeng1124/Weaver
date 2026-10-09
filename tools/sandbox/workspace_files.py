"""Bounded, no-follow workspace IO. Container paths never become host paths."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath

from common.config import settings

EXCLUDED_DIRS = {"node_modules", "venv", "env", "__pycache__", "logs", "screenshots"}
EXCLUDED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".sqlite3", ".db"}
EXCLUDED_NAMES = {"credentials", "credentials.json", "id_rsa", "id_ed25519", "memory_store.json"}


def digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def validate_path(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path or len(path) > 1024:
        raise ValueError("Invalid workspace path")
    parts = path.split("/")
    if PurePosixPath(path).is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Workspace paths must be relative and cannot traverse directories")
    if any(
        part.startswith(".") or part in EXCLUDED_DIRS or part.lower() in EXCLUDED_NAMES
        for part in parts
    ):
        raise PermissionError("Hidden, credential and runtime paths are excluded")
    if PurePosixPath(path).suffix.lower() in EXCLUDED_SUFFIXES:
        raise PermissionError("Credential and database files are excluded")
    return tuple(parts)


@contextmanager
def parent_fd(root: Path, path: str, *, create: bool = False):
    parts = validate_path(path)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=directory)
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        yield directory, parts[-1]
    finally:
        os.close(directory)


def read_host(root: Path, path: str) -> bytes | None:
    try:
        with parent_fd(root, path) as (directory, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise PermissionError("Only regular files with one hard link may be imported")
                data = handle.read(settings.sandbox_max_file_bytes + 1)
                if len(data) > settings.sandbox_max_file_bytes:
                    raise ValueError("File exceeds configured size limit")
                return data
    except FileNotFoundError:
        return None


def import_workspace(root: Path, *, exclude: Path | None = None) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name
            for name in dirs
            if not name.startswith(".")
            and name not in EXCLUDED_DIRS
            and not Path(directory, name).is_symlink()
            and (exclude is None or not Path(directory, name).resolve().is_relative_to(exclude))
        )
        for name in sorted(names):
            path = Path(directory, name).relative_to(root).as_posix()
            try:
                validate_path(path)
            except (ValueError, PermissionError):
                continue
            if Path(directory, name).is_symlink():
                continue
            data = read_host(root, path)
            if data is None:
                continue
            from common.security.content import contains_secret

            if contains_secret(data.decode("utf-8", errors="replace")):
                continue
            total += len(data)
            if (
                total > settings.sandbox_max_import_bytes
                or len(files) >= settings.sandbox_max_files
            ):
                raise ValueError(
                    "Workspace exceeds import limits; select a smaller project directory"
                )
            files[path] = data
    return files


def write_host(root: Path, path: str, data: bytes | None, expected: str | None) -> None:
    if digest(read_host(root, path)) != expected:
        raise ValueError(f"Local file changed since import: {path}")
    with parent_fd(root, path, create=data is not None) as (directory, name):
        if data is None:
            os.unlink(name, dir_fd=directory)
            return
        temp = f"weaver-apply-{secrets.token_hex(12)}.tmp"
        fd = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if digest(read_host(root, path)) != expected:
                raise ValueError(f"Local file changed during apply: {path}")
            if expected is None:
                # Creation must never replace a concurrently-created destination.
                os.link(
                    temp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False
                )
            else:
                mode = (
                    stat.S_IMODE(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode)
                    & 0o777
                )
                os.chmod(temp, mode, dir_fd=directory)
                os.replace(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temp, dir_fd=directory)
