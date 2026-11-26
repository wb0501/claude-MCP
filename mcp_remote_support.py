"""Remote MCPMark helper. Runner-visible CLI remains --mcp local|remote.

The remote endpoint at :3000 must run remote_mcp_host.py, not a raw single
MCP server. All control requests use the same Tailscale-secured HTTP channel.
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from urllib.request import build_opener, ProxyHandler
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REMOTE_MCP_URL = "http://100.126.50.78:3000/mcp"
REMOTE_AUTH_TOKEN = os.environ.get("MCP_REMOTE_AUTH_TOKEN", "")


def _control(action: str, payload: dict) -> dict:
    if not REMOTE_AUTH_TOKEN:
        raise RuntimeError("Set MCP_REMOTE_AUTH_TOKEN in computer A before using --mcp remote")
    request = urllib.request.Request(
        REMOTE_MCP_URL.removesuffix('/mcp') + f'/control/{action}',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {REMOTE_AUTH_TOKEN}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    try:
        # Tailnet control traffic must not follow ambient HTTP(S) proxy settings.
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=240) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(1024).decode('utf-8', errors='replace')
        raise RuntimeError(f'Remote MCP {action} failed HTTP {exc.code}: {detail}') from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f'Remote MCP {action} unreachable: {exc}') from exc
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise RuntimeError(f'Remote MCP {action} failed: {result.get("error", result)}')
    return result


def _tar_directory(folder: Path) -> str:
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            # Store contents under a stable relative root, not an absolute path.
            for item in folder.iterdir():
                archive.add(item, arcname=item.name, recursive=True)
        return base64.b64encode(buffer.getvalue()).decode('ascii')


def _safe_unpack(encoded: str, target: Path) -> None:
    raw = base64.b64decode(encoded, validate=True)
    # Extract into an empty directory, rejecting links and special files.
    temp = target.with_name(target.name + '.remote-sync-tmp')
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
            members = tar.getmembers()
            for member in members:
                member_path = Path(member.name)
                if (member_path.is_absolute() or '..' in member_path.parts
                        or not (member.isdir() or member.isfile())):
                    raise ValueError(f'Unsafe remote filesystem archive member: {member.name}')
            for member in members:
                out = temp / member.name
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    out.parent.mkdir(parents=True, exist_ok=True)
                    src = tar.extractfile(member)
                    if src is None:
                        raise ValueError(f'Cannot read archive entry {member.name}')
                    with src, out.open('wb') as dst:
                        shutil.copyfileobj(src, dst)
                    os.chmod(out, member.mode & 0o777)
                    os.utime(out, (member.mtime, member.mtime))
            for member in sorted((m for m in members if m.isdir()), key=lambda m: len(Path(m.name).parts), reverse=True):
                out = temp / member.name
                os.chmod(out, member.mode & 0o777)
                os.utime(out, (member.mtime, member.mtime))
        # Preserve the task's actual local path for the unmodified verifier.
        if target.exists():
            shutil.rmtree(target)
        temp.rename(target)
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def prepare_remote(kind: str, *, task_name: str, filesystem_dir: Path | None = None, **params) -> dict:
    payload = {'kind': kind, 'task_name': task_name, 'params': params}
    if filesystem_dir is not None:
        payload['filesystem_archive'] = _tar_directory(filesystem_dir)
    return _control('prepare', payload)


def finalize_remote(*, filesystem_dir: Path | None = None) -> None:
    result = _control('finalize', {})
    if filesystem_dir is not None:
        encoded = result.get('filesystem_archive')
        if not isinstance(encoded, str):
            raise RuntimeError('Remote filesystem result archive is missing; local verification would be invalid')
        _safe_unpack(encoded, filesystem_dir)


def local_tailscale_ip() -> str:
    try:
        return subprocess.check_output(['tailscale', 'ip', '-4'], text=True, timeout=10).strip().splitlines()[0]
    except (FileNotFoundError, subprocess.SubprocessError, IndexError) as exc:
        raise RuntimeError('Remote mode needs Tailscale running in the local WSL') from exc


def postgres_uri_for_remote(uri: str) -> str:
    """Legacy helper for PostgreSQL databases hosted on computer A.

    Not needed for the current co-located PostgreSQL + MCP deployment on B.
    """
    parts = urlsplit(uri)
    if not parts.hostname:
        raise ValueError('Invalid PostgreSQL URI')
    if parts.hostname not in ('localhost', '127.0.0.1', '::1'):
        return uri
    host = local_tailscale_ip()
    # Preserve URL-encoded credentials byte-for-byte; urlsplit does not decode them.
    auth = parts.netloc.rsplit('@', 1)[0] + '@' if '@' in parts.netloc else ''
    netloc = auth + host + (f':{parts.port}' if parts.port else '')
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
