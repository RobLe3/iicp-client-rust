"""Bounded sanitized build-script context emitted before disposable Cargo cleanup."""
from __future__ import annotations
import json
import io
import os
from pathlib import Path
import re
import sys
import tomllib

MAX_FILES = 32
MAX_FILE_BYTES = 65536


def step_event(identity, command, state, exit_code=None):
    """Optional content-free markers; never serialize argv or environment."""
    from datetime import datetime, UTC
    value = {'schema': 'iicp.pre1-build-step-event.v1', 'step_id': identity,
             'command': command, 'state': state, 'exit_code': exit_code,
             'observed_at': datetime.now(UTC).isoformat()}
    try:
        print('IICP_BUILD_STEP_EVENT ' + json.dumps(value), file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass  # Optional telemetry must not change the native build result.


def safe_line(line: str, environment: dict[str, str]) -> str:
    line = line[:2048]  # Bound regex work as well as retained output.
    if re.search(r'password|token|secret|credential|authorization|cookie|payload|prompt|request.body', line, re.I):
        return '<sensitive diagnostic omitted>'
    for value in sorted({v for v in environment.values() if len(v) >= 4}, key=len, reverse=True):
        line = line.replace(value, '<environment-value>')
    line = re.sub(r'[A-Za-z]+://[^\s]+|[A-Za-z]:\\.*|/(?:Users|home)/.*', '<path-or-url>', line)
    line = re.sub(r'[\w.+-]+@[\w.-]+\.[\w-]+', '<address>', line)
    line = re.sub(r"(['\"`]).*?\1", '<quoted-value>', line)
    return ''.join(c for c in line if c.isprintable())[:512]


def safe_path(path: Path, root: Path) -> bool:
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            return False
        if item == root:
            return True
    return False


def emit(run_root: Path, source: Path) -> None:
    """Best-effort detail only: failure here never replaces the original build error."""
    try:
        lock = tomllib.loads((source / 'Cargo.lock').read_text())
        names = {p['name'] for p in lock.get('package', [])}
        count = 0
        for stream in ('output', 'stderr'):
            for path in run_root.glob(f'target-*/debug/build/*/{stream}'):
                name = path.parent.name.rsplit('-', 1)[0]
                if name not in names or not safe_path(path, run_root) or not path.is_file():
                    continue
                if count >= MAX_FILES:
                    print('error: IICP_CARGO_CONTEXT file limit reached', file=sys.stderr)
                    return
                count += 1
                with path.open('rb') as handle:
                    size = os.fstat(handle.fileno()).st_size
                    handle.seek(max(0, size - MAX_FILE_BYTES))
                    raw = handle.read(MAX_FILE_BYTES)
                lines = []
                context = 0
                for line in raw.decode(errors='replace').splitlines():
                    if re.search(r'error|warning|failed|not found|cannot|denied|Caused|panic|could not|fatal', line, re.I):
                        context = 8
                    elif context:
                        context -= 1
                    else:
                        continue
                    lines.append(safe_line(line, dict(os.environ)))
                if lines:
                    print('error: IICP_CARGO_CONTEXT ' + json.dumps({
                        'package': name, 'stream': stream, 'sampled': True,
                        'truncated': size > MAX_FILE_BYTES or len(lines) > 32,
                        'lines': lines[:16] + lines[-16:] if len(lines) > 32 else lines,
                    }), file=sys.stderr, flush=True)
    except (OSError, ValueError, KeyError, TypeError):
        print('error: IICP_CARGO_CONTEXT capture unavailable', file=sys.stderr, flush=True)


def command_identity(argv: list[str]) -> list[str]:
    operation = argv[1] if len(argv) > 1 and argv[1] in {'test', 'package', 'vendor', 'install'} else 'other'
    if operation == 'install':
        operation = 'install-offline' if '--offline' in argv else 'install-online'
    return ['cargo' if argv and Path(argv[0]).stem == 'cargo' else 'other', operation]


def run(argv: list[str], cwd: Path, environment: dict[str, str]) -> None:
    """Drain both pipes without unbounded memory; retain bounded command context."""
    import subprocess
    import threading
    import time
    limit = 8 * 1024 * 1024
    buffers = [bytearray(), bytearray()]
    counts = [0, 0]
    failures = [None, None]

    def drain(pipe, index):
        try:
            read = pipe.read1 if isinstance(pipe, io.BufferedReader) else pipe.read
            while chunk := read(65536):
                counts[index] += len(chunk)
                buffers[index].extend(chunk)
                if len(buffers[index]) > limit:
                    del buffers[index][:-limit]
        except BaseException as error:
            failures[index] = error
        finally:
            try:
                pipe.close()
            except BaseException as error:
                failures[index] = error

    import uuid
    command = command_identity(argv)
    identity = uuid.uuid4().hex
    started = time.monotonic()
    step_event(identity, command, 'started')
    process = None
    capture_error = None
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        workers = [threading.Thread(target=drain, args=(pipe, index), daemon=True)
                   for index, pipe in enumerate((process.stdout, process.stderr))]
        code = wait_for_capture(process, workers, failures)
    except BaseException as error:
        capture_error = error
        code = process.returncode if process is not None and type(process.returncode) is int else None
    step_event(identity, command, 'failed' if capture_error is not None or code else 'success', code)
    for index, stream in enumerate(('stdout', 'stderr')):
        prefix = 'error: ' if code or capture_error is not None else ''
        print(f'{prefix}IICP_CARGO_COMMAND_CONTEXT stream={stream} exit_code={code} truncated={counts[index] > limit}', file=sys.stderr)
        for line in buffers[index].decode(errors='replace').splitlines():
            # Preserve safe Cargo package identities before redacting arbitrary quotes.
            line = re.sub(r'(failed to run custom build command for )`([A-Za-z0-9_-]{1,64} v[0-9][A-Za-z0-9.+-]{0,40})`', r'\1\2', line)
            print(safe_line(line, environment), file=sys.stderr)
    print('IICP_BUILD_STEP ' + json.dumps({'command': command, 'exit_code': code,
          'duration_ms': round((time.monotonic()-started)*1000), 'output_bytes': counts,
          'sampled': True, 'capture_complete': capture_error is None, 'truncated': any(size > limit for size in counts)}), file=sys.stderr, flush=True)
    if capture_error is not None:
        raise capture_error
    if code:
        raise subprocess.CalledProcessError(code, argv)


def wait_for_capture(process, workers, failures):
    """Bound failure propagation and reap the directly owned command."""
    import time
    try:
        for worker in workers:
            worker.start()
        while process.poll() is None:
            if any(error is not None for error in failures):
                raise RuntimeError('Cargo diagnostic capture failed')
            time.sleep(0.05)
        code = process.returncode
        for worker in workers:
            worker.join(timeout=5)
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError('Cargo diagnostic pipe remained open after exit')
        if any(error is not None for error in failures):
            raise RuntimeError('Cargo diagnostic capture failed')
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        print('error: IICP_CARGO_CONTEXT capture interrupted or unavailable', file=sys.stderr, flush=True)
        raise
    return code
