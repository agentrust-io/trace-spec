"""Development-only observer: capture child exit status, not a caller's assertion.

No shell; network isolation is NOT provided, and no independently enrolled key.
The dedicated operator must supply an explicit command allowlist and trusted
signing key. The result is *not* independent process attestation.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import time
from observer_receipt import issue


def capture(*, argv, allowed_argv, repository, expected_commit, private_key,
            host_label, timeout=300, isolate_network=False, challenge=None):
    """Run exactly one allowlisted program; sign observed exit and commit binding."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv required")
    if any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
        raise ValueError("invalid argv")
    if challenge is not None and (not isinstance(challenge, str) or len(challenge) < 16):
        raise ValueError("challenge must be a nontrivial string")
    if type(timeout) not in (int, float) or timeout <= 0:
        raise ValueError("invalid timeout")
    if not isinstance(allowed_argv, (list, tuple)) or tuple(argv) != tuple(allowed_argv):
        raise ValueError("full command not allowlisted")
    actual = Path(argv[0]).resolve(strict=True)
    if not actual.is_file():
        raise ValueError("invalid executable")
    executable_sha256 = hashlib.sha256(actual.read_bytes()).hexdigest()
    if not isinstance(host_label, str) or not host_label:
        raise ValueError("host label required")
    root = Path(repository).resolve(strict=True)
    rev = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()
    if rev != expected_commit:
        raise ValueError("source commit mismatch")
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    if status.stdout:
        raise ValueError("dirty working tree")
    # Network isolation is an explicit, fail-closed opt-in. It is not a
    # confidential-computing attestation or a general filesystem sandbox.
    command = list(argv)
    if type(isolate_network) is not bool:
        raise ValueError("isolate_network must be boolean")
    if isolate_network:
        bubblewrap = shutil.which("bwrap")
        if bubblewrap is None:
            raise RuntimeError("bubblewrap unavailable: isolated run refused")
        # No blanket host-root bind: mount only executable runtime trees and
        # the pinned checkout. Missing dependencies cause a failed launch.
        sandbox = [
            bubblewrap, "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--new-session", "--cap-drop", "ALL",
            "--die-with-parent", "--tmpfs", "/", "--proc", "/proc",
            "--dev", "/dev", "--dir", "/tmp",
        ]
        for runtime_path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(runtime_path).exists():
                sandbox.extend(["--ro-bind", runtime_path, runtime_path])
        if root == Path("/") or str(root) in ("/usr", "/bin", "/lib", "/lib64"):
            raise ValueError("checkout cannot be host root or runtime root")
        sandbox.extend(["--ro-bind", str(root), str(root)])
        command = [*sandbox, "--chdir", str(root), "--", *command]
    # Capture observed process status, rather than accepting a supplied result.
    result = subprocess.run(
        command, cwd=str(root), capture_output=True, timeout=timeout,
        shell=False, env={"PATH": os.defpath, "HOME": "/nonexistent",
                          "PYTHONNOUSERSITE": "1"},
    )
    if isolate_network and result.returncode != 0:
        # A nonzero exit could be the launcher refusing to isolate; do not
        # misrepresent that as an observed successful sandboxed workload.
        raise RuntimeError("isolated execution did not complete successfully")
    # Reject observed results if tracked/untracked source changed during execution.
    after = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    if after.stdout:
        raise ValueError("source changed during execution")
    if hashlib.sha256(actual.read_bytes()).hexdigest() != executable_sha256:
        raise ValueError("executable changed during execution")
    observation = {
        "executable_sha256": executable_sha256,
        "network_isolation_requested": isolate_network,
        "commit": rev, "host": host_label,
        "command": list(argv),
        "exit_code": result.returncode,
        "summary": "captured child process result",
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }
    if challenge is not None:
        observation["challenge"] = challenge
        observation["observed_at_unix"] = int(time.time())
    return issue(observation, private_key)
