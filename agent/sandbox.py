"""Execution sandbox. Untrusted repo code (tests, build hooks) only ever runs here.

DockerSandbox  : network none, read-only root, non-root user, caps dropped, resource limits.
LocalSandbox   : DEV FALLBACK ONLY. Scrubbed env (no credentials), rlimits, new session,
                 and network namespace isolation via `unshare -rn` when available.
                 It is NOT a strong isolation boundary and requires an explicit opt-in.
"""
from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .scanners import redact_text

MAX_OUTPUT = 20_000


class SandboxError(Exception):
    pass


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    isolation: dict = field(default_factory=dict)


def jvm_home_env(home: str) -> dict[str, str]:
    """Java takes user.home from the passwd database, NOT $HOME. Pin it (and Maven/Gradle homes) to the
    per-run directory so the run uses its private dependency-cache copy and never the host's ~/.m2."""
    return {"JAVA_TOOL_OPTIONS": f"-Duser.home={home}", "MAVEN_CONFIG": f"{home}/.m2",
            "GRADLE_USER_HOME": f"{home}/.gradle"}


def _clip(text: str) -> str:
    text = redact_text(text or "")
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n...[truncated]"


class BaseSandbox:
    name = "base"

    def __init__(self, allowed_executables: list[str]):
        self.allowed = set(allowed_executables)

    def _check(self, cmd: list[str]) -> None:
        if not cmd or Path(cmd[0]).name not in self.allowed:
            raise SandboxError(f"executable not allowlisted: {cmd[:1]}")

    def run(self, cmd: list[str], cwd: Path, timeout: int, home: Path | None = None,
            network: bool = False) -> RunResult:  # pragma: no cover
        raise NotImplementedError


@lru_cache(maxsize=1)
def _unshare_works() -> bool:
    if not shutil.which("unshare"):
        return False
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class LocalSandbox(BaseSandbox):
    name = "local"

    def run(self, cmd: list[str], cwd: Path, timeout: int, home: Path | None = None,
            network: bool = False) -> RunResult:
        self._check(cmd)
        cmd = list(cmd)
        if Path(cmd[0]).name in ("python", "python3"):
            cmd[0] = sys.executable
        exe = cmd[0]
        found = (Path(cwd) / exe).is_file() if exe.startswith("./") else bool(shutil.which(exe))
        if not found:
            raise SandboxError(f"'{exe}' was not found in the sandbox environment (install it, or use the Docker "
                               "sandbox image that contains your toolchain)")
        net_isolated = _unshare_works() and not network
        if net_isolated:
            cmd = ["unshare", "-rn", *cmd]
        own_home = home is None
        home = str(home) if home else tempfile.mkdtemp(prefix="agent-home-")
        env = {  # deliberately minimal: no tokens, no cloud creds, nothing inherited
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": home,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "CI": "1",
            **jvm_home_env(home),
        }

        def limits() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
            resource.setrlimit(resource.RLIMIT_FSIZE, (200 * 2**20, 200 * 2**20))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        start = time.time()
        timed_out = False
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", start_new_session=True, preexec_fn=limits,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate()
        finally:
            if own_home:
                shutil.rmtree(home, ignore_errors=True)
        return RunResult(
            proc.returncode if proc.returncode is not None else -9, _clip(out), _clip(err),
            time.time() - start, timed_out,
            {"sandbox": "local", "network_isolated": net_isolated, "credentials_present": False, "strong_isolation": False},
        )


class DockerSandbox(BaseSandbox):
    name = "docker"

    def __init__(self, allowed_executables: list[str], image: str = "maintenance-agent-sandbox:latest",
                 memory: str = "2g", cpus: str = "2"):
        super().__init__(allowed_executables)
        self.image = image
        self.memory = memory
        self.cpus = cpus

    def run(self, cmd: list[str], cwd: Path, timeout: int, home: Path | None = None,
            network: bool = False) -> RunResult:
        self._check(cmd)
        name = f"agent-sbx-{uuid.uuid4().hex[:10]}"
        # scratch copy must be writable by the unprivileged container user
        subprocess.run(["chmod", "-R", "a+rwX", str(cwd)], check=False)
        mounts = ["-v", f"{Path(cwd).resolve()}:/work:rw"]
        home_env = "/tmp"
        if home is not None:  # per-run COPY of the dependency cache (~/.m2, ~/.gradle); never shared between runs
            subprocess.run(["chmod", "-R", "a+rwX", str(home)], check=False)
            mounts += ["-v", f"{Path(home).resolve()}:/home/sandbox:rw"]
            home_env = "/home/sandbox"
        docker_cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network", "bridge" if network else "none", "--read-only", "--tmpfs", "/tmp:rw,size=512m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "512", "--memory", self.memory, "--cpus", self.cpus,
            "--user", "65534:65534",
            "-e", f"HOME={home_env}", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "CI=1",
            *[x for k, v in jvm_home_env(home_env).items() for x in ("-e", f"{k}={v}")],
            *mounts, "-w", "/work",
            self.image, *cmd,
        ]
        start = time.time()
        try:
            cp = subprocess.run(docker_cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
            return RunResult(cp.returncode, _clip(cp.stdout), _clip(cp.stderr), time.time() - start, False,
                             {"sandbox": "docker", "network_isolated": not network, "credentials_present": False, "strong_isolation": True})
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True)
            return RunResult(-9, "", "timeout", time.time() - start, True,
                             {"sandbox": "docker", "network_isolated": True, "credentials_present": False, "strong_isolation": True})


def select_sandbox(kind: str, allow_unsafe_local: bool, allowed_executables: list[str],
                   image: str = "maintenance-agent-sandbox:latest", memory: str = "2g", cpus: str = "2") -> BaseSandbox:
    have_docker = shutil.which("docker") is not None
    if kind in ("docker", "auto") and have_docker:
        return DockerSandbox(allowed_executables, image, memory, cpus)
    if kind == "docker":
        raise SandboxError("docker requested but not available")
    if kind in ("local", "auto"):
        if not allow_unsafe_local:
            raise SandboxError(
                "No Docker found. The local fallback is not a strong isolation boundary; "
                "re-run with --sandbox local --allow-unsafe-local only for repos you trust."
            )
        return LocalSandbox(allowed_executables)
    raise SandboxError(f"unknown sandbox kind: {kind}")


def pick_image(build_tool: str, java_version: str = "17", python_image: str = "maintenance-agent-sandbox:latest") -> str:
    """Choose a sandbox image from the detected build tool (used when docker_image == 'auto')."""
    if build_tool == "maven":
        return f"maven:3.9-eclipse-temurin-{java_version}"
    if build_tool == "gradle":
        return f"gradle:8-jdk{java_version}"
    return python_image
