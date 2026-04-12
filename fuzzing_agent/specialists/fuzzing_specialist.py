# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
Fuzzing Specialist — core agent for AI-powered fuzz testing.

Generates OSS-Fuzz-ready project structures (harnesses, Dockerfiles, build scripts),
orchestrates local fuzz runs via Docker, and triages crashes with LLM analysis.

Supported fuzzers: libFuzzer, AFL++, Atheris (Python), Honggfuzz.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from hancock_constants import (
    SUPPORTED_FUZZERS,
    SUPPORTED_SANITIZERS,
    OSS_FUZZ_BASE_IMAGES,
)


def build_harness_prompt(target_repo: str, language: str = "c++") -> str:
    """Return the LLM prompt for generating an OSS-Fuzz project structure.

    Parameters
    ----------
    target_repo:
        URL or local path of the target repository.
    language:
        Programming language of the target (``c++``, ``python``, etc.).

    Returns
    -------
    str
        A prompt string suitable for Hancock's ``llm_call`` / ``chat()``.
    """
    base_image = OSS_FUZZ_BASE_IMAGES.get(language, OSS_FUZZ_BASE_IMAGES["c++"])
    return (
        f"You are an OSS-Fuzz expert. Given target repo {target_repo} in {language}, "
        f"generate a complete OSS-Fuzz project folder with:\n"
        f"1. project.yaml\n"
        f"2. Dockerfile (use {base_image})\n"
        f"3. build.sh\n"
        f"4. A fuzz harness file appropriate for {language}\n"
        f"5. corpus/ seed files\n\n"
        f"Return as JSON with keys 'files' (mapping filename to content string)."
    )


def build_triage_prompt(crash_log: str, target_binary: str) -> str:
    """Return the LLM prompt for triaging a sanitizer crash.

    Parameters
    ----------
    crash_log:
        Raw text from the AddressSanitizer / UBSan / crash output.
    target_binary:
        Name or path of the target that crashed.

    Returns
    -------
    str
        A triage prompt.
    """
    return (
        f"Analyze this sanitizer crash from {target_binary}:\n"
        f"```\n{crash_log}\n```\n\n"
        f"Provide:\n"
        f"1. Root cause analysis\n"
        f"2. CWE classification\n"
        f"3. Security impact assessment (CVSS-style)\n"
        f"4. A minimal patch diff that fixes the issue"
    )


def write_project_files(project_dir: Path, files: dict[str, str]) -> Path:
    """Write generated OSS-Fuzz project files to *project_dir*.

    Parameters
    ----------
    project_dir:
        Destination directory (created if it does not exist).
    files:
        Mapping of relative filename → content string.

    Returns
    -------
    Path
        The *project_dir* that was written to.
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        filepath = project_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)
    return project_dir


def build_docker_run_cmd(
    project_dir: str,
    fuzzer: str = "aflpp",
    duration: int = 3600,
    image: str = "hancock-fuzz-env:latest",
) -> list[str]:
    """Build a ``docker run`` command list for a local fuzz run.

    Parameters
    ----------
    project_dir:
        Absolute path to the OSS-Fuzz project to mount.
    fuzzer:
        One of :data:`SUPPORTED_FUZZERS`.
    duration:
        Maximum fuzz duration in seconds.
    image:
        Docker image name/tag.

    Returns
    -------
    list[str]
        Argument list suitable for :func:`subprocess.run`.

    Raises
    ------
    ValueError
        If *fuzzer* is not in :data:`SUPPORTED_FUZZERS`.
    """
    if fuzzer not in SUPPORTED_FUZZERS:
        raise ValueError(
            f"Unsupported fuzzer '{fuzzer}'; choose from {SUPPORTED_FUZZERS}"
        )
    safe_dir = shlex.quote(str(project_dir))
    return [
        "docker", "run", "--rm",
        "-v", f"{safe_dir}:/src",
        "-e", f"HANCOCK_FUZZER={fuzzer}",
        "-e", f"HANCOCK_FUZZ_DURATION={int(duration)}",
        image,
        "python3", "-m", "fuzz_runner",
    ]


def run_local_fuzz(
    project_dir: str,
    fuzzer: str = "aflpp",
    duration: int = 3600,
    image: str = "hancock-fuzz-env:latest",
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Spin up the fuzz-env Docker container for a local fuzz run.

    Parameters
    ----------
    project_dir:
        Absolute path to the OSS-Fuzz project to mount.
    fuzzer:
        One of :data:`SUPPORTED_FUZZERS`.
    duration:
        Maximum fuzz duration in seconds.
    image:
        Docker image name/tag.
    timeout:
        Optional subprocess timeout (seconds).

    Returns
    -------
    subprocess.CompletedProcess
    """
    cmd = build_docker_run_cmd(project_dir, fuzzer, duration, image)
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )
