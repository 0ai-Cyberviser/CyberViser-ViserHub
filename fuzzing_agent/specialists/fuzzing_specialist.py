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


def build_harness_prompt(target_repo: str, language: str = "c++", context: str = "") -> str:
    """Return the LLM prompt for generating an OSS-Fuzz project structure.

    Parameters
    ----------
    target_repo:
        URL or local path of the target repository.
    language:
        Programming language of the target (``c++``, ``python``, etc.).
    context:
        Additional context about the target (e.g., "focus on JSON parser", "test HTTP endpoints").

    Returns
    -------
    str
        A prompt string suitable for Hancock's ``llm_call`` / ``chat()``.
    """
    base_image = OSS_FUZZ_BASE_IMAGES.get(language, OSS_FUZZ_BASE_IMAGES["c++"])
    context_line = f"\n\nAdditional context: {context}" if context else ""

    return (
        f"You are an OSS-Fuzz expert. Given target repo {target_repo} in {language}, "
        f"generate a complete OSS-Fuzz project folder with:\n"
        f"1. project.yaml (include homepage, primary_contact, auto_ccs, and main_repo)\n"
        f"2. Dockerfile (use {base_image} as base image)\n"
        f"3. build.sh (compile with sanitizers: -fsanitize=address,undefined)\n"
        f"4. A fuzz harness file appropriate for {language} (focus on high-value targets)\n"
        f"5. corpus/ seed files (at least 3 diverse examples){context_line}\n\n"
        f"Return as JSON with keys 'files' (mapping filename to content string).\n"
        f"Ensure the harness covers key input parsing/processing functions."
    )


def build_triage_prompt(crash_log: str, target_binary: str, source_code: str = "") -> str:
    """Return the LLM prompt for triaging a sanitizer crash.

    Parameters
    ----------
    crash_log:
        Raw text from the AddressSanitizer / UBSan / crash output.
    target_binary:
        Name or path of the target that crashed.
    source_code:
        Optional source code snippet around the crash location for better analysis.

    Returns
    -------
    str
        A triage prompt.
    """
    source_section = ""
    if source_code:
        source_section = f"\n\nRelevant source code:\n```\n{source_code}\n```\n"

    return (
        f"Analyze this sanitizer crash from {target_binary}:\n"
        f"```\n{crash_log}\n```{source_section}\n"
        f"Provide:\n"
        f"1. Root cause analysis (what went wrong and why)\n"
        f"2. CWE classification (e.g., CWE-119, CWE-416) with explanation\n"
        f"3. Security impact assessment:\n"
        f"   - Exploitability (Low/Medium/High)\n"
        f"   - CVSS v3.1 base score estimate\n"
        f"   - Attack vector and prerequisites\n"
        f"4. A minimal patch diff that fixes the issue\n"
        f"5. Suggested test case to prevent regression"
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
        image,
        "python3", "-m", "fuzz_runner",
        fuzzer,
        "--time", str(int(duration)),
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
