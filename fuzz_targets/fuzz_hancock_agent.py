#!/usr/bin/env python3
"""Atheris fuzz harness for CyberViser Hancock fuzzing specialist.

Exercises the pure-function layer of fuzzing_specialist so that any PR
touching fuzzing_agent/** or fuzz_targets/** is picked up as an affected
target by ClusterFuzzLite.

Coverage:
- ``build_harness_prompt`` — LLM prompt generation for OSS-Fuzz project setup.
- ``build_triage_prompt`` — LLM prompt generation for sanitizer crash triage.
- ``write_project_files`` — filesystem writer for generated project files.
- ``build_docker_run_cmd`` — Docker-run command builder for local fuzz runs.
"""
import atheris
import sys
import tempfile
from pathlib import Path

with atheris.instrument_imports():
    from fuzzing_agent.specialists.fuzzing_specialist import (
        build_harness_prompt,
        build_triage_prompt,
        build_docker_run_cmd,
        write_project_files,
    )

__all__ = ["TestOneInput"]


def TestOneInput(data: bytes) -> None:
    """Fuzz entry point invoked by Atheris/libFuzzer on every test case.

    Drives all four pure functions in fuzzing_specialist with arbitrary
    byte sequences so that any input-handling bug is exposed as a crash
    rather than a silent failure.
    """
    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeUnicodeNoSurrogates(128)
    language = fdp.ConsumeUnicodeNoSurrogates(16)
    crash_log = fdp.ConsumeUnicodeNoSurrogates(256)
    fuzzer = fdp.ConsumeUnicodeNoSurrogates(32)
    duration = fdp.ConsumeInt(4)
    filename = fdp.ConsumeUnicodeNoSurrogates(64)
    content = fdp.ConsumeUnicodeNoSurrogates(256)

    build_harness_prompt(target, language)
    build_triage_prompt(crash_log, target)

    try:
        build_docker_run_cmd(target, fuzzer, duration)
    except ValueError:
        pass  # invalid fuzzer name raises ValueError — that is expected

    safe_filename = Path(filename).name
    if filename and safe_filename and safe_filename == filename:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                write_project_files(Path(tmpdir), {safe_filename: content})
        except (ValueError, OSError):
            pass  # path traversal or other OS errors are acceptable


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
