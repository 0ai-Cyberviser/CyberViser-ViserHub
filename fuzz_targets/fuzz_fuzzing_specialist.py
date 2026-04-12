#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
"""
Atheris fuzz harness for FuzzingSpecialist — exercises prompt-building
and docker command construction logic.
"""
import sys
import atheris

from hancock_constants import SUPPORTED_FUZZERS

with atheris.instrument_imports():
    from fuzzing_agent.specialists.fuzzing_specialist import (
        build_harness_prompt,
        build_triage_prompt,
        build_docker_run_cmd,
    )


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    target = fdp.ConsumeUnicodeNoSurrogates(128)
    language = fdp.ConsumeUnicodeNoSurrogates(32)
    crash_log = fdp.ConsumeUnicodeNoSurrogates(512)
    binary = fdp.ConsumeUnicodeNoSurrogates(64)

    try:
        build_harness_prompt(target, language)
        build_triage_prompt(crash_log, binary)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        pass

    # Fuzz docker command builder with valid fuzzers
    if SUPPORTED_FUZZERS:
        fuzzer = fdp.PickValueInList(list(SUPPORTED_FUZZERS))
        try:
            build_docker_run_cmd("/tmp/project", fuzzer, 60)
        except ValueError:
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
