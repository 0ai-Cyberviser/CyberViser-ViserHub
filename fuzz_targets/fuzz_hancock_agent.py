#!/usr/bin/env python3
"""Atheris fuzz harness for CyberViser Hancock fuzzing specialist.

Exercises the pure-function layer of fuzzing_specialist so that any PR
touching fuzzing_agent/** is picked up as an affected target by ClusterFuzzLite.
"""
import atheris
import sys

with atheris.instrument_imports():
    from fuzzing_agent.specialists.fuzzing_specialist import (
        build_harness_prompt,
        build_triage_prompt,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeUnicodeNoSurrogates(128)
    language = fdp.ConsumeUnicodeNoSurrogates(16)
    crash_log = fdp.ConsumeUnicodeNoSurrogates(256)
    try:
        build_harness_prompt(target, language)
        build_triage_prompt(crash_log, target)
    except Exception:
        pass  # expected errors are acceptable; crashes are not


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
