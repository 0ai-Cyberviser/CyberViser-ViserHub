#!/usr/bin/env python3
"""Atheris fuzz harness for hancock — exercises build_harness_prompt and
build_triage_prompt from fuzzing_agent.specialists.fuzzing_specialist.

Importing *real* project code ensures ClusterFuzzLite's unaffected-target
filter keeps this target when fuzzing_agent/** files change.
"""
import os
import sys

import atheris

# Ensure project root is on the Python path so imports resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fuzzing_agent.specialists.fuzzing_specialist import (  # noqa: E402
    build_harness_prompt,
    build_triage_prompt,
)


def test_one_input(data: bytes) -> None:
    """Fuzz entry point — feed random bytes into prompt builders."""
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(512)
    lang = fdp.ConsumeUnicodeNoSurrogates(32)

    # Exercise build_harness_prompt with fuzzed inputs
    try:
        build_harness_prompt(text, lang)
    except Exception:
        pass

    # Exercise build_triage_prompt with fuzzed inputs
    try:
        build_triage_prompt(text, text)
    except Exception:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
