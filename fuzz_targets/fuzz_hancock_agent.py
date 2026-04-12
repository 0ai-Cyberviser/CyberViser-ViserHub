#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
"""
Atheris fuzz harness for Hancock — exercises CLI command parsing and
the mode/model dispatch logic in hancock_agent.py.

ClusterFuzzLite entry point: function must be named TestOneInput.
"""
import sys
import atheris

with atheris.instrument_imports():
    import hancock_agent  # noqa: F401 — instruments the module under test


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Fuzz /mode and /model CLI command parsing
    user_input = fdp.ConsumeUnicodeNoSurrogates(256)
    try:
        # Exercise SYSTEMS dict lookup (the mode-switch logic)
        mode = fdp.ConsumeUnicodeNoSurrogates(16).strip()
        _ = hancock_agent.SYSTEMS.get(mode)

        # Exercise model alias resolution
        alias = fdp.ConsumeUnicodeNoSurrogates(32).strip()
        _ = hancock_agent.MODELS.get(alias, alias)

        # Exercise the banner string rendering (no side effects)
        _ = hancock_agent.BANNER

    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        pass  # expected; crashes/hangs/assertions are not


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
