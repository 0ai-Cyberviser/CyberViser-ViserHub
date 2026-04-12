# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
ClusterFuzzLite Integration — bridge between FuzzingSpecialist and CI/CD.

Generates Atheris / libFuzzer harnesses + ClusterFuzzLite configuration that
can be consumed directly by GitHub Actions workflows.
"""
from __future__ import annotations

from pathlib import Path

from fuzzing_agent.specialists.fuzzing_specialist import (
    build_harness_prompt,
    write_project_files,
)

# Default ClusterFuzzLite configuration
DEFAULT_CONFIG = {
    "language": "python",
    "fuzzing_engine": "atheris",
    "sanitizers": ["address", "undefined"],
    "auto_build": True,
    "coverage": True,
}


def write_clusterfuzzlite_config(
    config_dir: str | Path = ".clusterfuzzlite",
    overrides: dict | None = None,
) -> Path:
    """Write a ``config.yml`` for ClusterFuzzLite.

    Parameters
    ----------
    config_dir:
        Directory for the config file (created if needed).
    overrides:
        Key/value pairs that override :data:`DEFAULT_CONFIG`.

    Returns
    -------
    Path
        Path to the written ``config.yml``.
    """
    import yaml  # optional dep; deferred import

    config = {**DEFAULT_CONFIG, **(overrides or {})}
    config_path = Path(config_dir)
    config_path.mkdir(parents=True, exist_ok=True)
    out = config_path / "config.yml"
    out.write_text(yaml.safe_dump(config, sort_keys=False))
    return out


def generate_harness_code(target_module: str) -> str:
    """Return a minimal Atheris harness for *target_module*.

    This is a **template** — the real harness content should come from the LLM.
    The template is useful as a fallback or starting seed.

    Parameters
    ----------
    target_module:
        Dotted Python module path (e.g., ``hancock_agent``).

    Returns
    -------
    str
        Python source code for an Atheris fuzz harness.
    """
    return (
        "#!/usr/bin/env python3\n"
        '"""Auto-generated Atheris fuzz harness for '
        f'{target_module}."""\n'
        "import atheris\n"
        "import sys\n\n\n"
        "def test_one_input(data: bytes) -> None:\n"
        f'    """Fuzz entry point for {target_module}."""\n'
        "    fdp = atheris.FuzzedDataProvider(data)\n"
        "    text = fdp.ConsumeUnicodeNoSurrogates(256)\n"
        f"    # TODO: call into {target_module} with 'text'\n\n\n"
        'if __name__ == "__main__":\n'
        "    atheris.Setup(sys.argv, test_one_input)\n"
        "    atheris.Fuzz()\n"
    )


def generate_clusterfuzzlite_harnesses(
    target_paths: list[str],
    output_dir: str | Path = "fuzz_targets",
) -> list[Path]:
    """Generate Atheris harness stubs for a list of Python modules.

    Parameters
    ----------
    target_paths:
        List of dotted module paths or file paths.
    output_dir:
        Directory where harness files are written.

    Returns
    -------
    list[Path]
        Paths to the generated harness files.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for path in target_paths:
        stem = Path(path).stem
        harness = generate_harness_code(stem)
        dest = out / f"fuzz_{stem}.py"
        if not dest.exists():
            dest.write_text(harness)
            written.append(dest)
    return written
