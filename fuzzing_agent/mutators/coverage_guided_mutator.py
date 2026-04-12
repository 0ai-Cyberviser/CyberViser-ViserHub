# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
Coverage-Guided Mutator — hybrid LLM + traditional fuzzing.

Parses coverage data (lcov / JSON) and uses Hancock's LLM backend to generate
semantically-aware mutations targeting low-coverage code paths.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def analyze_coverage(coverage_file: str | Path) -> dict[str, Any]:
    """Parse a coverage JSON file and identify low-coverage functions.

    Parameters
    ----------
    coverage_file:
        Path to a JSON coverage report (e.g., from ``coverage json``
        or ClusterFuzzLite ``coverage.json``).

    Returns
    -------
    dict
        ``{"low_coverage_paths": [...], "total_edges": int}``
    """
    data = json.loads(Path(coverage_file).read_text())
    functions = data.get("functions", [])
    low_cov = [
        func for func in functions
        if func.get("coverage", 100) < 30
    ]
    return {
        "low_coverage_paths": low_cov,
        "total_edges": data.get("total_edges", 0),
    }


def build_mutation_prompt(
    seed_hex: str,
    coverage_data: dict[str, Any],
    target_code: str,
) -> str:
    """Build an LLM prompt for smart, coverage-guided seed mutation.

    Parameters
    ----------
    seed_hex:
        Hex-encoded current seed input (truncated for prompt size).
    coverage_data:
        Output of :func:`analyze_coverage`.
    target_code:
        Source code snippet of the target under test.

    Returns
    -------
    str
        A prompt suitable for ``llm_call`` / ``chat()``.
    """
    low_paths_json = json.dumps(
        coverage_data["low_coverage_paths"][:10], indent=2
    )
    return (
        "You are a coverage-guided mutation expert.\n"
        f"Target code snippet:\n```\n{target_code[:2000]}\n```\n\n"
        f"Low-coverage paths:\n{low_paths_json}\n\n"
        f"Current seed (hex): {seed_hex[:200]}\n\n"
        "Generate 5 new mutated inputs (as hex strings) that are likely "
        "to hit the low-coverage paths. Focus on semantic changes that "
        "trigger new branches. Return as a JSON list of hex strings."
    )


def mutate_corpus(
    corpus_dir: str | Path,
    coverage_file: str | Path,
    target_code: str,
    llm_call: Any | None = None,
) -> int:
    """Apply hybrid LLM mutation to every seed in *corpus_dir*.

    If *llm_call* is ``None`` the function still analyses coverage but
    performs no mutations and returns ``0`` new seeds (useful for dry-run
    / testing).

    Parameters
    ----------
    corpus_dir:
        Directory containing seed corpus files.
    coverage_file:
        Path to coverage JSON.
    target_code:
        Source code of the target.
    llm_call:
        Optional callable ``(prompt: str) -> dict`` that queries the LLM.
        When provided, new mutated seeds are written back to *corpus_dir*.

    Returns
    -------
    int
        Number of new seeds written (0 when *llm_call* is ``None``).
    """
    coverage = analyze_coverage(coverage_file)
    corpus_path = Path(corpus_dir)
    new_seeds = 0

    for seed_file in sorted(corpus_path.glob("**/*")):
        if not seed_file.is_file():
            continue
        seed = seed_file.read_bytes()
        prompt = build_mutation_prompt(seed.hex(), coverage, target_code)

        if llm_call is None:
            continue

        response = llm_call(prompt)
        mutations = response if isinstance(response, list) else response.get("mutations", [])
        for i, hex_str in enumerate(mutations[:5]):
            try:
                mutated = bytes.fromhex(hex_str)
            except (ValueError, TypeError):
                continue
            dest = corpus_path / f"mutated_{seed_file.stem}_{i}"
            dest.write_bytes(mutated)
            new_seeds += 1

    return new_seeds
