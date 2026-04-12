"""Shared constants for Hancock modules."""

OPENAI_IMPORT_ERROR_MSG = "OpenAI client not installed. Run: pip install openai"

# ── Fuzzing Specialist constants ──────────────────────────────────────────────

FUZZ_MODES = ("generate-harness", "run", "triage")
"""Supported sub-modes for the /v1/fuzz/* endpoints."""

SUPPORTED_FUZZERS = ("libfuzzer", "aflpp", "atheris", "honggfuzz")
"""Fuzzer engines available in the fuzz-env Docker image."""

SUPPORTED_SANITIZERS = ("address", "undefined", "memory", "coverage")
"""Sanitizers that can be enabled during fuzz builds."""

OSS_FUZZ_BASE_IMAGES = {
    "c":      "gcr.io/oss-fuzz-base/base-builder",
    "c++":    "gcr.io/oss-fuzz-base/base-builder",
    "python": "gcr.io/oss-fuzz-base/base-builder-python",
    "go":     "gcr.io/oss-fuzz-base/base-builder-go",
    "rust":   "gcr.io/oss-fuzz-base/base-builder-rustc",
    "java":   "gcr.io/oss-fuzz-base/base-builder-jvm",
}
"""Language → base Docker image mapping for OSS-Fuzz project generation."""


def require_openai(openai_cls):
    """Raise ImportError when the OpenAI dependency is missing."""
    if openai_cls is None:
        raise ImportError(OPENAI_IMPORT_ERROR_MSG)
