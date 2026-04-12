"""
Fuzzing Agent Module — Unit Tests
Run:  pytest fuzzing_agent/tests/ -v
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# ── fuzzing_specialist ────────────────────────────────────────────────────────

class TestFuzzingSpecialist:
    def test_supported_fuzzers(self):
        from fuzzing_agent.specialists.fuzzing_specialist import SUPPORTED_FUZZERS
        assert "libfuzzer" in SUPPORTED_FUZZERS
        assert "aflpp" in SUPPORTED_FUZZERS
        assert "atheris" in SUPPORTED_FUZZERS
        assert "honggfuzz" in SUPPORTED_FUZZERS

    def test_build_harness_prompt(self):
        from fuzzing_agent.specialists.fuzzing_specialist import build_harness_prompt
        prompt = build_harness_prompt("https://github.com/example/proj", "python")
        assert "OSS-Fuzz" in prompt
        assert "python" in prompt
        assert "https://github.com/example/proj" in prompt

    def test_build_triage_prompt(self):
        from fuzzing_agent.specialists.fuzzing_specialist import build_triage_prompt
        prompt = build_triage_prompt("heap-buffer-overflow at 0x1234", "my_binary")
        assert "my_binary" in prompt
        assert "heap-buffer-overflow" in prompt
        assert "CWE" in prompt

    def test_write_project_files(self):
        from fuzzing_agent.specialists.fuzzing_specialist import write_project_files
        with tempfile.TemporaryDirectory() as td:
            project_dir = Path(td) / "test_project"
            files = {
                "Dockerfile": "FROM ubuntu",
                "build.sh": "#!/bin/bash\nmake",
                "sub/file.cc": "int main() {}",
            }
            result = write_project_files(project_dir, files)
            assert result == project_dir
            assert (project_dir / "Dockerfile").read_text() == "FROM ubuntu"
            assert (project_dir / "build.sh").read_text() == "#!/bin/bash\nmake"
            assert (project_dir / "sub" / "file.cc").read_text() == "int main() {}"

    def test_build_docker_run_cmd(self):
        from fuzzing_agent.specialists.fuzzing_specialist import build_docker_run_cmd
        cmd = build_docker_run_cmd("/tmp/proj", "aflpp", 600)
        assert "docker" in cmd
        assert "aflpp" in cmd
        assert "600" in cmd

    def test_build_docker_run_cmd_invalid_fuzzer(self):
        from fuzzing_agent.specialists.fuzzing_specialist import build_docker_run_cmd
        with pytest.raises(ValueError, match="Unsupported fuzzer"):
            build_docker_run_cmd("/tmp/proj", "invalid_fuzzer")


# ── clusterfuzz_integration ───────────────────────────────────────────────────

class TestClusterFuzzIntegration:
    def test_generate_harness_code(self):
        from fuzzing_agent.specialists.clusterfuzz_integration import generate_harness_code
        code = generate_harness_code("hancock_agent")
        assert "atheris" in code
        assert "hancock_agent" in code
        assert "test_one_input" in code

    def test_generate_clusterfuzzlite_harnesses(self):
        from fuzzing_agent.specialists.clusterfuzz_integration import generate_clusterfuzzlite_harnesses
        with tempfile.TemporaryDirectory() as td:
            written = generate_clusterfuzzlite_harnesses(
                ["hancock_agent", "hancock_constants"],
                output_dir=td,
            )
            assert len(written) == 2
            assert all(p.exists() for p in written)
            assert "fuzz_hancock_agent.py" in written[0].name
            code = written[0].read_text()
            assert "atheris" in code


# ── coverage_guided_mutator ───────────────────────────────────────────────────

class TestCoverageGuidedMutator:
    def test_analyze_coverage(self):
        from fuzzing_agent.mutators.coverage_guided_mutator import analyze_coverage
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "functions": [
                    {"name": "func_a", "coverage": 95},
                    {"name": "func_b", "coverage": 10},
                    {"name": "func_c", "coverage": 5},
                ],
                "total_edges": 1234,
            }, f)
            f.flush()
            result = analyze_coverage(f.name)
        os.unlink(f.name)
        assert result["total_edges"] == 1234
        assert len(result["low_coverage_paths"]) == 2
        assert result["low_coverage_paths"][0]["name"] == "func_b"

    def test_build_mutation_prompt(self):
        from fuzzing_agent.mutators.coverage_guided_mutator import build_mutation_prompt
        prompt = build_mutation_prompt(
            "deadbeef",
            {"low_coverage_paths": [{"name": "parse", "coverage": 5}], "total_edges": 100},
            "def parse(x): return x",
        )
        assert "coverage-guided mutation" in prompt
        assert "deadbeef" in prompt
        assert "parse" in prompt

    def test_mutate_corpus_dry_run(self):
        """Without llm_call, mutate_corpus returns 0 new seeds."""
        from fuzzing_agent.mutators.coverage_guided_mutator import mutate_corpus
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            (corpus / "seed1").write_bytes(b"hello")
            cov_file = Path(td) / "cov.json"
            cov_file.write_text(json.dumps({
                "functions": [{"name": "f", "coverage": 5}],
                "total_edges": 10,
            }))
            result = mutate_corpus(str(corpus), str(cov_file), "def f(): pass")
            assert result == 0

    def test_mutate_corpus_with_llm(self):
        """With a mock llm_call, new seeds are written."""
        from fuzzing_agent.mutators.coverage_guided_mutator import mutate_corpus
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            (corpus / "seed1").write_bytes(b"hello")
            cov_file = Path(td) / "cov.json"
            cov_file.write_text(json.dumps({
                "functions": [{"name": "f", "coverage": 5}],
                "total_edges": 10,
            }))

            def mock_llm(prompt):
                return {"mutations": ["deadbeef", "cafebabe"]}

            result = mutate_corpus(str(corpus), str(cov_file), "def f(): pass", llm_call=mock_llm)
            assert result == 2
            written = list(corpus.glob("mutated_*"))
            assert len(written) == 2
