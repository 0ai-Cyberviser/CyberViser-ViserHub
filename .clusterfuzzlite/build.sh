#!/bin/bash -eu
# ClusterFuzzLite build script for CyberViser Hancock (Python / Atheris)
# Runs inside the Docker container built from .clusterfuzzlite/Dockerfile.
# $SRC  — project sources (see Dockerfile COPY directives)
# $OUT  — output directory where ClusterFuzzLite looks for fuzz targets

# Install project dependencies
pip3 install --progress-bar off -r "$SRC/hancock/requirements.txt"
pip3 install --progress-bar off atheris pyyaml

# Copy source packages that fuzz targets import into $OUT so they are
# importable at fuzz time via PYTHONPATH=$this_dir (set by the wrapper
# that compile_python_fuzzer creates).  The pyproject.toml only discovers
# packages under clients/python, so pip install -e won't expose these.
cp -r "$SRC/hancock/fuzzing_agent" "$OUT/"
cp    "$SRC/hancock/hancock_constants.py" "$OUT/"

# Compile each fuzz target using the OSS-Fuzz helper.
# compile_python_fuzzer (provided by gcr.io/oss-fuzz-base/base-builder-python)
# copies the .py file to $OUT and creates an executable wrapper that sets
# LD_PRELOAD for the Atheris/libFuzzer sanitizer runtime and uses relative
# paths so targets work in both the build and run containers.
shopt -s nullglob
fuzz_scripts=("$SRC/hancock/fuzz_targets"/fuzz_*.py)

if [[ ${#fuzz_scripts[@]} -eq 0 ]]; then
    echo "ERROR: No fuzz_*.py targets found in $SRC/hancock/fuzz_targets/" >&2
    exit 1
fi

for fuzzer in "${fuzz_scripts[@]}"; do
    compile_python_fuzzer "$fuzzer"
done

echo "Fuzz targets written to ${OUT}:"
ls -la "${OUT}"
