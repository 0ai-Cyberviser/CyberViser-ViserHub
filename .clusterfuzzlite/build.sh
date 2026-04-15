#!/bin/bash -eu
# ClusterFuzzLite build script for CyberViser Hancock (Python / Atheris)
# Runs inside the Docker container built from .clusterfuzzlite/Dockerfile.
# $SRC  — project sources (see Dockerfile COPY directives)
# $OUT  — output directory where ClusterFuzzLite looks for fuzz targets

# Install project dependencies
pip3 install --progress-bar off -r "$SRC/hancock/requirements.txt"
pip3 install --progress-bar off atheris pyyaml

# Make the local fuzzing_agent package (and any other top-level packages)
# importable by fuzz harnesses.  The pyproject.toml only discovers packages
# under clients/python, so pip install -e won't expose fuzzing_agent; adding
# $SRC/hancock to PYTHONPATH is the correct fix.
export PYTHONPATH="$SRC/hancock:${PYTHONPATH:-}"

# Copy only actual fuzz target scripts (exclude .gitkeep and non-.py files)
shopt -s nullglob
fuzz_scripts=("$SRC/hancock/fuzz_targets"/fuzz_*.py)

if [[ ${#fuzz_scripts[@]} -eq 0 ]]; then
    echo "ERROR: No fuzz_*.py targets found in $SRC/hancock/fuzz_targets/" >&2
    exit 1
fi

cp "${fuzz_scripts[@]}" "$OUT/"

# Create an executable shell wrapper for every fuzz_*.py target.
# ClusterFuzzLite only treats shell wrappers as fuzz targets when their
# executable name ends with "_fuzzer"; otherwise it looks for an
# LLVMFuzzerTestOneInput symbol and ignores the file.
for fuzzer in "$OUT"/fuzz_*.py; do
    base=$(basename "$fuzzer" .py)
    wrapper="$OUT/${base}_fuzzer"
    printf '#!/bin/bash\nexport PYTHONPATH="%s:${PYTHONPATH:-}"\npython3 "%s" "$@"\n' "$SRC/hancock" "$fuzzer" > "$wrapper"
    chmod +x "$wrapper"
done

echo "Fuzz targets written to ${OUT}:"
ls -la "${OUT}"
