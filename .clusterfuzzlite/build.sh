#!/bin/bash -eu
# ClusterFuzzLite build script for CyberViser Hancock (Python / Atheris)
# Runs inside the Docker container built from .clusterfuzzlite/Dockerfile.
# $SRC  — project sources (see Dockerfile COPY directives)
# $OUT  — output directory where ClusterFuzzLite looks for fuzz targets

# Install project dependencies
pip3 install --progress-bar off -r "$SRC/hancock/requirements.txt"
pip3 install --progress-bar off atheris pyyaml

# Copy only actual fuzz target scripts (exclude .gitkeep and non-.py files)
shopt -s nullglob
fuzz_scripts=("$SRC/hancock/fuzz_targets"/fuzz_*.py)

if [[ ${#fuzz_scripts[@]} -eq 0 ]]; then
    echo "ERROR: No fuzz_*.py targets found in $SRC/hancock/fuzz_targets/" >&2
    exit 1
fi

cp "${fuzz_scripts[@]}" "$OUT/"

# Create an executable shell wrapper for every fuzz_*.py target.
# ClusterFuzzLite (OSS-Fuzz convention) requires executable binaries in $OUT;
# for Python/Atheris targets the wrapper is the binary that it invokes.
for fuzzer in "$OUT"/fuzz_*.py; do
    base=$(basename "$fuzzer" .py)
    printf '#!/bin/bash\npython3 %s "$@"\n' "$fuzzer" > "$OUT/$base"
    chmod +x "$OUT/$base"
done

echo "Fuzz targets written to ${OUT}:"
ls -la "${OUT}"
