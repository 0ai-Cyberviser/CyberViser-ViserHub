#!/bin/bash -eu
# build.sh — invoked by ClusterFuzzLite inside the build container (via CMD ["compile"])
# Installs dependencies and compiles all Python fuzz harnesses in fuzz_targets/
# $SRC is set by ClusterFuzzLite to the repo root

pip3 install --no-cache-dir -r "$SRC/requirements-fuzz.txt"

for fuzzer in "$SRC"/fuzz_targets/fuzz_*.py; do
    compile_python_fuzzer "$fuzzer"
done
