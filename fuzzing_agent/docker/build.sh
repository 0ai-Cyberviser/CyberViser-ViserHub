#!/bin/bash -eu
# build.sh — invoked by ClusterFuzzLite inside the build container (via CMD ["compile"])
# Installs dependencies and compiles all Python fuzz harnesses in fuzz_targets/

pip3 install --no-cache-dir -r /src/requirements-fuzz.txt

for fuzzer in /src/fuzz_targets/fuzz_*.py; do
    compile_python_fuzzer "$fuzzer"
done
