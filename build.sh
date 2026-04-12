#!/bin/bash
# ClusterFuzzLite build script for CyberViser Hancock (Python / Atheris)
# $OUT is set by ClusterFuzzLite to its output directory

set -e

# Install project and fuzzing dependencies
pip install --progress-bar off -r requirements.txt
pip install --progress-bar off atheris pyyaml

# Generate Atheris harnesses into $OUT
python - <<'EOF'
import os, sys
sys.path.insert(0, os.getcwd())
from fuzzing_agent.specialists.clusterfuzz_integration import generate_clusterfuzzlite_harnesses
generate_clusterfuzzlite_harnesses(
    ['hancock_agent'],
    output_dir=os.environ.get('OUT', 'build-out'),
)
EOF

echo "Fuzz targets written to ${OUT}:"
ls "${OUT}"

# Fail early if no fuzz targets were generated
if ! ls "${OUT}"/fuzz_*.py 1>/dev/null 2>&1; then
    echo "ERROR: No fuzz targets (fuzz_*.py) found in ${OUT}" >&2
    exit 1
fi
