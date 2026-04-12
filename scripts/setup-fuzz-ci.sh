#!/bin/bash
# CyberViser Hancock — Continuous Fuzzing CI/CD Setup
# Run this script from the repository root to prepare the fuzzing environment.
set -euo pipefail

echo "🔧 Setting up Continuous Fuzzing CI/CD for Hancock..."

# Create required directories
mkdir -p .clusterfuzzlite fuzz_targets fuzzing_agent/specialists fuzzing_agent/mutators

# Verify ClusterFuzzLite config exists
if [ ! -f .clusterfuzzlite/config.yml ]; then
    echo "⚠️  .clusterfuzzlite/config.yml not found — creating default..."
    cat > .clusterfuzzlite/config.yml << 'EOF'
language: python
fuzzing_engine: atheris
sanitizers:
  - address
  - undefined
  - coverage
auto_build: true
coverage: true
EOF
fi

# Verify workflows exist
for wf in clusterfuzzlite-pr.yml clusterfuzzlite-batch.yml fuzz-triage.yml coverage-report.yml; do
    if [ -f ".github/workflows/$wf" ]; then
        echo "✅ .github/workflows/$wf exists"
    else
        echo "⚠️  .github/workflows/$wf is missing — add it from the fuzzing_agent templates"
    fi
done

echo ""
echo "✅ Continuous fuzzing CI/CD ready. Commit & push!"
echo "   Fuzz targets go in: fuzz_targets/"
echo "   Config lives at:    .clusterfuzzlite/config.yml"
