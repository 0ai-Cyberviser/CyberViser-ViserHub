#!/bin/bash -eu
# ClusterFuzzLite build script — installs deps, copies Atheris fuzz targets
# to $OUT, and creates executable shell wrappers (OSS-Fuzz convention).

set -o pipefail

# Install project runtime dependencies and Atheris
pip install --progress-bar off -r requirements.txt
pip install --progress-bar off atheris pyyaml

# Copy every fuzz_*.py target into $OUT
for target in fuzz_targets/fuzz_*.py; do
    [ -f "$target" ] || continue
    cp "$target" "$OUT/"
done

# Create executable shell wrappers so ClusterFuzzLite can discover them.
# OSS-Fuzz expects an executable named "fuzz_<name>" (no .py extension)
# that invokes the Python harness.
for py in "$OUT"/fuzz_*.py; do
    [ -f "$py" ] || continue
    base="$(basename "$py" .py)"
    wrapper="$OUT/$base"
    cat > "$wrapper" <<WRAPPER
#!/bin/bash
# Auto-generated wrapper for $base.py
this_dir="\$(cd "\$(dirname "\$0")" && pwd)"
exec python3 "\$this_dir/$base.py" "\$@"
WRAPPER
    chmod +x "$wrapper"
done

echo "Fuzz targets written to ${OUT}:"
ls -la "${OUT}"/fuzz_* 2>/dev/null || echo "(none)"
