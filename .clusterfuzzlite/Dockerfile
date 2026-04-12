FROM gcr.io/oss-fuzz-base/base-builder-python

LABEL maintainer="CyberViser <cyberviser@proton.me>"

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm lcov \
    && pip3 install --no-cache-dir coverage[toml] \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy project source and the ClusterFuzzLite build script
COPY . $SRC/hancock
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/hancock
