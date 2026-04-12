FROM gcr.io/oss-fuzz-base/base-builder-python

LABEL maintainer="CyberViser <contact@cyberviser.ai>"
LABEL description="Hancock Fuzz Environment — pre-installed AFL++, Atheris, libFuzzer tooling"

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm lcov \
    && pip3 install --no-cache-dir atheris coverage[toml] \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# build.sh lives alongside this Dockerfile in fuzzing_agent/docker/
# ClusterFuzzLite sets the build context to this directory, so reference it directly
COPY build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh

# ClusterFuzzLite automatically clones the repo to $SRC — no manual COPY needed
WORKDIR $SRC
CMD ["compile"]
