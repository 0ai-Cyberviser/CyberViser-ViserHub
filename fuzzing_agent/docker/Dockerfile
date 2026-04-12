FROM gcr.io/oss-fuzz-base/base-builder-python

LABEL maintainer="CyberViser <contact@cyberviser.ai>"
LABEL description="Hancock Fuzz Environment — pre-installed AFL++, Atheris, libFuzzer tooling"

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm lcov \
    && pip3 install --no-cache-dir atheris coverage[toml] \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the entire project into /src
COPY . /src

# Copy build script to the standard ClusterFuzzLite location
COPY fuzzing_agent/docker/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh

WORKDIR /src
CMD ["compile"]
