FROM gcr.io/oss-fuzz-base/base-builder-python

LABEL maintainer="CyberViser <contact@cyberviser.ai>"
LABEL description="Hancock Fuzz Environment — pre-installed AFL++, Atheris, libFuzzer tooling"

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm lcov \
    && pip3 install --no-cache-dir atheris coverage[toml] \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /src
CMD ["compile"]
