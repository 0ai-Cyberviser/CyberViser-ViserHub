# ClusterFuzzLite Dockerfile for CyberViser Hancock (Python / Atheris)
# This Dockerfile is used by ClusterFuzzLite to build fuzz targets in an isolated environment.

FROM gcr.io/oss-fuzz-base/base-builder-python

# Copy the entire project source code into $SRC
COPY . $SRC/

# Copy the build script to $SRC
COPY build.sh $SRC/build.sh

# Set working directory
WORKDIR $SRC
