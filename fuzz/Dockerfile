FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/AresMaxima/aegis-p2p aegis-p2p
WORKDIR aegis-p2p/aegis-core
COPY build.sh $SRC/
