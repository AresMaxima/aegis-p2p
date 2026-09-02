#!/bin/bash -eu
cargo fuzz build fuzz_ingest_frame
cp target/x86_64-unknown-linux-gnu/release/fuzz_ingest_frame $OUT/
