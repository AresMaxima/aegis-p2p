#!/usr/bin/env bash
set -euo pipefail
TC="${1:-1.100.0}"; ROOT="$(pwd)"; RUP="$(command -v rustup)"
rm -rf /tmp/aegis-repro /tmp/aegis-rustup /tmp/aegis-chome /tmp/aegis-tmp /tmp/aegis-tools
mkdir -p /tmp/aegis-repro /tmp/aegis-rustup /tmp/aegis-chome /tmp/aegis-tmp /tmp/aegis-tools/bin
git archive HEAD | tar -x -C /tmp/aegis-repro
RUSTUP_HOME=/tmp/aegis-rustup CARGO_HOME=/tmp/aegis-chome "$RUP" toolchain install "$TC" --target aarch64-linux-android --profile minimal
SYS="/tmp/aegis-rustup/toolchains/${TC}-x86_64-unknown-linux-gnu"
curl -L -sSf https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz | tar -xz -C /tmp/aegis-tools/bin
CARGO_HOME=/tmp/aegis-tools /tmp/aegis-tools/bin/cargo-binstall -y cargo-auditable@0.7.7
cd /tmp/aegis-repro/aegis-core && CARGO_HOME=/tmp/aegis-chome "$SYS/bin/cargo" fetch --locked
NDK="/opt/ndk/android-ndk-r27"; NBIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CF="-ffile-prefix-map=/tmp/aegis-repro=/src -ffile-prefix-map=/tmp/aegis-chome=/chome -ffile-prefix-map=$NDK=/ndk -g0 -O2"
RF="--remap-path-prefix=/tmp/aegis-repro=/src --remap-path-prefix=/tmp/aegis-chome=/chome --remap-path-prefix=$SYS=/rustc -C strip=none -C link-arg=-Wl,--build-id=none -C link-arg=-Wl,--hash-style=gnu -C link-arg=-Wl,--threads=1"
env -i HOME=/tmp/aegis-tmp TMPDIR=/tmp/aegis-tmp RUSTUP_HOME=/tmp/aegis-rustup CARGO_HOME=/tmp/aegis-chome PATH="/tmp/aegis-tools/bin:$SYS/bin:/usr/bin:/bin" SOURCE_DATE_EPOCH=1735689600 ZERO_AR_DATE=1 CARGO_INCREMENTAL=0 LC_ALL=C TZ=UTC NUM_JOBS=1 ANDROID_NDK_HOME="$NDK" CC_aarch64_linux_android="$NBIN/aarch64-linux-android29-clang" CXX_aarch64_linux_android="$NBIN/aarch64-linux-android29-clang++" AR_aarch64_linux_android="$NBIN/llvm-ar" RANLIB_aarch64_linux_android="$NBIN/llvm-ranlib" CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NBIN/aarch64-linux-android29-clang" CFLAGS_aarch64_linux_android="$CF" CXXFLAGS_aarch64_linux_android="$CF" RUSTFLAGS="$RF" "$SYS/bin/cargo" auditable build --locked -j 1 --target aarch64-linux-android --release
"$NBIN/llvm-strip" --strip-all --keep-section=.dep-v0 target/aarch64-linux-android/release/libaegis_core.so
"$NBIN/llvm-readelf" -S target/aarch64-linux-android/release/libaegis_core.so | grep ".dep-v0"
cp target/aarch64-linux-android/release/libaegis_core.so "$ROOT/aegis-core/libaegis_core.so"
sha256sum "$ROOT/aegis-core/libaegis_core.so" | cut -d" " -f1 > "$ROOT/aegis-core/libaegis_core.so.sha256"
