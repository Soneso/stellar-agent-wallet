# Image of the stellar-agent-wallet dev container. It holds the toolchain of
# rust-toolchain.toml and the gate tools at the versions the repository pins:
# - cargo-llvm-cov: .github/workflows/coverage.yml
# - cargo-machete and cargo-deny: .github/workflows/ci.yml
# - shellcheck and actionlint: .github/workflows/install-surface.yml
# - Node.js and pnpm: interop/stellar-mpp-js/package.json
# - PyYAML: .github/scripts/workflow-check-requirements.txt
# A pin change in one of those files needs the same change here.
#
# Each download is checked against the digest its project publishes, for
# linux/amd64 and linux/arm64.

# mcr.microsoft.com/devcontainers/rust:2.1.1-trixie (Debian 13), pinned by the
# digest of its multi-platform index. The base image provides Git and the
# vscode user.
FROM mcr.microsoft.com/devcontainers/rust@sha256:1648c1ac19ef6b55a001048d832956c109a5a9ad37fc6b3c82d37b6cd462bbf3

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Build and gate prerequisites from the Debian repositories:
# - build-essential and Perl build the vendored OpenSSL and D-Bus.
# - libudev-dev and pkg-config serve hidapi.
# - Bash, Python 3, jq, zip, unzip, and the shasum of Perl serve the gate
#   scripts.
# - curl, ca-certificates, and xz-utils fetch and unpack the release archives.
# - python3-pip installs the hash-pinned PyYAML.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        jq \
        libudev-dev \
        perl \
        pkg-config \
        python3 \
        python3-pip \
        unzip \
        xz-utils \
        zip \
    && rm -rf /var/lib/apt/lists/*

# RUST_VERSION names the toolchain this image installs: the stable channel of
# rust-toolchain.toml.
ENV RUST_VERSION=stable

# The only toolchain is stable, with the components of rust-toolchain.toml and
# llvm-tools-preview for cargo-llvm-cov. The cargo gate tools build with
# --locked at the reference pins. The vscode user owns RUSTUP_HOME and
# CARGO_HOME, so `rustup update stable` and `cargo install` run without root.
RUN rustup toolchain install stable --profile minimal --component rustfmt,clippy,llvm-tools-preview \
    && rustup default stable \
    && rustup toolchain list | awk '$1 !~ /^stable-/ { print $1 }' | xargs -r -n 1 rustup toolchain uninstall \
    && cargo install --locked cargo-llvm-cov --version 0.8.7 \
    && cargo install --locked cargo-machete --version 0.9.2 \
    && cargo install --locked cargo-deny --version 0.19.9 \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git" \
    && chown -R vscode:rustlang "$RUSTUP_HOME" "$CARGO_HOME" \
    && chmod -R g+w "$RUSTUP_HOME" "$CARGO_HOME"

# shellcheck from its release archive. The digests are the GitHub release asset
# digests of v0.11.0.
RUN version=0.11.0 \
    && case "$(dpkg --print-architecture)" in \
        amd64) arch=x86_64 sha256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 ;; \
        arm64) arch=aarch64 sha256=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588 ;; \
        *) echo "no shellcheck digest for architecture $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
    && tmp=$(mktemp -d) \
    && curl -sSfL --retry 3 --proto '=https' -o "$tmp/shellcheck.tar.xz" \
        "https://github.com/koalaman/shellcheck/releases/download/v${version}/shellcheck-v${version}.linux.${arch}.tar.xz" \
    && echo "${sha256}  $tmp/shellcheck.tar.xz" | sha256sum -c - \
    && tar -xJf "$tmp/shellcheck.tar.xz" -C "$tmp" "shellcheck-v${version}/shellcheck" \
    && install -m 0755 "$tmp/shellcheck-v${version}/shellcheck" /usr/local/bin/shellcheck \
    && rm -rf "$tmp"

# actionlint from its release archive. The digests are the entries of
# actionlint_1.7.12_checksums.txt.
RUN version=1.7.12 \
    && case "$(dpkg --print-architecture)" in \
        amd64) arch=amd64 sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 ;; \
        arm64) arch=arm64 sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6 ;; \
        *) echo "no actionlint digest for architecture $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
    && tmp=$(mktemp -d) \
    && curl -sSfL --retry 3 --proto '=https' -o "$tmp/actionlint.tar.gz" \
        "https://github.com/rhysd/actionlint/releases/download/v${version}/actionlint_${version}_linux_${arch}.tar.gz" \
    && echo "${sha256}  $tmp/actionlint.tar.gz" | sha256sum -c - \
    && tar -xzf "$tmp/actionlint.tar.gz" -C "$tmp" actionlint \
    && install -m 0755 "$tmp/actionlint" /usr/local/bin/actionlint \
    && rm -rf "$tmp"

# COREPACK_HOME lies outside any home directory, so root and the vscode user
# resolve the same cached pnpm without a download. COREPACK_DEFAULT_TO_LATEST=0
# keeps the installed pnpm as the default outside a project that names one.
ENV COREPACK_HOME=/usr/local/share/corepack \
    COREPACK_DEFAULT_TO_LATEST=0

# Node.js from the official binary archive, with the Corepack it bundles
# enabled and pnpm installed through it. The Node.js digests are the entries of
# SHASUMS256.txt of v24.5.0. The pnpm digest is the SHA-512 integrity that the
# npm registry publishes for pnpm 10.33.0, in hex. Corepack checks the
# downloaded archive against it.
RUN version=24.5.0 \
    && case "$(dpkg --print-architecture)" in \
        amd64) arch=x64 sha256=32edb1f2aeaf8ea0d484af33bf3b5d8330d7d33c9cd8c70f811b8a643822e613 ;; \
        arm64) arch=arm64 sha256=313367534186a8551d68b39fbc2a6cc36638e583fb5dc75dcf5da3c6582bff3b ;; \
        *) echo "no Node.js digest for architecture $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
    && tmp=$(mktemp -d) \
    && curl -sSfL --retry 3 --proto '=https' -o "$tmp/node.tar.xz" \
        "https://nodejs.org/dist/v${version}/node-v${version}-linux-${arch}.tar.xz" \
    && echo "${sha256}  $tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf "$tmp/node.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
        --exclude="node-v${version}-linux-${arch}/CHANGELOG.md" \
        --exclude="node-v${version}-linux-${arch}/LICENSE" \
        --exclude="node-v${version}-linux-${arch}/README.md" \
    && rm -rf "$tmp" \
    && corepack enable \
    && corepack install --global pnpm@10.33.0+sha512.10568bb4a6afb58c9eb3630da90cc9516417abebd3fabbe6739f0ae795728da1491e9db5a544c76ad8eb7570f5c4bb3d6c637b2cb41bfdcdb47fa823c8649319 \
    && chown -R vscode:vscode "$COREPACK_HOME"

# PyYAML for the workflow checks, installed into the system Python. The two
# hashes are the CPython 3.13 manylinux wheels for x86_64 and aarch64 that
# workflow-check-requirements.txt also lists.
RUN requirements=$(mktemp) \
    && echo 'PyYAML==6.0.3 --hash=sha256:0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6 --hash=sha256:ee2922902c45ae8ccada2c5b501ab86c36525b883eff4255313a253a3160861c' >"$requirements" \
    && python3 -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
        --break-system-packages --require-hashes --only-binary :all: --no-deps -r "$requirements" \
    && rm "$requirements"
