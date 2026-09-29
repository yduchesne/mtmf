#!/usr/bin/env bash
#
# install.sh — idempotent MTMF development-dependency installer.
#
# Ensures the tools needed to develop/build the MTMF workspace:
#   1. `uv`            (package/workspace/dependency manager)
#   2. Python >= 3.14  (project baseline)
#   3. Rust toolchain  (rustup: stable >= crate MSRV, with clippy + rustfmt)
#   4. project environment (`uv sync --locked`)
#   5. private native module (`uv run maturin develop`, PR 8A)
#   6. pre-commit hooks (Gitleaks, quality gate, security scan)
#
# Installation strategy:
#   - `uv` is installed via the official astral installer when curl or
#     wget is available, and via the OS package manager otherwise.
#   - Python 3.14 is always installed as a uv-managed interpreter from
#     the same download source CI uses; the OS package manager is never
#     used to install Python.
#   - Rust is installed via the official rustup installer (stable
#     toolchain at or above the MSRV declared by the
#     `mtmf-permission-engine` crate, plus the `clippy` and `rustfmt`
#     components that `./build.sh --rust` requires).
#
# The script is idempotent: a dependency that is already satisfied is
# skipped, and `uv sync --locked` converges a synchronized workspace
# without changes. Safe to run repeatedly.
#
# Environment knobs:
#   MTMF_OS_RELEASE         path to an os-release file (containers/tests)
#   UV_INSTALL_DIR          directory for the uv binary (default ~/.local/bin)
#   UV_PYTHON_INSTALL_DIR   directory for uv-managed Pythons
#   MTMF_NO_SYNC=1          skip the `uv sync --locked` step
#   MTMF_NO_RUST=1          skip Rust toolchain setup and the native
#                           module build (the Python --qa/--sec gates do
#                           not require Rust)

set -euo pipefail

info() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;33m[skip]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Platform / package-manager detection
# ---------------------------------------------------------------------------

detect_pkg_manager() {
    PKG_MGR=""
    DISTRO="unknown"
    local os
    os="$(uname -s)"
    case "$os" in
        Linux)
            local release_file="${MTMF_OS_RELEASE:-/etc/os-release}"
            if [[ -r "$release_file" ]]; then
                # shellcheck disable=SC1090
                source "$release_file"
                DISTRO="${ID:-unknown}"
                local id="${ID:-}" id_like="${ID_LIKE:-} ${ID:-}"
                case " $id_like " in
                    *" debian "*|*" ubuntu "*|*" linuxmint "*|*" pop "*)
                        PKG_MGR=apt ;;
                    *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" amzn "*)
                        PKG_MGR=dnf ;;
                    *" arch "*|*" archarm "*|*" cachyos "*|*" endeavour "*)
                        PKG_MGR=pacman ;;
                    *" alpine "*) PKG_MGR=apk ;;
                    *" opensuse "*|*" suse "*|*" sles "*)
                        PKG_MGR=zypper ;;
                esac
            fi
            ;;
        Darwin)
            PKG_MGR=brew
            DISTRO="macos"
            ;;
        *)
            info "Unrecognized platform '$os'; using uv-managed installs only"
            ;;
    esac
    export PKG_MGR DISTRO
}

# True when package-manager invocations need elevation (not root, not brew).
needs_sudo() {
    [[ "$(id -u)" -ne 0 ]] && [[ "${PKG_MGR:-}" != "brew" ]]
}

# ---------------------------------------------------------------------------
# OS package-manager helpers (return 1 when unavailable)
# ---------------------------------------------------------------------------

os_has_pkg() {
    local pkg="$1"
    case "${PKG_MGR:-}" in
        apt)
            local candidate
            candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk -F': +' '/Candidate:/{print $2}')"
            [[ -n "$candidate" && "$candidate" != "(none)" ]]
            ;;
        dnf)
            dnf -q list --available "$pkg" >/dev/null 2>&1
            ;;
        pacman)
            pacman -Si "$pkg" >/dev/null 2>&1
            ;;
        apk)
            apk search -e "$pkg" >/dev/null 2>&1
            ;;
        zypper)
            zypper --no-refresh search -x -t package "$pkg" >/dev/null 2>&1
            ;;
        brew)
            brew info "$pkg" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

os_install_pkg() {
    local pkg="$1"
    case "${PKG_MGR:-}" in
        apt)    $SUDO_PREFIX apt-get install -y --no-install-recommends "$pkg" ;;
        dnf)    $SUDO_PREFIX dnf install -y "$pkg" ;;
        pacman) $SUDO_PREFIX pacman -S --noconfirm "$pkg" ;;
        apk)    $SUDO_PREFIX apk add --no-cache "$pkg" ;;
        zypper) $SUDO_PREFIX zypper --non-interactive --no-gpg-checks install "$pkg" ;;
        brew)   brew install "$pkg" ;;
        *)      return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

# version_ge <version> <major> <minor> — true when version >= major.minor
version_ge() {
    local ver="$1" major minor
    major="${ver%%.*}"
    minor="${ver#*.}"
    minor="${minor%%.*}"
    [[ -n "$major" && -n "$minor" ]] || return 1
    if [[ "$major" -gt "$2" ]]; then
        return 0
    elif [[ "$major" -eq "$2" ]]; then
        [[ "$minor" -ge "$3" ]]
    else
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Dependency checks / installers
# ---------------------------------------------------------------------------

python_available() {
    if command -v python3.14 >/dev/null 2>&1; then
        return 0
    fi
    if command -v uv >/dev/null 2>&1 && uv python find ">=3.14" >/dev/null 2>&1; then
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        local version
        version="$(python3 --version 2>&1 | awk '{print $2}')"
        if version_ge "$version" 3 14; then
            return 0
        fi
    fi
    return 1
}

python_display() {
    if command -v python3.14 >/dev/null 2>&1; then
        printf 'python3.14 (%s)' "$(python3.14 --version 2>&1)"
    elif command -v uv >/dev/null 2>&1 && uv python find ">=3.14" >/dev/null 2>&1; then
        printf 'uv-managed (%s)' "$(uv python find ">=3.14")"
    elif command -v python3 >/dev/null 2>&1; then
        printf 'python3 (%s)' "$(python3 --version 2>&1)"
    else
        printf 'unknown'
    fi
}

install_uv_script() {
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
    else
        wget -qO- https://astral.sh/uv/install.sh | sh
    fi
    local dir="${UV_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
    if [[ -x "$dir/uv" ]] && [[ ":$PATH:" != *":$dir:"* ]]; then
        PATH="$dir:$PATH"
        export PATH
    fi
}

install_uv_os() {
    os_has_pkg uv && os_install_pkg uv
}

verify_uv() {
    if ! command -v uv >/dev/null 2>&1; then
        local dir="${UV_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
        if [[ -x "$dir/uv" ]] && [[ ":$PATH:" != *":$dir:"* ]]; then
            PATH="$dir:$PATH"
            export PATH
        fi
    fi
    command -v uv >/dev/null 2>&1 || return 1
    return 0
}

ensure_uv() {
    info "Checking uv ..."
    if command -v uv >/dev/null 2>&1; then
        skip "uv already installed ($(uv --version))"
        return 0
    fi
    ok "uv not found; installing"
    if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
        ok "Using the official astral uv installer"
        install_uv_script
    fi
    if ! verify_uv; then
        if [[ -n "${PKG_MGR:-}" ]]; then
            ok "Official installer failed; trying '$PKG_MGR' package 'uv'"
            if install_uv_os; then
                verify_uv || fail "uv was installed but is not reachable on PATH"
            else
                fail "Could not install uv; install it manually (https://docs.astral.sh/uv/)"
            fi
        else
            fail "Could not install uv; install it manually (https://docs.astral.sh/uv/)"
        fi
    fi
    ok "uv ready ($(uv --version))"
}

ensure_python() {
    info "Checking Python >= 3.14 ..."
    if python_available; then
        skip "Python >= 3.14 already available: $(python_display)"
        return 0
    fi
    ok "Python 3.14 not found; installing"
    command -v uv >/dev/null 2>&1 \
        || fail "uv is required to install Python; install it first (https://docs.astral.sh/uv/)"
    # Preferred path: a uv-managed interpreter keeps the toolchain
    # consistent with the workspace and CI. uv skips the download when a
    # 3.14 interpreter is already present, so the step stays idempotent.
    ok "Installing uv-managed Python 3.14"
    uv python install 3.14
    python_available || fail "Python 3.14 installation did not produce a usable interpreter"
    ok "Python >= 3.14 available: $(python_display)"
}

# ---------------------------------------------------------------------------
# Rust toolchain helpers
# ---------------------------------------------------------------------------

# Default floor when the crate manifest cannot be read (kept in sync with
# packages/mtmf-permission-engine/Cargo.toml rust-version).
RUST_MIN_VERSION_DEFAULT="1.98"

# The crate manifest is the single source of truth for the MSRV that
# ./build.sh --rust requires.
rust_min_version() {
    local version=""
    if [[ -r "packages/mtmf-permission-engine/Cargo.toml" ]]; then
        version="$(sed -n 's/^rust-version = "\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' packages/mtmf-permission-engine/Cargo.toml | head -1)"
    fi
    printf '%s' "${version:-${RUST_MIN_VERSION_DEFAULT}}"
}

rust_has_components() {
    command -v cargo-clippy >/dev/null 2>&1 && command -v cargo-fmt >/dev/null 2>&1
}

rust_at_least() {
    # rust_at_least <version> <min-major> <min-minor>
    version_ge "$1" "$2" "$3"
}

rust_ready() {
    command -v rustc >/dev/null 2>&1 || return 1
    command -v cargo >/dev/null 2>&1 || return 1
    local version
    version="$(rustc --version 2>/dev/null | awk '{print $2}')"
    [[ -n "$version" ]] || return 1
    local min major minor
    min="$(rust_min_version)"
    major="${min%%.*}"
    minor="${min#*.}"
    minor="${minor%%.*}"
    rust_at_least "$version" "$major" "$minor"
}

rust_display() {
    if command -v rustc >/dev/null 2>&1; then
        local components
        if rust_has_components; then
            components="clippy+rustfmt ready"
        else
            components="missing clippy/rustfmt"
        fi
        printf 'rustc %s (%s)' "$(rustc --version | awk '{print $2}')" "$components"
    else
        printf 'unknown'
    fi
}

install_rust_script() {
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    else
        wget -qO- https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    fi
    local bin_dir="${CARGO_HOME:-$HOME/.cargo}/bin"
    if [[ -x "$bin_dir/cargo" ]] && [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        PATH="$bin_dir:$PATH"
        export PATH
    fi
}

ensure_rust() {
    if [[ "${MTMF_NO_RUST:-0}" == "1" ]]; then
        skip "Rust toolchain setup skipped (MTMF_NO_RUST=1)"
        return 0
    fi
    local min
    min="$(rust_min_version)"
    info "Checking Rust toolchain (>= $min, with clippy and rustfmt components) ..."
    if rust_ready && rust_has_components; then
        skip "Rust toolchain already available: $(rust_display)"
        return 0
    fi
    if rust_ready; then
        ok "Rust >= $min found; adding missing clippy/rustfmt components"
        if command -v rustup >/dev/null 2>&1; then
            rustup component add clippy rustfmt || true
        elif [[ -n "${PKG_MGR:-}" ]]; then
            os_has_pkg clippy && os_install_pkg clippy || true
            os_has_pkg rustfmt && os_install_pkg rustfmt || true
        fi
    else
        if command -v rustup >/dev/null 2>&1; then
            ok "Rust toolchain found; refreshing stable toolchain and clippy/rustfmt components"
            rustup update stable || true
            rustup component add clippy rustfmt || true
        else
            ok "Rust not found (or below $min); installing via rustup"
            install_rust_script \
                || fail "Could not install Rust via rustup; install it manually (https://rustup.rs) or set MTMF_NO_RUST=1"
            rustup component add clippy rustfmt || true
        fi
    fi
    if rust_ready && rust_has_components; then
        ok "Rust toolchain ready: $(rust_display)"
    else
        fail "Rust toolchain is not fully ready (need rustc >= $min plus clippy and rustfmt); fix it, re-run with MTMF_NO_RUST=1 to skip, or install rustup (https://rustup.rs)"
    fi
}

ensure_native_module() {
    if [[ "${MTMF_NO_RUST:-0}" == "1" ]] || ! command -v cargo >/dev/null 2>&1; then
        skip "private native module build (_mtmf_permission_engine)"
        return 0
    fi
    info "Building and installing the private native module (maturin develop) ..."
    if uv run maturin develop --manifest-path packages/mtmf-permission-engine/Cargo.toml; then
        ok "private native module installed (_mtmf_permission_engine)"
    else
        warn "Native module build failed; the Python workspace (--qa/--sec) is unaffected."
        warn "Run ./build.sh --rust later to rebuild it (canonical native gate)."
    fi
}

ensure_project_env() {
    if [[ "${MTMF_NO_SYNC:-0}" == "1" ]]; then
        skip "workspace sync skipped (MTMF_NO_SYNC=1)"
        return 0
    fi
    info "Synchronizing the workspace environment (uv sync --locked) ..."
    uv sync --locked
    ok "workspace environment synchronized"
}

ensure_pre_commit_hooks() {
    if [[ ! -d ".git" ]]; then
        skip "pre-commit hooks (no .git directory present)"
        return 0
    fi
    info "Installing pre-commit hooks (Gitleaks, --qa, --sec) ..."
    uv run pre-commit install
    ok "pre-commit hooks installed"
}

# ---------------------------------------------------------------------------

main() {
    detect_pkg_manager
    if [[ -n "${PKG_MGR:-}" ]]; then
        SUDO_PREFIX=""
        if needs_sudo; then
            command -v sudo >/dev/null 2>&1 || fail "Root privileges are required but 'sudo' is not installed"
            SUDO_PREFIX="sudo"
        fi
    fi
    info "Platform: $DISTRO (package manager: ${PKG_MGR:-none})"
    ensure_uv
    ensure_python
    ensure_rust
    ensure_project_env
    ensure_native_module
    ensure_pre_commit_hooks
    ok "All MTMF development dependencies are installed."
}

main "$@"